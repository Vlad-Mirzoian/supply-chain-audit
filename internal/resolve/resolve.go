// Package resolve implements the resolution mode of the graph builder: a
// breadth-first traversal of registry metadata in which version selection is
// delegated to the rules of each ecosystem.
package resolve

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Rule is the version-selection semantics of an ecosystem.
type Rule int

const (
	// NPMDedupe reuses a version already chosen for the name if it satisfies
	// the range, otherwise adds the highest matching version as a new node.
	NPMDedupe Rule = iota
	// PyPISingle keeps one version per name that satisfies all constraints.
	PyPISingle
	// MavenNearest fixes the version found closest to the root.
	MavenNearest
)

// Dep is one declared dependency.
type Dep struct {
	Name       string
	Range      string
	Scope      model.Scope
	Optional   bool
	Marker     string   // PEP 508 environment marker
	Extras     []string // PyPI extras requested for this dependency
	Exclusions []string // Maven "group:artifact" patterns
}

// Source supplies registry metadata to the resolver.
type Source interface {
	Rule() Rule
	// Versions returns all published versions in ascending order.
	Versions(ctx context.Context, name string) ([]string, error)
	// Deps returns the dependencies of a concrete version.
	Deps(ctx context.Context, name, version string, extras []string) ([]Dep, error)
	Satisfies(version, rng string) bool
	// Pinned returns the version if rng names exactly one version.
	Pinned(rng string) (string, bool)
	MarkerApplies(d Dep) bool
	Component(name, version string) *model.Component
	// Transitive merges scopes along a path; ok=false drops the dependency.
	Transitive(parent model.Scope, d Dep, depth int) (model.Scope, bool)
	// Managed returns a root-level override (Maven dependencyManagement).
	Managed(name string) (version string, scope model.Scope, ok bool)
	Normalise(name string) string
}

type item struct {
	parent string
	dep    Dep
	depth  int
	scope  model.Scope
	excl   []string
}

// Resolve builds the graph from root dependencies. maxRounds bounds the
// re-selection loop; when it is exhausted the graph is marked incomplete.
func Resolve(ctx context.Context, src Source, root *model.Component, deps []Dep, maxRounds int) (*model.Graph, error) {
	if maxRounds <= 0 {
		maxRounds = 3
	}
	constraints := map[string][]string{} // PyPI: all ranges seen for a name
	var g *model.Graph
	pf := newPrefetcher(ctx, src)
	for round := 1; ; round++ {
		g = model.NewGraph(root)
		changed := false
		selected := map[string][]string{} // name -> chosen versions
		// scope in which a node was last expanded: a node reached again in a
		// stronger scope (a test dependency that a runtime dependency also
		// needs) is expanded again, so that its subtree takes that scope too
		expanded := map[string]model.Scope{}
		evicted := map[string]map[string]bool{}
		var q []item
		for _, d := range deps {
			q = append(q, item{parent: root.PURL, dep: d, depth: 1, scope: d.Scope})
		}
		for len(q) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			it := q[0]
			q = q[1:]
			d := it.dep
			name := src.Normalise(d.Name)
			if !src.MarkerApplies(d) || excluded(it.excl, name) {
				continue
			}
			scope := it.scope
			if mv, ms, ok := src.Managed(name); ok && it.depth > 1 {
				if mv != "" {
					d.Range = mv
				}
				if ms != "" {
					scope = ms
				}
			}
			v, err := selectVersion(ctx, src, pf, name, d.Range, selected, constraints)
			if err != nil || v == "" {
				note := "no version satisfies range"
				if err != nil {
					note = err.Error()
				} else {
					// a conflict: the versions are known and none satisfies
					// the range; missing data (offline, registry unreachable,
					// unknown package) is not a conflict, only a hole
					g.Conflicts = append(g.Conflicts, model.Conflict{Name: name, Range: d.Range, Parent: it.parent, Note: note})
				}
				// the dependency and its subtree are missing from the graph;
				// only an npm optional dependency may be left out (npm skips
				// it; a Maven <optional> dependency is still installed for the
				// project that declares it)
				msg := fmt.Sprintf("%s %q (required by %s) not resolved: %s", name, d.Range, it.parent, note)
				if d.Scope != model.ScopeOptional {
					g.Incomplete = append(g.Incomplete, msg)
				} else if err != nil {
					g.Notes = append(g.Notes, "optional dependency "+msg)
				}
				continue
			}
			if src.Rule() == MavenNearest {
				if prev := selected[name]; len(prev) > 0 && prev[0] != v {
					// a farther declaration lost mediation
					if evicted[name] == nil {
						evicted[name] = map[string]bool{}
					}
					evicted[name][v] = true
					v = prev[0]
				}
			}
			if src.Rule() == PyPISingle {
				constraints[name] = appendUnique(constraints[name], d.Range)
				if prev := selected[name]; len(prev) > 0 && prev[0] != v {
					changed = true
					v = prev[0] // keep this round consistent; re-select next round
				}
			}
			if !contains(selected[name], v) {
				selected[name] = append(selected[name], v)
			}
			c := src.Component(name, v)
			c.Scope = scope
			c.Source = "resolver"
			node := g.AddNode(c)
			if scopeRank(scope) < scopeRank(node.Scope) {
				node.Scope = scope
			}
			g.AddEdge(model.Edge{From: it.parent, To: node.PURL, Range: d.Range, Scope: scope})
			key := node.PURL + "[" + strings.Join(d.Extras, ",") + "]"
			if es, ok := expanded[key]; ok && scopeRank(scope) >= scopeRank(es) {
				continue
			}
			expanded[key] = scope
			children, err := pf.deps(name, v, d.Extras)
			if err != nil {
				g.Incomplete = append(g.Incomplete, fmt.Sprintf("metadata for %s@%s unavailable: %v", name, v, err))
				continue
			}
			excl := append(append([]string{}, it.excl...), d.Exclusions...)
			for _, ch := range children {
				s, ok := src.Transitive(scope, ch, it.depth+1)
				if !ok {
					continue
				}
				q = append(q, item{parent: node.PURL, dep: ch, depth: it.depth + 1, scope: s, excl: excl})
				pf.hint(src.Normalise(ch.Name), ch.Range)
			}
		}
		for name, vs := range evicted {
			for _, c := range g.Nodes {
				if src.Normalise(c.FullName()) == name {
					for v := range vs {
						c.Evicted = appendUnique(c.Evicted, v)
					}
					sort.Strings(c.Evicted)
				}
			}
		}
		if !changed {
			break
		}
		if round >= maxRounds {
			g.Incomplete = append(g.Incomplete, fmt.Sprintf("version re-selection did not settle after %d rounds", maxRounds))
			break
		}
	}
	g.ComputeDepths()
	return g, nil
}

func selectVersion(ctx context.Context, src Source, pf *prefetcher, name, rng string, selected, constraints map[string][]string) (string, error) {
	switch src.Rule() {
	case NPMDedupe:
		for _, v := range selected[name] {
			if src.Satisfies(v, rng) {
				return v, nil
			}
		}
	case MavenNearest:
		if prev := selected[name]; len(prev) > 0 {
			// the first selection wins; report the requested version so the
			// caller can record it as evicted
			if p, ok := src.Pinned(rng); ok {
				return p, nil
			}
			return prev[0], nil
		}
		if p, ok := src.Pinned(rng); ok {
			return p, nil
		}
	case PyPISingle:
		if prev := selected[name]; len(prev) > 0 && src.Satisfies(prev[0], rng) {
			return prev[0], nil
		}
	}
	vs, err := pf.versions(name)
	if err != nil {
		return "", err
	}
	all := append([]string{rng}, constraints[name]...)
	for i := len(vs) - 1; i >= 0; i-- {
		ok := true
		for _, r := range all {
			if !src.Satisfies(vs[i], r) {
				ok = false
				break
			}
		}
		if ok {
			return vs[i], nil
		}
	}
	// fall back to the current range alone (constraint set is unsatisfiable)
	for i := len(vs) - 1; i >= 0; i-- {
		if src.Satisfies(vs[i], rng) {
			return vs[i], nil
		}
	}
	return "", nil
}

func excluded(excl []string, name string) bool {
	for _, e := range excl {
		if e == name || e == "*:*" || e == "*" {
			return true
		}
		if g, a, ok := strings.Cut(e, ":"); ok {
			ng, na, _ := strings.Cut(name, ":")
			if (g == "*" || g == ng) && (a == "*" || a == na) {
				return true
			}
		}
	}
	return false
}

func scopeRank(s model.Scope) int {
	switch s {
	case model.ScopeRuntime:
		return 0
	case model.ScopeOptional:
		return 1
	case model.ScopeProvided:
		return 2
	case model.ScopeExtra:
		return 3
	case model.ScopeDev:
		return 4
	case model.ScopeTest:
		return 5
	}
	return 6
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, x string) []string {
	if contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// prefetcher issues metadata requests ahead of the traversal so that the
// network latency of the N registry requests overlaps.
type prefetcher struct {
	ctx context.Context
	src Source
	mu  sync.Mutex
	vs  map[string]*vres
	sem chan struct{}
}

type vres struct {
	once sync.Once
	v    []string
	err  error
}

func newPrefetcher(ctx context.Context, src Source) *prefetcher {
	return &prefetcher{ctx: ctx, src: src, vs: map[string]*vres{}, sem: make(chan struct{}, 16)}
}

func (p *prefetcher) get(name string) *vres {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.vs[name]
	if !ok {
		r = &vres{}
		p.vs[name] = r
	}
	return r
}

func (p *prefetcher) versions(name string) ([]string, error) {
	r := p.get(name)
	r.once.Do(func() { r.v, r.err = p.src.Versions(p.ctx, name) })
	return r.v, r.err
}

func (p *prefetcher) hint(name, rng string) {
	if _, ok := p.src.Pinned(rng); ok && p.src.Rule() == MavenNearest {
		return
	}
	go func() {
		p.sem <- struct{}{}
		defer func() { <-p.sem }()
		_, _ = p.versions(name)
	}()
}

func (p *prefetcher) deps(name, v string, extras []string) ([]Dep, error) {
	return p.src.Deps(p.ctx, name, v, extras)
}
