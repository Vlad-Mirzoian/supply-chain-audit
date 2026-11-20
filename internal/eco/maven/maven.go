package maven

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	mvnversion "github.com/masahiro331/go-mvn-version"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/resolve"
)

// Plugin implements common.Plugin for Maven.
type Plugin struct{}

func (Plugin) Name() string { return model.Maven }

func (Plugin) Detect(dir string) []string {
	if common.Exists(dir, "pom.xml") {
		return []string{"pom.xml"}
	}
	return nil
}

// Compare orders versions with Maven's ComparableVersion rules.
func Compare(a, b string) int {
	va, ea := mvnversion.NewVersion(a)
	vb, eb := mvnversion.NewVersion(b)
	if ea != nil || eb != nil {
		return strings.Compare(a, b)
	}
	return va.Compare(vb)
}

// Satisfies checks v against a Maven version or range specification such as
// "[1.0,2.0)", "(,1.5]" or "[1.2]". A plain version is a soft requirement and
// is satisfied only by itself.
func Satisfies(v, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	if !strings.ContainsAny(spec, "[(") {
		return Compare(v, spec) == 0
	}
	for _, r := range splitRanges(spec) {
		if inRange(v, r) {
			return true
		}
	}
	return false
}

func splitRanges(spec string) []string {
	var out []string
	depth, start := 0, 0
	for i, ch := range spec {
		switch ch {
		case '[', '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ']', ')':
			depth--
			if depth == 0 {
				out = append(out, spec[start:i+1])
			}
		}
	}
	return out
}

func inRange(v, r string) bool {
	if len(r) < 2 {
		return false
	}
	lo, hi := r[0], r[len(r)-1]
	body := r[1 : len(r)-1]
	if !strings.Contains(body, ",") {
		return Compare(v, strings.TrimSpace(body)) == 0
	}
	a, b, _ := strings.Cut(body, ",")
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a != "" {
		c := Compare(v, a)
		if c < 0 || c == 0 && lo == '(' {
			return false
		}
	}
	if b != "" {
		c := Compare(v, b)
		if c > 0 || c == 0 && hi == ')' {
			return false
		}
	}
	return true
}

func split(name string) (string, string) {
	g, a, _ := strings.Cut(name, ":")
	return g, a
}

// Load resolves the Maven project in dir. A multi-module project is resolved
// module by module, as Maven does, and the graphs are merged.
func (Plugin) Load(ctx context.Context, dir string, opt common.Options) (*model.Graph, error) {
	if opt.Net == nil {
		return nil, fmt.Errorf("Maven resolution needs network access (no lockfile format exists)")
	}
	repo := NewRepo(opt.Net)
	rootPOM, err := ReadLocal(filepath.Join(dir, "pom.xml"))
	if err != nil {
		return nil, err
	}
	// collect reactor modules
	var modules []*POM
	var walk func(p *POM, depth int)
	walk = func(p *POM, depth int) {
		modules = append(modules, p)
		if depth > 6 {
			return
		}
		mods := append([]string{}, p.Modules...)
		for _, pr := range p.Profiles {
			if strings.TrimSpace(pr.Activation.ActiveByDefault) == "true" {
				mods = append(mods, pr.Modules...)
			}
		}
		for _, m := range mods {
			path := filepath.Join(p.dir, m)
			if !strings.HasSuffix(path, ".xml") {
				path = filepath.Join(path, "pom.xml")
			}
			if mp, err := ReadLocal(path); err == nil {
				walk(mp, depth+1)
			}
		}
	}
	walk(rootPOM, 0)
	effs := make([]*Effective, len(modules))
	reactor := map[string]bool{}
	for i, m := range modules {
		e, err := repo.EffectiveLocal(ctx, m)
		if err != nil {
			return nil, err
		}
		effs[i] = e
		reactor[e.GroupID+":"+e.ArtifactID] = true
		repo.mu.Lock()
		repo.local[gav(e.GroupID, e.ArtifactID, e.Version)] = m
		repo.mu.Unlock()
	}
	// the declared repositories are searched after Maven Central (Maven
	// itself searches them first: M3 reports them); plain HTTP is not used
	for _, u := range effs[0].Repos {
		if u != "" && !strings.Contains(u, "${") && strings.HasPrefix(strings.ToLower(u), "https://") {
			repo.URLs = append(repo.URLs, strings.TrimSuffix(u, "/"))
		}
	}
	root := model.NewComponent(model.Maven, effs[0].GroupID, effs[0].ArtifactID, effs[0].Version)
	root.Source = "pom.xml"
	merged := model.NewGraph(root)
	seenRepo := map[model.Repository]bool{}
	for _, e := range effs {
		for _, d := range e.RepoDecls {
			if d.URL != "" && !seenRepo[d] {
				seenRepo[d] = true
				merged.Repositories = append(merged.Repositories, d)
			}
		}
	}
	merged.Inputs = []string{"pom.xml"}
	for i, e := range effs {
		if e.Packaging == "pom" && len(e.Deps) == 0 {
			continue
		}
		src := &source{repo: repo, managed: map[string]pomDep{}, reactor: reactor}
		for _, m := range e.Managed {
			k := m.GroupID + ":" + m.ArtifactID
			if _, ok := src.managed[k]; !ok {
				src.managed[k] = m
			}
		}
		var deps []resolve.Dep
		for _, d := range e.Deps {
			// A sibling module is resolved like any dependency, from its local
			// POM, because the versions it brings in take part in the
			// nearest-wins mediation of this module, as in Maven's reactor;
			// collapseReactor then removes it from the graph.
			s, ok := scopeOf(d.Scope)
			if !ok || (s == model.ScopeTest && !opt.IncludeDev) {
				continue
			}
			if d.Type != "" && d.Type != "jar" && d.Type != "bundle" {
				continue
			}
			if d.GroupID == "" || d.ArtifactID == "" || strings.TrimSpace(d.Version) == "" {
				// Maven rejects the POM; resolving it would pick an arbitrary
				// version. When a parent POM or BOM could not be read, the
				// version is probably defined there, and that problem
				// (reported below) is the reason.
				if len(e.Problems) == 0 {
					merged.Incomplete = append(merged.Incomplete, fmt.Sprintf("module %s: dependency %s:%s has no groupId, artifactId or version", modules[i].ArtifactID, d.GroupID, d.ArtifactID))
				}
				continue
			}
			if strings.Contains(d.GroupID+d.ArtifactID+d.Version, "${") {
				// a property that no POM defines: Maven stops ("must be a
				// valid version"), so nothing can be said about what it
				// would build; as above, an unreadable parent POM or BOM is
				// the more likely reason and is reported instead
				if len(e.Problems) == 0 {
					merged.Incomplete = append(merged.Incomplete, fmt.Sprintf("module %s: dependency %s:%s:%s uses an undefined property", modules[i].ArtifactID, d.GroupID, d.ArtifactID, d.Version))
				}
				continue
			}
			deps = append(deps, depOf(d, s))
		}
		g, err := resolve.Resolve(ctx, src, root, deps, 1)
		if err != nil {
			return nil, err
		}
		if n := src.undefinedNote(); n != "" {
			g.Notes = append(g.Notes, fmt.Sprintf("module %s: %s", modules[i].ArtifactID, n))
		}
		for _, p := range e.Problems {
			merged.Incomplete = append(merged.Incomplete, fmt.Sprintf("module %s: %s", modules[i].ArtifactID, p))
		}
		collapseReactor(g, reactor)
		mergeGraph(merged, g)
	}
	merged.ComputeDepths()
	return merged, nil
}

// collapseReactor removes the reactor modules that a module reached through
// its sibling dependencies: they belong to the project and are not
// third-party components. Their dependencies become dependencies of the
// project, in the weaker of the module's scope and the edge's scope, as when
// the sibling is analysed on its own.
func collapseReactor(g *model.Graph, reactor map[string]bool) {
	isModule := func(id string) bool {
		c := g.Nodes[id]
		return id != g.Root && c != nil && reactor[c.Namespace+":"+c.Name]
	}
	var mods []string
	for id := range g.Nodes {
		if isModule(id) {
			mods = append(mods, id)
		}
	}
	sort.Strings(mods)
	for _, id := range mods {
		for _, e := range g.Out[id] {
			if isModule(e.To) {
				continue
			}
			e.From = g.Root
			if model.ScopeRank(g.Nodes[id].Scope) > model.ScopeRank(e.Scope) {
				e.Scope = g.Nodes[id].Scope
			}
			g.AddEdge(e)
		}
	}
	for _, id := range mods {
		delete(g.Out, id)
		delete(g.Nodes, id)
	}
	for from, es := range g.Out {
		kept := es[:0]
		for _, e := range es {
			if g.Nodes[e.To] != nil {
				kept = append(kept, e)
			}
		}
		g.Out[from] = kept
	}
}

func mergeGraph(dst, src *model.Graph) {
	for id, c := range src.Nodes {
		if id == src.Root {
			continue
		}
		if old, ok := dst.Nodes[id]; ok {
			if rank(c.Scope) < rank(old.Scope) {
				old.Scope = c.Scope
			}
			for _, ev := range c.Evicted {
				if !contains(old.Evicted, ev) {
					old.Evicted = append(old.Evicted, ev)
				}
			}
			continue
		}
		dst.Nodes[id] = c
	}
	for _, es := range src.Out {
		for _, e := range es {
			if e.From == src.Root {
				e.From = dst.Root
			}
			dst.AddEdge(e)
		}
	}
	dst.Conflicts = append(dst.Conflicts, src.Conflicts...)
	dst.Incomplete = append(dst.Incomplete, src.Incomplete...)
	dst.Notes = append(dst.Notes, src.Notes...)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if x == y {
			return true
		}
	}
	return false
}

func rank(s model.Scope) int {
	switch s {
	case model.ScopeRuntime:
		return 0
	case model.ScopeProvided:
		return 1
	}
	return 2
}

func scopeOf(s string) (model.Scope, bool) {
	switch s {
	case "", "compile", "runtime":
		return model.ScopeRuntime, true
	case "provided":
		return model.ScopeProvided, true
	case "test":
		return model.ScopeTest, true
	}
	return "", false // system, import
}

func depOf(d pomDep, s model.Scope) resolve.Dep {
	var ex []string
	for _, x := range d.Exclusions {
		ex = append(ex, x.GroupID+":"+x.ArtifactID)
	}
	return resolve.Dep{
		Name: d.GroupID + ":" + d.ArtifactID, Range: d.Version, Scope: s,
		Optional: strings.TrimSpace(d.Optional) == "true", Exclusions: ex,
	}
}

// ---------------------------------------------------------------- resolver source

type source struct {
	repo    *Repo
	managed map[string]pomDep
	reactor map[string]bool
	mu      sync.Mutex
	// dependencies of dependency POMs whose coordinates use a property that
	// no POM defines; Maven only warns about such a POM ("is invalid,
	// transitive dependencies (if any) will not be available"), so they are
	// left out as Maven does and listed in a note
	undefined map[string]bool
}

func (s *source) noteUndefined(owner string, d pomDep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.undefined == nil {
		s.undefined = map[string]bool{}
	}
	s.undefined[fmt.Sprintf("%s declares %s:%s:%s", owner, d.GroupID, d.ArtifactID, d.Version)] = true
}

func (s *source) undefinedNote() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.undefined) == 0 {
		return ""
	}
	list := make([]string, 0, len(s.undefined))
	for k := range s.undefined {
		list = append(list, k)
	}
	sort.Strings(list)
	more := ""
	if len(list) > 5 {
		more = fmt.Sprintf(", … %d more", len(list)-5)
		list = list[:5]
	}
	return fmt.Sprintf("%d dependencies of dependency POMs use undefined properties and are left out, as Maven does: %s%s", len(s.undefined), strings.Join(list, "; "), more)
}

func (s *source) Rule() resolve.Rule        { return resolve.MavenNearest }
func (s *source) Normalise(n string) string { return n }

func (s *source) Versions(ctx context.Context, name string) ([]string, error) {
	g, a := split(name)
	vs, err := s.repo.Versions(ctx, g, a)
	if err != nil {
		return nil, err
	}
	sort.Slice(vs, func(i, j int) bool { return Compare(vs[i], vs[j]) < 0 })
	return vs, nil
}

func (s *source) Deps(ctx context.Context, name, version string, _ []string) ([]resolve.Dep, error) {
	g, a := split(name)
	e, err := s.repo.Effective(ctx, g, a, version)
	if err != nil {
		return nil, err
	}
	var out []resolve.Dep
	for _, d := range e.Deps {
		sc, ok := scopeOf(d.Scope)
		if !ok || sc == model.ScopeTest || sc == model.ScopeProvided {
			continue // not transitive
		}
		if strings.TrimSpace(d.Optional) == "true" {
			continue // optional dependencies are not transitive
		}
		if d.Type != "" && d.Type != "jar" && d.Type != "bundle" {
			continue
		}
		if strings.Contains(d.GroupID+d.ArtifactID+d.Version, "${") {
			s.noteUndefined(name+":"+version, d)
			continue
		}
		out = append(out, depOf(d, sc))
	}
	return out, nil
}

func (s *source) Satisfies(v, r string) bool { return Satisfies(v, r) }

func (s *source) Pinned(r string) (string, bool) {
	r = strings.TrimSpace(r)
	if r != "" && !strings.ContainsAny(r, "[(,") {
		return r, true
	}
	if strings.HasPrefix(r, "[") && strings.HasSuffix(r, "]") && !strings.Contains(r, ",") {
		return strings.Trim(r, "[]"), true
	}
	return "", false
}

func (s *source) MarkerApplies(d resolve.Dep) bool {
	return d.Range != "" && !strings.Contains(d.Range, "${")
}

func (s *source) Component(name, version string) *model.Component {
	g, a := split(name)
	return model.NewComponent(model.Maven, g, a, version)
}

func (s *source) Transitive(parent model.Scope, d resolve.Dep, depth int) (model.Scope, bool) {
	switch parent {
	case model.ScopeProvided, model.ScopeTest:
		return parent, true
	}
	return model.ScopeRuntime, true
}

func (s *source) Managed(name string) (string, model.Scope, bool) {
	m, ok := s.managed[name]
	if !ok {
		return "", "", false
	}
	sc, _ := scopeOf(m.Scope)
	if m.Scope == "" {
		sc = ""
	}
	return m.Version, sc, true
}
