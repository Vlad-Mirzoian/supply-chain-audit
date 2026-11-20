package resolve

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/Masterminds/semver/v3"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// fake is an in-memory registry. Versions are SemVer and ranges are
// Masterminds constraints; a range that is a bare version is pinned.
type fake struct {
	rule     Rule
	versions map[string][]string         // name -> ascending versions
	deps     map[string][]Dep            // name@version -> dependencies
	managed  map[string]string           // name -> managed version (Maven)
	broken   map[string]bool             // name@version whose metadata fails
	drop     func(d Dep, depth int) bool // Transitive: false keeps the dependency
}

func (f *fake) Rule() Rule { return f.rule }

func (f *fake) Versions(_ context.Context, name string) ([]string, error) {
	vs, ok := f.versions[name]
	if !ok {
		return nil, errors.New("no such package")
	}
	return vs, nil
}

func (f *fake) Deps(_ context.Context, name, version string, extras []string) ([]Dep, error) {
	if f.broken[name+"@"+version] {
		return nil, errors.New("registry error")
	}
	out := append([]Dep{}, f.deps[name+"@"+version]...)
	for _, x := range extras {
		out = append(out, f.deps[name+"["+x+"]@"+version]...)
	}
	return out, nil
}

func (f *fake) Satisfies(v, rng string) bool {
	if rng == "" || rng == "*" {
		return true
	}
	c, err := semver.NewConstraint(rng)
	if err != nil {
		return false
	}
	sv, err := semver.NewVersion(v)
	return err == nil && c.Check(sv)
}

func (f *fake) Pinned(rng string) (string, bool) {
	if _, err := semver.StrictNewVersion(rng); err == nil {
		return rng, true
	}
	return "", false
}

func (f *fake) MarkerApplies(d Dep) bool { return d.Marker != "python_version < '3'" }

func (f *fake) Component(name, version string) *model.Component {
	return model.NewComponent("test", "", name, version)
}

func (f *fake) Transitive(parent model.Scope, d Dep, depth int) (model.Scope, bool) {
	if f.drop != nil && f.drop(d, depth) {
		return "", false
	}
	return parent, true
}

func (f *fake) Managed(name string) (string, model.Scope, bool) {
	v, ok := f.managed[name]
	return v, "", ok
}

func (f *fake) Normalise(n string) string { return strings.ToLower(n) }

func resolve(t *testing.T, f *fake, deps ...Dep) *model.Graph {
	t.Helper()
	g, err := Resolve(context.Background(), f, model.NewComponent("test", "", "root", "1.0.0"), deps, 3)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func nodes(g *model.Graph) string {
	var out []string
	for _, c := range g.Components() {
		out = append(out, c.Name+"@"+c.Version)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func d(name, rng string) Dep { return Dep{Name: name, Range: rng, Scope: model.ScopeRuntime} }

// npm: a version already in the graph is reused when it satisfies the range,
// otherwise a second version of the same package is added.
func TestNPMDedupe(t *testing.T) {
	f := &fake{rule: NPMDedupe,
		versions: map[string][]string{"a": {"1.0.0", "1.2.0", "2.0.0"}, "b": {"1.0.0"}, "c": {"1.0.0"}},
		deps: map[string][]Dep{
			"b@1.0.0": {d("a", "^1.1.0")},
			"c@1.0.0": {d("a", "^2.0.0")},
		}}
	g := resolve(t, f, d("a", "^1.0.0"), d("b", "^1.0.0"), d("c", "*"))
	if got, want := nodes(g), "a@1.2.0 a@2.0.0 b@1.0.0 c@1.0.0"; got != want {
		t.Fatalf("nodes %s, want %s", got, want)
	}
	if n := len(g.Out["pkg:test/b@1.0.0"]); n != 1 || g.Out["pkg:test/b@1.0.0"][0].To != "pkg:test/a@1.2.0" {
		t.Errorf("b does not reuse a@1.2.0: %+v", g.Out["pkg:test/b@1.0.0"])
	}
	if g.Nodes["pkg:test/a@2.0.0"].Depth != 2 {
		t.Errorf("depth of a@2.0.0: %d", g.Nodes["pkg:test/a@2.0.0"].Depth)
	}
}

// PyPI: one version per name. A later, stricter constraint triggers another
// round in which the version satisfying all constraints is chosen.
func TestPyPIReselection(t *testing.T) {
	f := &fake{rule: PyPISingle,
		versions: map[string][]string{"x": {"1.0.0", "1.9.0", "2.0.0"}, "y": {"1.0.0"}},
		deps:     map[string][]Dep{"y@1.0.0": {d("x", "<2.0.0")}}}
	g := resolve(t, f, d("x", ">=1.0.0"), d("y", "*"))
	if got, want := nodes(g), "x@1.9.0 y@1.0.0"; got != want {
		t.Fatalf("nodes %s, want %s", got, want)
	}
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
}

// Unsatisfiable constraints must not loop for ever: after maxRounds the graph
// is marked incomplete.
func TestPyPIUnsatisfiableIsBounded(t *testing.T) {
	f := &fake{rule: PyPISingle,
		versions: map[string][]string{"x": {"1.9.0", "2.0.0"}, "y": {"1.0.0"}},
		deps:     map[string][]Dep{"y@1.0.0": {d("x", "<2.0.0")}}}
	g := resolve(t, f, d("x", ">=2.0.0"), d("y", "*"))
	if len(g.Incomplete) != 1 || !strings.Contains(g.Incomplete[0], "did not settle after 3 rounds") {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
}

// Maven: the declaration nearest to the root fixes the version; farther ones
// are recorded as evicted. dependencyManagement overrides transitive versions
// only, and exclusions cut a subtree for everything below the declaration.
func TestMavenNearestManagedExclusions(t *testing.T) {
	f := &fake{rule: MavenNearest,
		versions: map[string][]string{"g:c": {"1.0.0", "2.0.0", "3.0.0"}},
		deps: map[string][]Dep{
			"g:a@1.0.0": {d("g:c", "2.0.0"), d("g:m", "1.0.0"), d("g:x", "1.0.0")},
			"g:x@1.0.0": {d("g:y", "1.0.0")},
			"g:b@1.0.0": {d("g:x", "1.0.0")},
		},
		managed: map[string]string{"g:m": "9.0.0", "g:b": "5.0.0"}}
	a := d("g:a", "1.0.0")
	a.Exclusions = []string{"g:y"}
	g := resolve(t, f, a, d("g:c", "1.0.0"), d("g:b", "1.0.0"))
	if got, want := nodes(g), "g:a@1.0.0 g:b@1.0.0 g:c@1.0.0 g:m@9.0.0 g:x@1.0.0"; got != want {
		t.Fatalf("nodes %s, want %s", got, want)
	}
	if ev := g.Nodes["pkg:test/g:c@1.0.0"].Evicted; len(ev) != 1 || ev[0] != "2.0.0" {
		t.Errorf("evicted %v", ev)
	}
	// g:y is excluded below g:a; g:b reaches g:x too, but g:x was already
	// expanded through g:a (Maven keeps the first expansion as well)
	if g.Nodes["pkg:test/g:y@1.0.0"] != nil {
		t.Error("excluded dependency resolved")
	}
	for _, pat := range []string{"g:y", "g:*", "*:y", "*:*", "*"} {
		if !excluded([]string{pat}, "g:y") {
			t.Errorf("pattern %s does not exclude g:y", pat)
		}
	}
	if excluded([]string{"h:*", "g:z"}, "g:y") {
		t.Error("unrelated pattern excludes g:y")
	}
}

// Markers, non-transitive scopes, missing packages and failing metadata.
func TestSkipsConflictsAndIncomplete(t *testing.T) {
	f := &fake{rule: NPMDedupe,
		versions: map[string][]string{"a": {"1.0.0"}, "a2": {"1.0.0"}, "py2": {"1.0.0"}, "t": {"1.0.0"}, "bad": {"1.0.0"}},
		deps:     map[string][]Dep{"a@1.0.0": {d("t", "*")}},
		broken:   map[string]bool{"bad@1.0.0": true},
		drop:     func(d Dep, depth int) bool { return d.Name == "t" }}
	py2 := d("py2", "*")
	py2.Marker = "python_version < '3'"
	opt := d("ghost-optional", "*")
	opt.Scope = model.ScopeOptional
	g := resolve(t, f, d("a", "*"), py2, d("ghost", "*"), d("a2", "^3.0.0"), d("bad", "*"), opt)
	if got, want := nodes(g), "a@1.0.0 bad@1.0.0"; got != want {
		t.Fatalf("nodes %s, want %s", got, want)
	}
	// only a known package without a matching version is a conflict; an
	// unknown package is missing data (incomplete, or a note when optional)
	if len(g.Conflicts) != 1 || g.Conflicts[0].Name != "a2" {
		t.Errorf("conflicts %+v, want only a2 (no version in range)", g.Conflicts)
	}
	if len(g.Notes) != 1 || !strings.Contains(g.Notes[0], "optional dependency ghost-optional") {
		t.Errorf("notes %q, want the unresolved optional dependency", g.Notes)
	}
	// a dependency that cannot be resolved leaves a hole in the graph: the
	// analysis is incomplete, except for an npm optional dependency
	want := []string{"ghost", "a2", "bad@1.0.0"}
	if len(g.Incomplete) != len(want) {
		t.Fatalf("incomplete %v, want entries for %v", g.Incomplete, want)
	}
	for i, w := range want {
		if !strings.Contains(g.Incomplete[i], w) {
			t.Errorf("incomplete[%d] = %q, want %q", i, g.Incomplete[i], w)
		}
	}
}

// Extras add dependencies, and the same version is expanded again for a new
// set of extras (uv / pip "httpx[http2]").
func TestExtras(t *testing.T) {
	f := &fake{rule: PyPISingle,
		versions: map[string][]string{"httpx": {"1.0.0"}, "h2": {"4.0.0"}, "anyio": {"4.0.0"}, "app": {"1.0.0"}},
		deps: map[string][]Dep{
			"httpx@1.0.0":        {d("anyio", "*")},
			"httpx[http2]@1.0.0": {d("h2", "*")},
			"app@1.0.0":          {{Name: "httpx", Range: "*", Scope: model.ScopeRuntime, Extras: []string{"http2"}}},
		}}
	g := resolve(t, f, d("httpx", "*"), d("app", "*"))
	if got, want := nodes(g), "anyio@4.0.0 app@1.0.0 h2@4.0.0 httpx@1.0.0"; got != want {
		t.Fatalf("nodes %s, want %s", got, want)
	}
}

// Cycles terminate and keep both edges; the weaker scope does not overwrite a
// runtime scope reached by another path.
func TestCyclesAndScopes(t *testing.T) {
	f := &fake{rule: NPMDedupe,
		versions: map[string][]string{"a": {"1.0.0"}, "b": {"1.0.0"}},
		deps:     map[string][]Dep{"a@1.0.0": {d("b", "*")}, "b@1.0.0": {d("a", "*")}}}
	dev := d("b", "*")
	dev.Scope = model.ScopeDev
	g := resolve(t, f, dev, d("a", "*"))
	if g.EdgeCount() != 4 {
		t.Errorf("edges %d", g.EdgeCount())
	}
	if s := g.Nodes["pkg:test/b@1.0.0"].Scope; s != model.ScopeRuntime {
		t.Errorf("scope of b: %s (runtime path through a must win)", s)
	}
}

func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fake{rule: NPMDedupe, versions: map[string][]string{"a": {"1.0.0"}}}
	if _, err := Resolve(ctx, f, model.NewComponent("test", "", "root", "1.0.0"), []Dep{d("a", "*")}, 3); err == nil {
		t.Error("cancelled context ignored")
	}
}

// A package first reached in a weak scope and later through a runtime path is
// expanded again, so that its own dependencies become runtime too (a test
// dependency t needs x -> y; the runtime dependency a reaches x one level
// deeper, after x was expanded in test scope).
func TestScopeUpgradeReachesSubtree(t *testing.T) {
	f := &fake{rule: MavenNearest,
		versions: map[string][]string{},
		deps: map[string][]Dep{
			"t@1.0.0": {d("x", "1.0.0")},
			"a@1.0.0": {d("m", "1.0.0")},
			"m@1.0.0": {d("x", "1.0.0")},
			"x@1.0.0": {d("y", "1.0.0")},
		}}
	test := d("t", "1.0.0")
	test.Scope = model.ScopeTest
	g := resolve(t, f, test, d("a", "1.0.0"))
	for _, n := range []string{"x", "y"} {
		if s := g.Nodes["pkg:test/"+n+"@1.0.0"].Scope; s != model.ScopeRuntime {
			t.Errorf("scope of %s: %s, want runtime", n, s)
		}
	}
	if s := g.Nodes["pkg:test/t@1.0.0"].Scope; s != model.ScopeTest {
		t.Errorf("scope of t: %s", s)
	}
	// depth of a runtime package is measured along runtime dependencies
	if dx := g.Nodes["pkg:test/x@1.0.0"].Depth; dx != 3 {
		t.Errorf("depth of x: %d, want 3 (root -> a -> m -> x)", dx)
	}
}
