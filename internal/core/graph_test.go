package core

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func load(t *testing.T, dir string, dev bool) *model.Graph {
	t.Helper()
	g, _, err := BuildGraph(context.Background(), filepath.Join("..", "..", "testdata", dir), "", common.Options{IncludeDev: dev})
	if err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	return g
}

func names(g *model.Graph) []string {
	var out []string
	for _, c := range g.Components() {
		out = append(out, c.FullName()+"@"+c.Version)
	}
	sort.Strings(out)
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPackageLockV3(t *testing.T) {
	g := load(t, "npm-v3", false)
	// stale@9.9.9 is required by nothing; npm ci installs it anyway, so it
	// is kept (attached to the project) and marked extraneous
	want := []string{"a@1.2.0", "b@2.0.0", "c@1.3.0", "c@2.1.0", "d@1.0.0", "e@1.0.0", "stale@9.9.9"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	for _, c := range g.Components() {
		if c.Extraneous != (c.Name == "stale") {
			t.Errorf("%s: extraneous %v", c.Name, c.Extraneous)
		}
	}
	// nested c@2.1.0 must be the child of b, hoisted c@1.3.0 the child of a
	c2 := g.Nodes["pkg:npm/c@2.1.0"]
	if c2.Depth != 2 {
		t.Errorf("c@2.1.0 depth %d", c2.Depth)
	}
	if len(g.Cycles) != 1 {
		t.Errorf("expected the d<->e cycle, got %v", g.Cycles)
	}
	if len(g.Notes) == 0 {
		t.Errorf("extraneous lockfile entry not reported")
	}
	if g.Nodes["pkg:npm/a@1.2.0"].Integrity[0] != "sha512-AAA=" {
		t.Errorf("integrity not read")
	}
	gd := load(t, "npm-v3", true)
	if gd.Nodes["pkg:npm/t@1.0.0"] == nil || gd.Nodes["pkg:npm/t@1.0.0"].Scope != model.ScopeDev {
		t.Errorf("dev dependency missing or wrong scope")
	}
	// a development entry is required by the project: never extraneous, in
	// the full graph or (left out) in the runtime graph
	for _, c := range gd.Components() {
		if c.Extraneous != (c.Name == "stale") {
			t.Errorf("full graph: %s extraneous %v", c.Name, c.Extraneous)
		}
	}
}

func TestPackageLockV1Nesting(t *testing.T) {
	g := load(t, "npm-v1", false)
	// a requires b@^1 which is nested under a; the hoisted b@2.0.0 is
	// required by nothing, but npm ci installs it: kept and marked extraneous
	want := []string{"a@1.0.0", "b@1.5.0", "b@2.0.0", "c@3.0.0"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	for _, c := range g.Components() {
		if c.Extraneous != (c.PURL == "pkg:npm/b@2.0.0") {
			t.Errorf("%s: extraneous %v", c.PURL, c.Extraneous)
		}
	}
}

func TestYarnV1(t *testing.T) {
	g := load(t, "yarn", false)
	want := []string{"a@1.2.0", "b@2.0.0", "c@1.3.0", "c@2.1.0"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
}

func TestPnpm9(t *testing.T) {
	g := load(t, "pnpm9", false)
	want := []string{"a@1.2.0", "b@2.0.0", "c@1.3.0"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	if g.Nodes["pkg:npm/b@2.0.0"].Depth != 1 || g.Nodes["pkg:npm/c@1.3.0"].Depth != 2 {
		t.Errorf("depths wrong")
	}
}

func TestPoetry(t *testing.T) {
	g := load(t, "poetry", false)
	want := []string{"flask@2.0.1", "jinja2@3.0.1"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	gd := load(t, "poetry", true)
	if gd.Nodes["pkg:pypi/pytest@7.0.0"] == nil {
		t.Errorf("dev group not included")
	}
}

func TestUV(t *testing.T) {
	g := load(t, "uv", false)
	want := []string{"requests@2.31.0", "urllib3@2.0.0"}
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	if len(g.Nodes["pkg:pypi/requests@2.31.0"].Integrity) != 2 {
		t.Errorf("hashes not read")
	}
}

// A directory with two ecosystems gives one graph with both; before, only the
// first detected ecosystem was audited and the other one silently skipped.
func TestMixedEcosystems(t *testing.T) {
	g, ecos, err := BuildGraph(context.Background(), filepath.Join("..", "..", "testdata", "mixed"), "", common.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !eq(ecos, []string{"npm", "pypi"}) {
		t.Errorf("ecosystems %v", ecos)
	}
	npmOnly, pyOnly := names(load(t, "npm-v1", false)), names(load(t, "uv", false))
	want := append(append([]string{}, npmOnly...), pyOnly...)
	sort.Strings(want)
	if got := names(g); !eq(got, want) {
		t.Fatalf("nodes %v, want %v", got, want)
	}
	if g.Root != "pkg:npm/old@0.1.0" {
		t.Errorf("root %s", g.Root)
	}
	req := g.Nodes["pkg:pypi/requests@2.31.0"]
	if !req.Direct || req.Depth != 1 || g.Nodes["pkg:pypi/urllib3@2.0.0"].Depth != 2 {
		t.Errorf("python dependencies not attached to the root: %+v", req)
	}
	if len(g.Inputs) != 2 {
		t.Errorf("inputs %v", g.Inputs)
	}
	// --ecosystem still restricts the audit to one ecosystem
	only, ecos, err := BuildGraph(context.Background(), filepath.Join("..", "..", "testdata", "mixed"), "pypi", common.Options{})
	if err != nil || !eq(ecos, []string{"pypi"}) || !eq(names(only), pyOnly) {
		t.Errorf("forced ecosystem: %v %v %v", ecos, names(only), err)
	}
}

// A package.json that only configures development tools must not make the
// audit of a Python project incomplete (it needs no lockfile).
func TestToolOnlyPackageJSON(t *testing.T) {
	g := load(t, "python-with-tools", false)
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
	if got, want := names(g), names(load(t, "uv", false)); !eq(got, want) {
		t.Errorf("nodes %v, want %v", got, want)
	}
}

// The root of a Python project is named after pyproject.toml; without a name
// the directory name is used, also when the directory is given as ".".
func TestPythonRootName(t *testing.T) {
	if g := load(t, "uv", false); g.Root != "pkg:pypi/demo@0.0.0" {
		t.Errorf("uv root %s", g.Root)
	}
	lock, err := os.ReadFile(filepath.Join("..", "..", "testdata", "poetry", "poetry.lock"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "orders_api")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "poetry.lock"), lock, 0o644)
	os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[tool.poetry.dependencies]\nFlask = \"^2.0\"\n"), 0o644)
	t.Chdir(dir)
	g, _, err := BuildGraph(context.Background(), ".", "", common.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if g.Root != "pkg:pypi/orders-api@0.0.0" {
		t.Errorf("root of \".\" is %s", g.Root)
	}
}
