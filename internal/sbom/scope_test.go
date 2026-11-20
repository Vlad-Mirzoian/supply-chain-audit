package sbom

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Development and test dependencies are in the SBOM and marked as such:
// CycloneDX scope "excluded" (plus the npm development property), SPDX
// DEV_DEPENDENCY_OF / TEST_DEPENDENCY_OF instead of DEPENDS_ON on every edge.
// Reading the documents back keeps the edges.
func TestScopesInSBOM(t *testing.T) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := g.AddNode(model.NewComponent(model.NPM, "", "a", "1.0.0"))
	d := g.AddNode(model.NewComponent(model.NPM, "", "lint", "2.0.0"))
	h := g.AddNode(model.NewComponent(model.NPM, "", "helper", "1.0.0"))
	x := g.AddNode(model.NewComponent(model.NPM, "", "mocha", "10.0.0"))
	d.Scope, h.Scope, x.Scope = model.ScopeDev, model.ScopeDev, model.ScopeTest
	g.AddEdge(model.Edge{From: root.PURL, To: a.PURL, Scope: model.ScopeRuntime})
	g.AddEdge(model.Edge{From: root.PURL, To: d.PURL, Scope: model.ScopeDev})
	g.AddEdge(model.Edge{From: d.PURL, To: h.PURL})
	g.AddEdge(model.Edge{From: root.PURL, To: x.PURL, Scope: model.ScopeTest})
	doc := FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))

	cdx, err := doc.CycloneDX("app", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Components []struct {
			Name       string `json:"name"`
			Scope      string `json:"scope"`
			Properties []struct{ Name, Value string }
		} `json:"components"`
	}
	json.Unmarshal(cdx, &c)
	for _, x := range c.Components {
		excluded := x.Name != "a"
		if (x.Scope == "excluded") != excluded {
			t.Errorf("CycloneDX %s: scope %q", x.Name, x.Scope)
		}
		if excluded && (len(x.Properties) == 0 || x.Properties[0].Name != "cdx:npm:package:development") {
			t.Errorf("CycloneDX %s: properties %+v", x.Name, x.Properties)
		}
	}

	spdx, err := doc.SPDX("app")
	if err != nil {
		t.Fatal(err)
	}
	s := string(spdx)
	for rel, want := range map[string]int{"DEV_DEPENDENCY_OF": 2, "TEST_DEPENDENCY_OF": 1, `"DEPENDS_ON"`: 1} { // lint, helper; mocha; a
		if strings.Count(s, rel) != want {
			t.Errorf("SPDX: %d x %s, want %d", strings.Count(s, rel), rel, want)
		}
	}

	dir := t.TempDir()
	for name, b := range map[string][]byte{"c.json": cdx, "s.json": spdx} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		back, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(back.Edges) != 4 || len(back.Components) != 4 {
			t.Errorf("%s read back: %d components, %d edges", name, len(back.Components), len(back.Edges))
		}
		for _, c := range back.Components {
			if c.Scope.Production() != (c.Name == "a") {
				t.Errorf("%s read back: %s has scope %q", name, c.Name, c.Scope)
			}
		}
	}
}

// An SBOM of an incomplete graph says so: CycloneDX with an "incomplete"
// composition of the root and the reasons as properties, SPDX in the
// creation comment; both are read back. A complete graph adds neither.
func TestIncompleteSBOM(t *testing.T) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := g.AddNode(model.NewComponent(model.NPM, "", "a", "1.0.0"))
	g.AddEdge(model.Edge{From: root.PURL, To: a.PURL, Scope: model.ScopeRuntime})
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	write := func(name string, b []byte, err error) string {
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		return p
	}
	full := FromGraph(g, "test", now)
	cdx, err := full.CycloneDX("app", "1.0.0")
	if strings.Contains(string(cdx), "compositions") || strings.Contains(string(cdx), "ssca:incomplete") {
		t.Errorf("complete graph marked incomplete: %s", cdx)
	}
	if d, _ := Read(write("full.cdx.json", cdx, err)); len(d.Incomplete) != 0 {
		t.Errorf("complete CycloneDX read as incomplete: %v", d.Incomplete)
	}

	g.Incomplete = []string{"package-lock.json is out of sync", "package-lock.json is out of sync", "registry unavailable"}
	doc := FromGraph(g, "test", now)
	if len(doc.Incomplete) != 2 {
		t.Fatalf("reasons %v, want 2 without the duplicate", doc.Incomplete)
	}
	cdx, err = doc.CycloneDX("app", "1.0.0")
	var c struct {
		Compositions []struct {
			Aggregate  string   `json:"aggregate"`
			Assemblies []string `json:"assemblies"`
		} `json:"compositions"`
	}
	json.Unmarshal(cdx, &c)
	if len(c.Compositions) != 1 || c.Compositions[0].Aggregate != "incomplete" || c.Compositions[0].Assemblies[0] != root.PURL {
		t.Errorf("compositions %+v", c.Compositions)
	}
	spdx, err2 := doc.SPDX("app")
	for _, p := range []string{write("inc.cdx.json", cdx, err), write("inc.spdx.json", spdx, err2)} {
		d, err := Read(p)
		if err != nil || strings.Join(d.Incomplete, "|") != "package-lock.json is out of sync|registry unavailable" {
			t.Errorf("%s: incomplete %v, %v", filepath.Base(p), d.Incomplete, err)
		}
	}
}

// An integrity value of a lockfile may list several hashes; every one of them
// goes into the SBOM (before, the whole value was lost).
func TestSeveralHashesInOneIntegrity(t *testing.T) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := model.NewComponent(model.NPM, "", "a", "1.0.0")
	a.Integrity = []string{"sha1-AQID sha512-BAUG"}
	g.AddNode(a)
	b := model.NewComponent(model.PyPI, "", "b", "1.0.0")
	b.Integrity = []string{"sha256:ABCD"}
	g.AddNode(b)
	want := map[string]map[string][]string{
		a.PURL: {"SHA-1": {"010203"}, "SHA-512": {"040506"}},
		b.PURL: {"SHA-256": {"abcd"}},
	}
	doc := FromGraph(g, "test", time.Now())
	if len(doc.Components) != 2 {
		t.Fatalf("components %d", len(doc.Components))
	}
	for _, c := range doc.Components {
		if !maps.EqualFunc(c.Hashes, want[c.PURL], slices.Equal[[]string]) {
			t.Errorf("%s: hashes %v, want %v", c.PURL, c.Hashes, want[c.PURL])
		}
	}
}

// An SBOM that states that it is incomplete cannot get the score of a
// complete one: the dependency relationships element is not met.
func TestAssessIncomplete(t *testing.T) {
	d := &Doc{Author: "a", Tool: "t", Timestamp: "x", Context: "pre-build", Edges: [][2]string{{"r", "a"}},
		Components: []Comp{{PURL: "pkg:npm/a@1", Name: "a", Version: "1", Supplier: "s", Licenses: []string{"MIT"}, Hashes: map[string][]string{"SHA-1": {"x"}}}}}
	if c := d.Assess(); c.Score != 1 || c.Elements["dependency_relationships"] != 1 {
		t.Errorf("complete SBOM: %+v", c)
	}
	d.Incomplete = []string{"lockfile out of sync"}
	c := d.Assess()
	if c.Elements["dependency_relationships"] != 0 || c.Score >= 1 {
		t.Errorf("incomplete SBOM: %+v", c)
	}
}

// A package needed only by an extra of a Python project is installed on
// request: CycloneDX scope "optional", SPDX OPTIONAL_DEPENDENCY_OF, and the
// scope "extra" again when the documents are read back; it is not production.
func TestExtraScopeInSBOM(t *testing.T) {
	root := model.NewComponent(model.PyPI, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := g.AddNode(model.NewComponent(model.PyPI, "", "requests", "2.31.0"))
	x := g.AddNode(model.NewComponent(model.PyPI, "", "pysocks", "1.7.1"))
	x.Scope = model.ScopeExtra
	g.AddEdge(model.Edge{From: root.PURL, To: a.PURL, Scope: model.ScopeRuntime})
	g.AddEdge(model.Edge{From: root.PURL, To: x.PURL, Scope: model.ScopeExtra})
	if model.ScopeExtra.Production() {
		t.Fatal("extra must not be a production scope")
	}
	doc := FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	cdx, _ := doc.CycloneDX("app", "1.0.0")
	if !strings.Contains(string(cdx), `"scope": "optional"`) && !strings.Contains(string(cdx), `"scope":"optional"`) {
		t.Errorf("CycloneDX: no optional scope:\n%s", cdx)
	}
	spdx, _ := doc.SPDX("app")
	if strings.Count(string(spdx), "OPTIONAL_DEPENDENCY_OF") != 1 {
		t.Errorf("SPDX: want one OPTIONAL_DEPENDENCY_OF")
	}
	dir := t.TempDir()
	for name, b := range map[string][]byte{"c.json": cdx, "s.json": spdx} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		back, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range back.Components {
			want := model.ScopeRuntime
			if c.Name == "pysocks" {
				want = model.ScopeExtra
			}
			if c.Scope.Production() != (want == model.ScopeRuntime) || c.Name == "pysocks" && c.Scope != model.ScopeExtra {
				t.Errorf("%s read back: %s has scope %q", name, c.Name, c.Scope)
			}
		}
	}
}
