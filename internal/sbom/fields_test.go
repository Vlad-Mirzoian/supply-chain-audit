package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func fieldsDoc() (*model.Graph, *Doc) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := model.NewComponent(model.NPM, "@s", "a", "1.0.0")
	a.Resolved = "https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz"
	a.Meta = &model.PackageMeta{Supplier: "Ann", Repository: "github.com/s/a"}
	g.AddNode(a)
	m := model.NewComponent(model.Maven, "org.x", "lib", "2.0")
	g.AddNode(m)
	e := model.NewComponent(model.Maven, "org.y", "enriched", "3.0")
	e.Meta = &model.PackageMeta{Supplier: "Org Y", SupplierOrg: true, RepoSHA1: "abcd"}
	g.AddNode(e)
	g.AddEdge(model.Edge{From: root.PURL, To: a.PURL, Scope: model.ScopeRuntime})
	g.AddEdge(model.Edge{From: root.PURL, To: m.PURL, Scope: model.ScopeRuntime})
	return g, FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
}

// The supplier is what the metadata declares: a repository or a groupId is
// not a producer. A Maven checksum from the repository fills the hash.
func TestSupplierAndRepositoryHash(t *testing.T) {
	_, d := fieldsDoc()
	want := map[string]string{"@s/a": "Ann", "org.x:lib": "", "org.y:enriched": "Org Y"}
	for _, c := range d.Components {
		if c.Supplier != want[c.Name] {
			t.Errorf("%s: supplier %q, want %q", c.Name, c.Supplier, want[c.Name])
		}
		if c.Name == "org.y:enriched" && !slices.Equal(c.Hashes["SHA-1"], []string{"abcd"}) {
			t.Errorf("repository hash lost: %v", c.Hashes)
		}
	}
	spdx, err := d.SPDX("app")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"Person: Ann"`, `"Organization: Org Y"`} {
		if !strings.Contains(string(spdx), s) {
			t.Errorf("SPDX has no %s", s)
		}
	}
}

// CycloneDX keeps the scope or groupId in "group"; on reading the full name
// comes back, and the identity of the component (purl) does not change.
func TestGroupAndDownload(t *testing.T) {
	_, d := fieldsDoc()
	cdx, err := d.CycloneDX("app", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	var x struct {
		Components []struct {
			Group, Name, PURL  string
			ExternalReferences []struct{ Type, URL string } `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdx, &x); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range x.Components {
		switch c.Name {
		case "a":
			seen++
			if c.Group != "@s" || len(c.ExternalReferences) != 1 || c.ExternalReferences[0].Type != "distribution" {
				t.Errorf("npm component: %+v", c)
			}
		case "lib":
			seen++
			if c.Group != "org.x" || len(c.ExternalReferences) != 0 {
				t.Errorf("Maven component: %+v", c)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("components %+v", x.Components)
	}
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, cdx, 0o644)
	back, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range back.Components {
		names[c.Name] = true
	}
	if !names["@s/a"] || !names["org.x:lib"] {
		t.Errorf("names read back: %v", names)
	}
	spdx, _ := d.SPDX("app")
	if !strings.Contains(string(spdx), `"downloadLocation": "https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz"`) {
		t.Errorf("SPDX has no download location")
	}
}

func TestDownloadLocation(t *testing.T) {
	for resolved, want := range map[string]string{
		"https://r.example/a.tgz":                 "https://r.example/a.tgz",
		"git+https://github.com/x/b.git#0123456":  "git+https://github.com/x/b.git#0123456",
		"https://user:token@r.example/a.tgz":      "",
		"git+ssh://git@github.com/x/b.git#012345": "",
		"file:../local":                           "",
		"":                                        "",
	} {
		c := model.NewComponent(model.NPM, "", "a", "1")
		c.Resolved = resolved
		if got := downloadLocation(c); got != want {
			t.Errorf("%q: %q, want %q", resolved, got, want)
		}
	}
	c := model.NewComponent(model.PyPI, "", "a", "1")
	c.Resolved = "https://download.pytorch.org/whl/cpu" // an index, not the package
	if got := downloadLocation(c); got != "" {
		t.Errorf("PyPI index taken for a download location: %q", got)
	}
}

// A Python release has one file per platform: all their hashes are kept,
// written in both formats and read back, and two SBOMs that share a file are
// not a hash mismatch.
func TestSeveralFilesOfOneRelease(t *testing.T) {
	root := model.NewComponent(model.PyPI, "", "app", "1.0.0")
	g := model.NewGraph(root)
	a := model.NewComponent(model.PyPI, "", "a", "1.0.0")
	a.Integrity = []string{"sha256:CC", "sha256:AA", "sha256:BB", "sha256:AA"}
	g.AddNode(a)
	g.AddEdge(model.Edge{From: root.PURL, To: a.PURL, Scope: model.ScopeRuntime})
	d := FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if got := d.Components[0].Hashes["SHA-256"]; !slices.Equal(got, []string{"aa", "bb", "cc"}) {
		t.Fatalf("hashes %v", got)
	}
	cdx, _ := d.CycloneDX("app", "1.0.0")
	spdx, _ := d.SPDX("app")
	dir := t.TempDir()
	for name, b := range map[string][]byte{"c.json": cdx, "s.json": spdx} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		back, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, vs := range back.Components[0].Hashes {
			n += len(vs)
		}
		if n != 3 {
			t.Errorf("%s read back: %v", name, back.Components[0].Hashes)
		}
	}
}

// An SPDX document of ssca states its generation context in the creation
// comment (SPDX 2.3 has no field for it), also next to the reasons of an
// incomplete analysis, and reading it back gives both: the SPDX SBOM meets
// the generation-context element as the CycloneDX one does.
func TestSPDXGenerationContext(t *testing.T) {
	g, d := fieldsDoc()
	dir := t.TempDir()
	for _, inc := range [][]string{nil, {"registry unavailable", "lockfile out of sync"}} {
		g.Incomplete = inc
		d = FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
		b, err := d.SPDX("app")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "s.spdx.json")
		os.WriteFile(p, b, 0o644)
		back, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		if back.Context != "pre-build" || back.Assess().Elements["generation_context"] != 1 {
			t.Errorf("incomplete %v: context %q read back from %s", inc, back.Context, b)
		}
		if !slices.Equal(back.Incomplete, inc) && !(len(inc) == 0 && len(back.Incomplete) == 0) {
			t.Errorf("incomplete reasons %v read back as %v", inc, back.Incomplete)
		}
	}
}

// Without lockfile hashes the SBOM records the SHA-256 that PyPI publishes for
// the files of the release; lockfile hashes take precedence.
func TestPyPIRegistryHashes(t *testing.T) {
	root := model.NewComponent(model.PyPI, "", "app", "1.0")
	g := model.NewGraph(root)
	free := model.NewComponent(model.PyPI, "", "free", "2.0")
	free.Meta = &model.PackageMeta{RepoSHA256: []string{"bb", "aa"}}
	locked := model.NewComponent(model.PyPI, "", "locked", "3.0")
	locked.Integrity = []string{"sha256:" + strings.Repeat("c", 64)}
	locked.Meta = &model.PackageMeta{RepoSHA256: []string{"dd"}}
	g.AddNode(free)
	g.AddNode(locked)
	d := FromGraph(g, "test", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	for _, c := range d.Components {
		switch c.Name {
		case "free":
			if !slices.Equal(c.Hashes["SHA-256"], []string{"aa", "bb"}) {
				t.Errorf("registry hashes: %v", c.Hashes)
			}
		case "locked":
			if slices.Contains(c.Hashes["SHA-256"], "dd") || len(c.Hashes["SHA-256"]) != 1 {
				t.Errorf("lockfile hash replaced by the registry: %v", c.Hashes)
			}
		}
	}
}
