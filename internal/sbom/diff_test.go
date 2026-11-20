package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doc(comps ...Comp) *Doc { return &Doc{Components: comps} }

func TestKeyNormalisation(t *testing.T) {
	cases := map[string]string{
		"pkg:pypi/Django_REST.framework@3.0":     "pypi/django-rest-framework",
		"pkg:npm/%40babel/core@7.0.0?foo=bar":    "npm/@babel/core",
		"pkg:maven/org.apache/log4j-core@2.14.1": "maven/org.apache/log4j-core",
	}
	for in, want := range cases {
		if got := Key(in); got != want {
			t.Errorf("Key(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestDiffClasses(t *testing.T) {
	a := doc(
		Comp{PURL: "pkg:npm/axios@1.14.0", Version: "1.14.0", Supplier: "github.com/axios/axios"},
		Comp{PURL: "pkg:npm/lodash@4.17.21", Version: "4.17.21", Hashes: map[string][]string{"SHA-512": {"aa"}}},
		Comp{PURL: "pkg:npm/left-pad@1.0.0", Version: "1.0.0"},
	)
	b := doc(
		Comp{PURL: "pkg:npm/axios@1.14.1", Version: "1.14.1"},
		Comp{PURL: "pkg:npm/lodash@4.17.21", Version: "4.17.21", Hashes: map[string][]string{"SHA-512": {"bb"}}},
		Comp{PURL: "pkg:npm/plain-crypto-js@4.2.1", Version: "4.2.1"},
	)
	b.Edges = [][2]string{{"pkg:npm/axios@1.14.1", "pkg:npm/plain-crypto-js@4.2.1"}}
	young := func(k string) bool { return k == "npm/plain-crypto-js" }
	r := Diff(a, b, ReleaseVsRelease, nil, young)
	got := map[string]string{}
	for _, c := range r.Changes {
		got[c.Class] = c.Severity
	}
	want := map[string]string{"ADDED": "high", "REMOVED": "info", "HASH_MISMATCH": "critical", "VERSION_CHANGED": "low", "EDGE_ADDED": "medium"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got severity %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	if r.Jaccard != 0.5 { // axios, lodash shared; left-pad, plain-crypto-js not
		t.Errorf("Jaccard = %v", r.Jaccard)
	}
	m1 := Diff(a, b, DeclaredVsObserved, nil, nil)
	if m1.Changes[0].Class != "MISSING" && m1.Changes[0].Class != "PHANTOM" && m1.Changes[0].Class != "VERSION_CHANGED" {
		t.Errorf("mode 1 classes not renamed: %v", m1.Changes)
	}
}

// The CycloneDX and SPDX documents of one scan describe the same inventory:
// the application itself is the subject of both (metadata.component and the
// DESCRIBES relationship), not a component that one of them adds.
func TestDiffCycloneDXvsSPDX(t *testing.T) {
	d := &Doc{Root: "pkg:npm/app@1.0.0", Tool: "ssca", Timestamp: "2026-10-28T00:00:00Z",
		Components: []Comp{{PURL: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21"}},
		Edges:      [][2]string{{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.21"}}}
	cdx, err := d.CycloneDX("app", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	spdx, err := d.SPDX("app")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.cdx.json"), cdx, 0o644)
	os.WriteFile(filepath.Join(dir, "a.spdx.json"), spdx, 0o644)
	a, err := Read(filepath.Join(dir, "a.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(filepath.Join(dir, "a.spdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if b.Root != d.Root || len(b.Components) != 1 {
		t.Fatalf("SPDX root %q, %d components", b.Root, len(b.Components))
	}
	if r := Diff(a, b, VendorVsGenerated, nil, nil); len(r.Changes) != 0 || r.Jaccard != 1 {
		t.Errorf("same inventory differs: %v (J=%v)", r.Changes, r.Jaccard)
	}
}

// With two versions of one package, a version that only disappears is a
// removal, and one that only appears is an addition, not a version change.
func TestDiffMultiVersion(t *testing.T) {
	a := doc(Comp{PURL: "pkg:npm/debug@2.6.9", Version: "2.6.9"}, Comp{PURL: "pkg:npm/debug@4.4.3", Version: "4.4.3"})
	b := doc(Comp{PURL: "pkg:npm/debug@2.6.9", Version: "2.6.9"})
	if r := Diff(a, b, DeclaredVsObserved, nil, nil); len(r.Changes) != 1 || r.Changes[0].Class != "MISSING" || r.Changes[0].From != "4.4.3" {
		t.Errorf("removed version: %v", r.Changes)
	}
	if r := Diff(b, a, ReleaseVsRelease, nil, nil); len(r.Changes) != 1 || r.Changes[0].Class != "ADDED" || r.Changes[0].To != "4.4.3" {
		t.Errorf("added version: %v", r.Changes)
	}
}

func hashDoc(values ...string) *Doc {
	return &Doc{Components: []Comp{{PURL: "pkg:pypi/a@1", Version: "1", Hashes: map[string][]string{"SHA-256": values}}}}
}

func TestHashMismatchComparesSets(t *testing.T) {
	mismatch := func(x, y *Doc) bool {
		for _, c := range Diff(x, y, ReleaseVsRelease, func(_, a, b string) int { return strings.Compare(a, b) }, nil).Changes {
			if c.Class == "HASH_MISMATCH" {
				return true
			}
		}
		return false
	}
	if mismatch(hashDoc("aa", "bb"), hashDoc("bb", "cc")) {
		t.Error("a shared file reported as a mismatch")
	}
	if !mismatch(hashDoc("aa", "bb"), hashDoc("cc")) {
		t.Error("disjoint hashes not reported")
	}
}
