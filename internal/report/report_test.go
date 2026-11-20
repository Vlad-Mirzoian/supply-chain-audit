package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/integrity"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// The evidence bundle must cover every file in the output directory: files of
// an earlier run are removed, the HTML report is hashed like the others, and
// the manifest records the evaluation time of reproducible runs.
func TestEvidenceRemovesStaleFiles(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "reachability.openvex.json")
	if err := os.WriteFile(stale, []byte(`{"statements":["old"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "notes.txt") // not an ssca output: must be kept
	if err := os.WriteFile(other, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Report{Tool: "ssca", Version: "test"}
	created := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if err := r.Evidence(dir, map[string][]byte{"sbom.cdx.json": []byte("{}")}, created); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale VEX document of an earlier run was kept")
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("unrelated file was removed: %v", err)
	}
	var m struct {
		Created string            `json:"created"`
		Files   map[string]string `json:"files"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Created != "2026-10-28T12:00:00Z" {
		t.Errorf("created %q", m.Created)
	}
	entries, _ := os.ReadDir(dir)
	var outputs []string
	for _, e := range entries {
		if n := e.Name(); n != "manifest.json" && n != "notes.txt" {
			outputs = append(outputs, n)
		}
	}
	var hashed []string
	for n := range m.Files {
		hashed = append(hashed, n)
	}
	sort.Strings(hashed)
	if strings.Join(outputs, ",") != strings.Join(hashed, ",") {
		t.Errorf("manifest covers %v, directory holds %v", hashed, outputs)
	}
	for n, h := range m.Files {
		data, _ := os.ReadFile(filepath.Join(dir, n))
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != h {
			t.Errorf("hash of %s does not match", n)
		}
	}
}

// SARIF results of components point at the package's entry in the lockfile
// of its own ecosystem, not at line 1 of the first input.
func TestSARIFLocations(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"package-lock.json": `{
  "packages": {
    "": {
      "dependencies": {"ejs": "3.1.6"}
    },
    "node_modules/ejs": {
      "version": "3.1.6"
    },
    "node_modules/@acme/core": {
      "version": "1.0.0"
    }
  }
}`,
		"poetry.lock": `[[package]]
name = "flask"
version = "2.0.0"

[[package]]
name = "typing-extensions"
version = "4.0.0"
`,
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ejs := model.NewComponent(model.NPM, "", "ejs", "3.1.6")
	core := model.NewComponent(model.NPM, "@acme", "core", "1.0.0")
	flask := model.NewComponent(model.PyPI, "", "flask", "2.0.0")
	te := model.NewComponent(model.PyPI, "", "typing_extensions", "4.0.0")
	missing := model.NewComponent(model.PyPI, "", "absent", "1.0")
	r := &Report{
		Project:    Project{Dir: dir, Inputs: []string{"package-lock.json", "poetry.lock"}},
		Components: []*model.Component{ejs, core, flask, te, missing},
	}
	// a run without findings has empty arrays, not null (SARIF 2.1.0 schema)
	if empty, err := r.SARIF(); err != nil || !strings.Contains(string(empty), `"results": []`) || !strings.Contains(string(empty), `"rules": []`) {
		t.Errorf("SARIF without findings: %v\n%s", err, empty)
	}
	for _, c := range r.Components {
		r.Findings = append(r.Findings, &model.Finding{ID: "X-" + c.Name, Kind: model.KindVulnerability,
			Component: c.PURL, Severity: model.SevHigh, Title: "t"})
	}
	b, err := r.SARIF()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"X-ejs": "package-lock.json:6", "X-core": "package-lock.json:9",
		"X-flask": "poetry.lock:2", "X-typing_extensions": "poetry.lock:6", "X-absent": "poetry.lock:1"}
	for _, res := range doc.Runs[0].Results {
		loc := res.Locations[0].Physical
		got := loc.Artifact.URI + ":" + strconv.Itoa(loc.Region.StartLine)
		if got != want[res.RuleID] {
			t.Errorf("%s located at %s, want %s", res.RuleID, got, want[res.RuleID])
		}
	}
}

// The summary must say how many lockfile hashes were compared with the
// registry and why the others were not, so that a project whose packages all
// come from another index does not look verified.
func TestHashSummary(t *testing.T) {
	r := &Report{HashCheck: map[string]int{"verified": 2, "other-source": 168, "no-lockfile-hash": 1}}
	want := "Lockfile hashes: 2 of 171 components verified against the registry; 168 not from the public registry, 1 no hash in the lockfile."
	if got := r.HashSummary(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if !strings.Contains(r.Markdown(), want) {
		t.Error("summary.md does not contain the hash summary")
	}
	if h, err := r.HTML(); err != nil || !strings.Contains(string(h), "2 of 171 components verified") {
		t.Errorf("report.html does not contain the hash summary (%v)", err)
	}
}

// A saved trusted root is named with its age in the readable reports and only
// when one was used.
func TestTrustedRootCopyInReports(t *testing.T) {
	r := &Report{}
	if strings.Contains(r.Markdown(), "trusted root") {
		t.Error("online report names a saved trusted root")
	}
	r.TrustedRootCopy = &integrity.RootCopy{Fetched: time.Date(2026, 11, 6, 2, 22, 0, 0, time.UTC), AgeDays: 3}
	const want = "saved copy fetched 2026-11-06, 3 days old"
	if md := r.Markdown(); !strings.Contains(md, want) {
		t.Errorf("Markdown: %s", md)
	}
	h, err := r.HTML()
	if err != nil || !strings.Contains(string(h), want) {
		t.Errorf("HTML (%v): %s", err, h)
	}
}
