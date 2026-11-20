package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
)

// Exit codes of Table 3.13 for the command line: help is not an error, usage
// errors give 3, and nothing that could not be checked ends with 0.
func TestExitCodes(t *testing.T) {
	empty := t.TempDir()
	broken := t.TempDir()
	wf := filepath.Join(broken, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(wf, "ci.yml"), []byte("on: [push\n"), 0o644)
	vex := filepath.Join(empty, "v.json")
	os.WriteFile(vex, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"X"},"status":"not_affected"}]}`), 0o644)
	// OpenVEX statements with a product but an unknown status or a
	// not_affected without justification
	vexStatus := filepath.Join(empty, "status.json")
	os.WriteFile(vexStatus, []byte(`{"statements":[{"vulnerability":{"name":"X"},"products":[{"@id":"pkg:npm/a@1"}],"status":"bogus_status"}]}`), 0o644)
	vexJust := filepath.Join(empty, "just.json")
	os.WriteFile(vexJust, []byte(`{"statements":[{"vulnerability":{"name":"X"},"products":[{"@id":"pkg:npm/a@1"}],"status":"not_affected"}]}`), 0o644)

	outOfSync := t.TempDir()
	os.WriteFile(filepath.Join(outOfSync, "package.json"), []byte(`{"name":"x","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`), 0o644)
	os.WriteFile(filepath.Join(outOfSync, "package-lock.json"), []byte(`{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}}}`), 0o644)

	cases := []struct {
		args []string
		want int
	}{
		{nil, exitUsage},
		{[]string{"--help"}, exitOK},
		{[]string{"-h"}, exitOK},
		{[]string{"bogus"}, exitUsage},
		{[]string{"scan", "-h"}, exitOK},
		{[]string{"scan", "--no-such-flag"}, exitUsage},
		{[]string{"ci-audit", "-h"}, exitOK},
		{[]string{"ci-audit", filepath.Join(empty, "missing")}, exitUsage},
		{[]string{"ci-audit", empty}, exitOK},
		{[]string{"ci-audit", broken}, exitIncomplete},
		{[]string{"scan", "--offline", "--vex", vex, empty}, exitUsage},
		{[]string{"scan", "--offline", "--vex", vexStatus, empty}, exitUsage},
		{[]string{"scan", "--offline", "--vex", vexJust, empty}, exitUsage},
		{[]string{"diff", "only-one.json"}, exitUsage},
		{[]string{"scan", "--include-dev", "--runtime-only", empty}, exitUsage},
		{[]string{"graph", "--include-dev", "--runtime-only", empty}, exitUsage},
		{[]string{"diff", "-h"}, exitOK},
		{[]string{"verify-artifact", "-h"}, exitOK},
		{[]string{"typosquat", "lodash"}, exitOK},
		{[]string{"typosquat", "lodahs"}, exitViolation},
		{[]string{"typosquat", ""}, exitUsage},
		{[]string{"scan", "--offline", filepath.Join(empty, "missing")}, exitUsage},
		{[]string{"scan", "--offline", "--ecosystem", "cargo", empty}, exitUsage},
		{[]string{"scan", "--offline", empty}, exitIncomplete},
		{[]string{"graph", "--offline", filepath.Join(empty, "missing")}, exitUsage},
		// a complete lockfile graph is 0, an out-of-sync lockfile 2
		{[]string{"graph", "--offline", "--cache", empty, filepath.Join("..", "..", "testdata", "npm-v3")}, exitOK},
		{[]string{"graph", "--offline", "--cache", empty, outOfSync}, exitIncomplete},
		{[]string{"graph", "--offline", "--json", "--cache", empty, outOfSync}, exitIncomplete},
		{[]string{"sbom", "--offline", filepath.Join(empty, "missing")}, exitUsage},
		// the SBOMs of an incomplete graph are written, but the exit code is 2
		{[]string{"sbom", "--offline", "--cache", empty, "--out", t.TempDir(), outOfSync}, exitIncomplete},
		{[]string{"sbom", "--offline", "--cache", empty, "--out", t.TempDir(), filepath.Join("..", "..", "testdata", "npm-v3")}, exitOK},
		{[]string{"typosquat"}, exitUsage},
		{[]string{"graph", "--offline", "--depth", "-1", empty}, exitUsage},
		{[]string{"typosquat", "--ecosystem", "maven", "guava"}, exitUsage},
		{[]string{"diff", "--mode", "bogus", "a.json", "b.json"}, exitUsage},
		{[]string{"verify-artifact", "--sha512", "zz", "x"}, exitUsage},
		{[]string{"verify-artifact", filepath.Join(empty, "missing.tgz")}, exitUsage},
	}
	for _, c := range cases {
		if got := run(c.args); got != c.want {
			t.Errorf("ssca %v: exit %d, want %d", c.args, got, c.want)
		}
	}
}

// scan picks up .ssca/policy.yaml of the project without --policy (a faulty
// one is a usage error), and --policy builtin ignores it.
func TestScanFindsProjectPolicy(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".ssca"), 0o755)
	os.WriteFile(filepath.Join(dir, ".ssca", "policy.yaml"), []byte("version: 1\ntreshholds: {}\n"), 0o644)
	if got := run([]string{"scan", "--offline", "--quiet", "--out", t.TempDir(), dir}); got != exitUsage {
		t.Errorf("faulty project policy: exit %d, want %d", got, exitUsage)
	}
	if got := run([]string{"scan", "--offline", "--quiet", "--policy", "builtin", "--out", t.TempDir(), dir}); got != exitIncomplete {
		t.Errorf("--policy builtin: exit %d, want %d (no manifest)", got, exitIncomplete)
	}
	info, err := policyInfo(dir, filepath.Join(dir, ".ssca", "policy.yaml"), true)
	if err != nil || info.Source != ".ssca/policy.yaml" || !info.Discovered || len(info.SHA256) != 64 {
		t.Errorf("policy info %+v, %v", info, err)
	}
	if info, _ := policyInfo(dir, "", false); info.Source != "built-in" || !strings.Contains(info.Describe(), "has no") {
		t.Errorf("built-in policy info %+v", info)
	}
	if d := (report.PolicyInfo{Source: "built-in", Forced: true}).Describe(); !strings.Contains(d, "--policy builtin") {
		t.Errorf("forced built-in policy: %q", d)
	}
}

// Only "not reachable" verdicts become not_affected statements; an unknown
// verdict (no source files of the application) must not.
func TestAutoVEXIgnoresUnknown(t *testing.T) {
	mk := func(reach string) *model.Finding {
		return &model.Finding{ID: "GHSA-x", Kind: model.KindVulnerability, Component: "pkg:npm/a@1.0.0",
			Vuln: &model.Vulnerability{ID: "GHSA-x", Reachable: reach}}
	}
	if b := autoVEX(&report.Report{Findings: []*model.Finding{mk("unknown"), mk("yes")}}, time.Now()); b != nil {
		t.Errorf("VEX for unknown/yes verdicts: %s", b)
	}
	if b := autoVEX(&report.Report{Findings: []*model.Finding{mk("no")}}, time.Now()); b == nil {
		t.Error("no VEX for a not-reachable verdict")
	}
}

// sbom --validate: a low score is a violation, an SBOM that states that it is
// incomplete is exit code 2 and an SBOM without components is not accepted.
func TestValidateExitCodes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const comp = `{"type":"library","bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1","supplier":{"name":"s"},"licenses":[{"license":{"id":"MIT"}}],"hashes":[{"alg":"SHA-512","content":"ab"}]}`
	const meta = `"specVersion":"1.6","metadata":{"timestamp":"t","authors":[{"name":"x"}],"tools":{},"lifecycles":[{"phase":"pre-build"}],"component":{"bom-ref":"r","purl":"pkg:npm/r@1"}`
	const deps = `"dependencies":[{"ref":"r","dependsOn":["a"]}]`
	good := write("good.json", `{"bomFormat":"CycloneDX",`+meta+`},"components":[`+comp+`],`+deps+`}`)
	// name and purl only: no version, producer, hash or licence, and no relationships
	low := write("low.json", `{"bomFormat":"CycloneDX",`+meta+`},"components":[{"bom-ref":"a","name":"a","purl":"pkg:npm/a@1"}]}`)
	incomplete := write("incomplete.json", `{"bomFormat":"CycloneDX",`+meta+`,"properties":[{"name":"ssca:incomplete","value":"lockfile out of sync"}]},"components":[`+comp+`],`+deps+`}`)
	empty := write("empty.json", `{"bomFormat":"CycloneDX",`+meta+`},"components":[],`+deps+`}`)
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"sbom", "--validate", good}, exitOK},
		{[]string{"sbom", "--json", "--validate", good}, exitOK},
		{[]string{"sbom", "--validate", low}, exitViolation},
		{[]string{"sbom", "--min-score", "10", "--validate", low}, exitOK},
		{[]string{"sbom", "--validate", incomplete}, exitIncomplete},
		{[]string{"sbom", "--min-score", "0", "--validate", incomplete}, exitIncomplete},
		{[]string{"sbom", "--validate", empty}, exitViolation},
		{[]string{"sbom", "--min-score", "101", "--validate", good}, exitUsage},
		{[]string{"sbom", "--min-score", "90", t.TempDir()}, exitUsage},
		{[]string{"sbom", "--validate", "--json", good}, exitUsage},
	}
	for _, c := range cases {
		if got := run(c.args); got != c.want {
			t.Errorf("ssca %v: exit %d, want %d", c.args, got, c.want)
		}
	}
}

// ssca cache needs an explicitly selected directory; a damaged entry means
// that the state is not fully known.
func TestCacheCommand(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSCA_CACHE", "")
	if got := run([]string{"cache"}); got != exitUsage {
		t.Errorf("no cache selected: exit %d, want %d", got, exitUsage)
	}
	if got := run([]string{"cache", "--cache", filepath.Join(dir, "missing")}); got != exitUsage {
		t.Errorf("missing directory: exit %d, want %d", got, exitUsage)
	}
	if got := run([]string{"cache", "--cache", dir, "extra"}); got != exitUsage {
		t.Errorf("extra argument: exit %d, want %d", got, exitUsage)
	}
	t.Setenv("SSCA_CACHE", dir)
	if got := run([]string{"cache"}); got != exitOK {
		t.Errorf("empty cache from SSCA_CACHE: exit %d, want %d", got, exitOK)
	}
	if got := run([]string{"cache", "--json"}); got != exitOK {
		t.Errorf("--json: exit %d, want %d", got, exitOK)
	}
	os.MkdirAll(filepath.Join(dir, "aa"), 0o755)
	os.WriteFile(filepath.Join(dir, "aa", "x.json"), []byte("not json"), 0o644)
	if got := run([]string{"cache"}); got != exitIncomplete {
		t.Errorf("damaged entry: exit %d, want %d", got, exitIncomplete)
	}
}
