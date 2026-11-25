package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
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
		{[]string{"graph", "--include-dev", empty}, exitUsage}, // --include-dev is a flag of scan only
		{[]string{"sbom", "--include-dev", empty}, exitUsage},
		{[]string{"verify-artifact", "--ecosystem", "npm", "x.tgz"}, exitUsage}, // no project flags
		{[]string{"sbom", "--enrich", "--no-enrich", empty}, exitUsage},
		{[]string{"sbom", "--no-enrich", "--validate", "x.json"}, exitUsage},
		{[]string{"diff", "-h"}, exitOK},
		{[]string{"verify-artifact", "-h"}, exitOK},
		{[]string{"typosquat", "lodash"}, exitOK},
		{[]string{"typosquat", "lodahs"}, exitViolation},
		{[]string{"typosquat", ""}, exitUsage},
		{[]string{"scan", "--offline", filepath.Join(empty, "missing")}, exitUsage},
		{[]string{"scan", "--offline", "--ecosystem", "cargo", empty}, exitUsage},
		// a directory without any project file is a wrong target, as a
		// missing one
		{[]string{"scan", "--offline", empty}, exitUsage},
		{[]string{"graph", "--offline", "--cache", empty, empty}, exitUsage},
		{[]string{"sbom", "--offline", "--cache", empty, "--out", t.TempDir(), empty}, exitUsage},
		// a flag after the arguments would be ignored (scan, graph, sbom,
		// ci-audit) or taken for an argument (typosquat, diff)
		{[]string{"scan", empty, "--offline"}, exitUsage},
		{[]string{"graph", filepath.Join("..", "..", "testdata", "npm-v3"), "--json"}, exitUsage},
		{[]string{"sbom", empty, "--no-enrich"}, exitUsage},
		{[]string{"ci-audit", empty, "--json"}, exitUsage},
		{[]string{"typosquat", "requets", "--ecosystem", "pypi"}, exitUsage},
		{[]string{"diff", "a.json", "b.json", "--json"}, exitUsage},
		{[]string{"cache", "seal", "--json"}, exitUsage},
		// one project directory only
		{[]string{"scan", "--offline", empty, empty}, exitUsage},
		{[]string{"ci-audit", empty, empty}, exitUsage},
		{[]string{"typosquat", "--top", "-1", "lodash"}, exitUsage},
		// --tree and --depth have no JSON form
		{[]string{"graph", "--offline", "--cache", empty, "--json", "--tree", filepath.Join("..", "..", "testdata", "npm-v3")}, exitUsage},
		{[]string{"graph", "--offline", "--cache", empty, "--json", "--depth", "2", filepath.Join("..", "..", "testdata", "npm-v3")}, exitUsage},
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
	if got := run([]string{"scan", "--offline", "--quiet", "--policy", "builtin", "--out", t.TempDir(), dir}); got != exitUsage {
		t.Errorf("--policy builtin: exit %d, want %d (no manifest)", got, exitUsage)
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
		// flags of SBOM generation and a project directory are not silently
		// ignored by --validate, nor --json without it
		{[]string{"sbom", "--validate", good, t.TempDir()}, exitUsage},
		{[]string{"sbom", "--out", t.TempDir(), "--validate", good}, exitUsage},
		{[]string{"sbom", "--runtime-only", "--validate", good}, exitUsage},
		{[]string{"sbom", "--json", t.TempDir()}, exitUsage},
		{[]string{"sbom", "--min-score", "80", t.TempDir()}, exitUsage},
		// diff: an SBOM that states that it is incomplete is no pass, but a
		// high or critical change still blocks
		{[]string{"diff", good, good}, exitOK},
		{[]string{"diff", good, incomplete}, exitIncomplete},
		{[]string{"diff", "--json", incomplete, good}, exitIncomplete},
		{[]string{"diff", "--mode", "declared-vs-observed", low, incomplete}, exitIncomplete},
		{[]string{"diff", "--mode", "declared-vs-observed", empty, incomplete}, exitViolation},
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

// sbom, graph and scan warn when the npm or PyPI dependencies come without a
// lockfile: their hashes are not pinned and the versions not pinned exactly
// are resolved at the run. A lockfile, or a requirements file that pins every
// hash, gives no warning; Maven, which has no lockfile, gives none either.
func TestUnlockedWarnings(t *testing.T) {
	mk := func(inputs []string, comps ...*model.Component) *model.Graph {
		g := model.NewGraph(model.NewComponent(model.PyPI, "", "app", "1.0"))
		g.Inputs = inputs
		for _, c := range comps {
			g.AddNode(c)
		}
		return g
	}
	py := model.NewComponent(model.PyPI, "", "requests", "2.32.0")
	pinned := model.NewComponent(model.PyPI, "", "idna", "3.10")
	pinned.Integrity = []string{"sha256:" + strings.Repeat("a", 64)}
	mvn := model.NewComponent(model.Maven, "org.x", "lib", "1.0")
	warn := func(g *model.Graph) []string {
		return unlockedWarnings(g.Inputs, g.Components(), ", and the SBOM can only record registry hashes")
	}
	if w := warn(mk([]string{"requirements.txt"}, py, pinned)); len(w) != 1 ||
		!strings.Contains(w[0], "no lockfile for the PyPI dependencies: 1 package version is not pinned with a hash") || !strings.Contains(w[0], "pip-compile --generate-hashes") ||
		!strings.Contains(w[0], "differ from what an installation gets, and the SBOM can only record registry hashes;") {
		t.Errorf("requirements without hashes: %v", w)
	}
	for name, g := range map[string]*model.Graph{
		"uv.lock":       mk([]string{"pyproject.toml", "sub/uv.lock"}, py),
		"pinned hashes": mk([]string{"requirements.txt"}, pinned),
		"maven":         mk([]string{"pom.xml"}, mvn),
	} {
		if w := warn(g); len(w) != 0 {
			t.Errorf("%s: unexpected warning %v", name, w)
		}
	}
}

// stdout runs the command line and returns its exit code and standard output.
func stdout(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	code := run(args)
	w.Close()
	os.Stdout = old
	return code, string(<-done)
}

// The SBOMs of scan name the root as the sbom command does: a scoped npm
// package keeps its scope (it was named after the last segment of its purl).
func TestScanSBOMRootName(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"@acme/orders","version":"2.0.0"}`), 0o644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"@acme/orders","version":"2.0.0","lockfileVersion":3,"packages":{"":{"name":"@acme/orders","version":"2.0.0"}}}`), 0o644)
	run([]string{"scan", "--offline", "--cache", t.TempDir(), "--quiet", "--no-metadata", "--provenance=false", "--out", out, dir})
	var cdx struct {
		Metadata struct {
			Component struct{ Name, Version string }
		}
	}
	var spdx struct{ Name string }
	b, _ := os.ReadFile(filepath.Join(out, "sbom.cdx.json"))
	json.Unmarshal(b, &cdx)
	b, _ = os.ReadFile(filepath.Join(out, "sbom.spdx.json"))
	json.Unmarshal(b, &spdx)
	if c := cdx.Metadata.Component; c.Name != "@acme/orders" || c.Version != "2.0.0" || spdx.Name != "@acme/orders" {
		t.Errorf("root of the scan SBOMs: CycloneDX %+v, SPDX %q", c, spdx.Name)
	}
}

// graph --json gives empty lists, not null, for a graph without
// components, cycles, conflicts or incomplete reasons.
func TestGraphJSONEmptyLists(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"}}}`), 0o644)
	code, out := stdout(t, "graph", "--offline", "--cache", t.TempDir(), "--json", dir)
	var g map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &g); code != exitOK || err != nil {
		t.Fatalf("exit %d, %v: %s", code, err, out)
	}
	for _, k := range []string{"components", "cycles", "conflicts", "incomplete"} {
		if string(g[k]) != "[]" {
			t.Errorf("%s: %s, want []", k, g[k])
		}
	}
}

// cache --json names the reason of exit code 4 (a damaged seal manifest).
func TestCacheJSONSealError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, netx.SealFile), []byte("{"), 0o644)
	code, out := stdout(t, "cache", "--cache", dir, "--json")
	if code != exitSelfCheck || !strings.Contains(out, `"seal_error"`) {
		t.Errorf("exit %d, want %d with seal_error: %s", code, exitSelfCheck, out)
	}
}
