package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

// ssca --version is the version command, not an unknown command.
func TestVersionFlag(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version"} {
		code, out := stdout(t, arg)
		if code != exitOK || out != "ssca "+Version+"\n" {
			t.Errorf("ssca %s: exit %d, output %q", arg, code, out)
		}
	}
}

// sbom --now fixes the creation time, so that the same project and data
// give byte-identical SBOMs (serial number and SPDX namespace included).
func TestSBOMNowIsDeterministic(t *testing.T) {
	proj := filepath.Join("..", "..", "testdata", "npm-v3")
	cache := t.TempDir()
	var files [2][2][]byte
	for i := range files {
		out := t.TempDir()
		if code := run([]string{"sbom", "--offline", "--cache", cache, "--now", "2026-11-25T00:00:00Z", "--out", out, proj}); code != exitOK {
			t.Fatalf("sbom: exit %d", code)
		}
		for j, f := range []string{"sbom.cdx.json", "sbom.spdx.json"} {
			b, err := os.ReadFile(filepath.Join(out, f))
			if err != nil {
				t.Fatal(err)
			}
			files[i][j] = b
		}
	}
	for j, f := range []string{"sbom.cdx.json", "sbom.spdx.json"} {
		if !bytes.Equal(files[0][j], files[1][j]) {
			t.Errorf("%s differs between two runs with the same --now", f)
		}
		if !bytes.Contains(files[0][j], []byte(`"2026-11-25T00:00:00Z"`)) {
			t.Errorf("%s does not carry the --now time", f)
		}
	}
	for _, args := range [][]string{
		{"sbom", "--now", "yesterday", proj},
		{"sbom", "--now", "2026-11-25T00:00:00Z", "--validate", "x.json"},
	} {
		if code := run(args); code != exitUsage {
			t.Errorf("ssca %v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

// ci-audit --json and --sarif keep the exit code of the text output; SARIF
// gives every finding its own fingerprint and turns the reasons of an
// incomplete audit into tool execution notifications.
func TestCIAuditJSONAndSARIF(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	os.MkdirAll(wf, 0o755)
	os.WriteFile(filepath.Join(wf, "ci.yml"), []byte("on: push\npermissions: {}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"+
		"      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n"), 0o644)
	code, out := stdout(t, "ci-audit", "--json", dir)
	var j struct {
		Files      []string
		Findings   []struct{ Rule, File string }
		Incomplete []string
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || code != exitOK {
		t.Fatalf("--json: exit %d, %v: %s", code, err, out)
	}
	if len(j.Files) != 1 || j.Files[0] != ".github/workflows/ci.yml" || len(j.Findings) != 2 || j.Incomplete == nil {
		t.Errorf("--json: %+v", j)
	}
	code, out = stdout(t, "ci-audit", "--sarif", dir)
	var s struct {
		Runs []struct {
			Results []struct {
				RuleID       string            `json:"ruleId"`
				Fingerprints map[string]string `json:"partialFingerprints"`
				Locations    []struct {
					Physical struct {
						Artifact struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				}
			}
			Invocations []struct {
				Success bool `json:"executionSuccessful"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil || code != exitOK || len(s.Runs) != 1 {
		t.Fatalf("--sarif: exit %d, %v: %s", code, err, out)
	}
	res := s.Runs[0].Results
	if len(res) != 2 || res[0].RuleID != "ssca/unpinned-action" || res[0].Locations[0].Physical.Artifact.URI != ".github/workflows/ci.yml" ||
		res[0].Fingerprints["ssca/v1"] == res[1].Fingerprints["ssca/v1"] || s.Runs[0].Invocations != nil {
		t.Errorf("--sarif: %+v", s.Runs[0])
	}
	os.WriteFile(filepath.Join(wf, "bad.yml"), []byte("on: [push\n"), 0o644)
	code, out = stdout(t, "ci-audit", "--sarif", dir)
	if json.Unmarshal([]byte(out), &s); code != exitIncomplete || len(s.Runs[0].Invocations) != 1 || s.Runs[0].Invocations[0].Success ||
		!strings.Contains(out, "bad.yml") {
		t.Errorf("--sarif of an incomplete audit: exit %d: %s", code, out)
	}
	empty := t.TempDir()
	if code, out := stdout(t, "ci-audit", "--json", empty); code != exitOK || !strings.Contains(out, `"files": []`) || !strings.Contains(out, `"findings": []`) {
		t.Errorf("--json without CI files: exit %d: %s", code, out)
	}
	if code := run([]string{"ci-audit", "--json", "--sarif", empty}); code != exitUsage {
		t.Errorf("--json --sarif: exit %d, want %d", code, exitUsage)
	}
}

// registryMock serves deps.dev, the npm registry and the npm downloads API
// for the release-history checks of diff and typosquat; it counts requests.
func registryMock(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	history := func(years ...int) string {
		var v []string
		for i, y := range years {
			v = append(v, fmt.Sprintf(`{"versionKey":{"version":"1.%d.0"},"publishedAt":"%d-06-01T00:00:00Z"}`, i, y))
		}
		return `{"versions":[` + strings.Join(v, ",") + `]}`
	}
	deps := map[string]string{"old-pkg": history(2019, 2020, 2021), "lodahs": history(2015, 2016, 2017, 2018, 2019, 2020)}
	young := `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}},"time":{"created":"2026-11-20T10:00:00Z","1.0.0":"2026-11-20T10:00:00Z"}}`
	packuments := map[string]string{
		"plain-crypto-js": `{"time":{"created":"2026-03-30T12:00:00Z","4.2.1":"2026-03-30T12:00:00Z"}}`,
		"loadsh":          young, "lodsah": young,
		"lodash": `{"dist-tags":{"latest":"4.17.21"},"versions":{"4.17.21":{}},"time":{"4.17.21":"2021-02-20T00:00:00Z"}}`,
	}
	versions := map[string]string{
		"loadsh/1.0.0": `{"maintainers":[{"name":"evil"}]}`, "lodsah/1.0.0": `{"maintainers":[{"name":"JDalton"}]}`,
		"lodash/4.17.21": `{"maintainers":[{"name":"jdalton"}]}`,
	}
	downloads := map[string]string{"loadsh": "10", "lodsah": "10", "lodash": "100000000"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		p := r.URL.Path
		name := p[strings.LastIndex(p, "/")+1:]
		var body string
		switch {
		case strings.HasSuffix(name, "broken-pkg") || strings.HasSuffix(name, "expresss"):
			w.WriteHeader(http.StatusForbidden)
			return
		case strings.HasPrefix(p, "/v3/systems/npm/packages/"):
			body = deps[name]
		case strings.HasPrefix(p, "/downloads/"):
			if d, ok := downloads[name]; ok {
				body = `{"downloads":` + d + `}`
			}
		case strings.HasPrefix(p, "/npm/"):
			rest := strings.TrimPrefix(p, "/npm/")
			if strings.Contains(rest, "/") {
				body = versions[rest]
			} else {
				body = packuments[rest]
			}
		}
		if body == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	oldDD, oldReg, oldDL := risk.DepsDev, npm.Registry, npm.DownloadsAPI
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/v3", srv.URL+"/npm", srv.URL+"/downloads/"
	t.Cleanup(func() { risk.DepsDev, npm.Registry, npm.DownloadsAPI = oldDD, oldReg, oldDL })
	return &n
}

// cdx writes a minimal CycloneDX SBOM with the given creation time and npm
// packages ("name@version").
func cdx(t *testing.T, ts string, pkgs ...string) string {
	t.Helper()
	var comps []string
	for _, p := range pkgs {
		name, ver, _ := strings.Cut(p, "@")
		comps = append(comps, fmt.Sprintf(`{"bom-ref":"pkg:npm/%[1]s@%[2]s","name":"%[1]s","version":"%[2]s","purl":"pkg:npm/%[1]s@%[2]s"}`, name, ver))
	}
	f := filepath.Join(t.TempDir(), "sbom.cdx.json")
	os.WriteFile(f, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"`+ts+
		`","component":{"bom-ref":"pkg:npm/app@1.0.0","purl":"pkg:npm/app@1.0.0"}},"components":[`+strings.Join(comps, ",")+`]}`), 0o644)
	return f
}

// diff --mode release-vs-release rates a package that is added in the new
// release and first published less than 7 days before it as high (Table
// 3.16), with the release history from deps.dev or, for a package that
// deps.dev does not know yet, from the registry. An unknown age is an
// incomplete result; other modes read no release history.
func TestDiffYoungPackage(t *testing.T) {
	reqs := registryMock(t)
	cache := t.TempDir()
	a := cdx(t, "2026-03-20T00:00:00Z", "lodash@4.17.21")
	b := cdx(t, "2026-03-31T00:00:00Z", "lodash@4.17.21", "plain-crypto-js@4.2.1", "old-pkg@1.2.0")
	code, out := stdout(t, "diff", "--cache", cache, "--mode", "release-vs-release", "--json", a, b)
	var res struct {
		Changes    []struct{ Class, Key, Severity, Detail string }
		UnknownAge []string `json:"unknown_age"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != exitViolation {
		t.Fatalf("exit %d, %v: %s", code, err, out)
	}
	got := map[string]string{}
	for _, c := range res.Changes {
		got[c.Key] = c.Severity + " " + c.Detail
	}
	if got["npm/plain-crypto-js"] != "high young" || got["npm/old-pkg"] != "medium " || res.UnknownAge != nil {
		t.Errorf("changes %v, unknown age %v", got, res.UnknownAge)
	}
	// the text output explains the mark
	if _, out := stdout(t, "diff", "--cache", cache, "--mode", "release-vs-release", a, b); !strings.Contains(out, "(young: the first release of the package is less than 7 days before 2026-03-31 00:00 UTC)") {
		t.Errorf("text output:\n%s", out)
	}
	// judged a month later (--now), the package is no longer young
	if code := run([]string{"diff", "--cache", cache, "--mode", "release-vs-release", "--now", "2026-05-01T00:00:00Z", a, b}); code != exitOK {
		t.Errorf("--now a month later: exit %d, want 0", code)
	}
	c := cdx(t, "2026-03-31T00:00:00Z", "lodash@4.17.21", "broken-pkg@1.0.0")
	code, out = stdout(t, "diff", "--cache", cache, "--mode", "release-vs-release", "--json", a, c)
	if code != exitIncomplete || !strings.Contains(out, `"unknown_age"`) || !strings.Contains(out, "npm/broken-pkg") {
		t.Errorf("unknown age: exit %d: %s", code, out)
	}
	before := reqs.Load()
	run([]string{"diff", "--cache", t.TempDir(), a, b})
	if reqs.Load() != before {
		t.Errorf("declared-vs-observed read release history (%d requests)", reqs.Load()-before)
	}
}

// typosquat confirms a name match as scan does: an established package is
// not a typosquat, and an npm candidate that shares a maintainer with its
// target or has comparable downloads is a companion package; a match that
// cannot be confirmed stays suspect. --names-only reads no registry data.
func TestTyposquatConfirmsMatches(t *testing.T) {
	reqs := registryMock(t)
	code, out := stdout(t, "typosquat", "--cache", t.TempDir(), "--now", "2026-11-26T00:00:00Z", "lodahs", "loadsh", "lodsah", "expres", "expresss", "react")
	for _, want := range []string{
		"  lodahs    ok: like lodash (0.92, edit distance), but established package: first release 2015-06-01, 6 releases over 5.0 years\n",
		"  loadsh    suspect: lodash (0.92, edit distance)\n",
		"  lodsah    ok: like lodash (0.92, edit distance), but shares the maintainer JDalton with lodash\n",
		"  expres    suspect: express (0.86, edit distance), espree (0.83, edit distance) (not in the npm registry)\n",
		"  expresss  suspect: express (0.88, edit distance) (release history unavailable: ",
		"  react     ok\n", "3 of 6 names look like popular packages\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if code != exitViolation {
		t.Errorf("exit %d, want %d", code, exitViolation)
	}
	before := reqs.Load()
	if code := run([]string{"typosquat", "--names-only", "lodahs"}); code != exitViolation || reqs.Load() != before {
		t.Errorf("--names-only: exit %d, %d requests", code, reqs.Load()-before)
	}
	if code := run([]string{"typosquat", "--names-only", "--offline", "lodahs"}); code != exitUsage {
		t.Errorf("--names-only --offline: exit %d, want %d", code, exitUsage)
	}
}
