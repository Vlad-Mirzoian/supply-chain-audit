package vuln

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/maven"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func TestAffectedBy(t *testing.T) {
	// log4j-core: introduced 2.0-beta9, fixed 2.15.0 (CVE-2021-44228)
	ev := []Event{{Introduced: "2.0-beta9"}, {Fixed: "2.15.0"}}
	for v, want := range map[string]bool{"2.14.1": true, "2.0-beta9": true, "2.15.0": false, "2.17.1": false, "1.2.17": false} {
		if got := AffectedBy(model.Maven, v, ev); got != want {
			t.Errorf("maven %s: got %v want %v", v, got, want)
		}
	}
	ev = []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}
	if !AffectedBy(model.NPM, "4.17.20", ev) || AffectedBy(model.NPM, "4.17.21", ev) {
		t.Error("npm range")
	}
	ev = []Event{{Introduced: "1.0"}, {LastAffected: "1.4.2"}}
	if !AffectedBy(model.PyPI, "1.4.2", ev) || AffectedBy(model.PyPI, "1.4.3", ev) {
		t.Error("last_affected")
	}
}

func TestVersionSemantics(t *testing.T) {
	if pypi.Compare("1.0rc1", "1.0") >= 0 || pypi.Compare("1.0.post1", "1.0") <= 0 {
		t.Error("PEP 440 ordering")
	}
	if !pypi.Satisfies("2.31.0", ">=2,<3") || pypi.Satisfies("3.0.0", ">=2,<3") {
		t.Error("PEP 440 specifiers")
	}
	if maven.Compare("2.0-beta9", "2.0") >= 0 || maven.Compare("1.10", "1.9") <= 0 {
		t.Error("Maven ordering")
	}
	if !maven.Satisfies("1.5", "[1.0,2.0)") || maven.Satisfies("2.0", "[1.0,2.0)") || !maven.Satisfies("3.1", "(,1.0],[3.0,)") {
		t.Error("Maven ranges")
	}
	if !npm.Satisfies("1.4.0", "^1.2.0") || npm.Satisfies("2.0.0", "^1.2.0") || !npm.Satisfies("1.2.9", "~1.2.0") ||
		!npm.Satisfies("1.5.0", ">=1.2.0 <2.0.0") || !npm.Satisfies("3.0.0", "^1.0.0 || ^3.0.0") {
		t.Error("npm ranges")
	}
}

func TestMarkers(t *testing.T) {
	cases := map[string]bool{
		`python_version >= "3.8"`:                                 true,
		`python_version < "3.8"`:                                  false,
		`sys_platform == "win32"`:                                 false,
		`extra == "socks"`:                                        false,
		`platform_system != "Windows" and python_version > "3.6"`: true,
		`(os_name == "nt" or sys_platform == "linux")`:            true,
	}
	for m, want := range cases {
		if got := pypi.EvalMarker(m, nil); got != want {
			t.Errorf("%s: got %v", m, got)
		}
	}
	if !pypi.EvalMarker(`extra == "socks"`, []string{"socks"}) {
		t.Error("extra not applied")
	}
}

func TestVEX(t *testing.T) {
	f := &model.Finding{ID: "GHSA-1", Kind: model.KindVulnerability, Component: "pkg:npm/x@1.0.0",
		Vuln: &model.Vulnerability{ID: "GHSA-1", Aliases: []string{"CVE-2026-1"}}}
	n := ApplyVEX([]*model.Finding{f}, []Statement{{Vulnerability: "CVE-2026-1", Products: []string{"pkg:npm/x@1.0.0"}, Status: "not_affected", Justification: "vulnerable_code_not_present"}})
	if n != 1 || !f.Suppressed || f.Vuln.VEXJustification != "vulnerable_code_not_present" {
		t.Fatalf("VEX not applied: %+v", f)
	}
}

func writeVEX(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vex.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func vulnFinding(comp, id, alias string) *model.Finding {
	return &model.Finding{ID: id, Kind: model.KindVulnerability, Component: comp,
		Vuln: &model.Vulnerability{ID: id, Aliases: []string{alias}}}
}

// OpenVEX: the product is the application and the vulnerable dependency is a
// subcomponent; only that subcomponent may be suppressed.
func TestOpenVEXSubcomponents(t *testing.T) {
	p := writeVEX(t, `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
	 {"vulnerability":{"name":"CVE-2022-29078"},"status":"not_affected","justification":"vulnerable_code_not_in_execute_path",
	  "products":[{"@id":"pkg:npm/app@1.0.0","subcomponents":[{"@id":"pkg:npm/ejs@3.1.6"}]}]},
	 {"vulnerability":{"name":"CVE-2026-2"},"status":"fixed",
	  "products":[{"@id":"urn:app","identifiers":{"purl":"pkg:npm/%40acme/lib"}}]}]}`)
	stmts, err := LoadVEX([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	ejs := vulnFinding("pkg:npm/ejs@3.1.6", "GHSA-phwq-j96m-2c2q", "CVE-2022-29078")
	other := vulnFinding("pkg:npm/ejs@3.1.5", "GHSA-phwq-j96m-2c2q", "CVE-2022-29078")
	scoped := vulnFinding("pkg:npm/%40acme/lib@2.0.0", "GHSA-2", "CVE-2026-2")
	unrelated := vulnFinding("pkg:npm/%40acme/lib-extra@2.0.0", "GHSA-3", "CVE-2026-2")
	if n := ApplyVEX([]*model.Finding{ejs, other, scoped, unrelated}, stmts); n != 2 {
		t.Errorf("suppressed %d findings, want 2", n)
	}
	if !ejs.Suppressed || ejs.Vuln.VEXJustification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("subcomponent statement not applied: %+v", ejs)
	}
	if other.Suppressed || unrelated.Suppressed {
		t.Error("statement applied to a component it does not name")
	}
	if !scoped.Suppressed {
		t.Error("version-less purl from identifiers.purl not applied")
	}
}

// A statement without a product would otherwise suppress the vulnerability in
// every component.
func TestVEXWithoutProductRejected(t *testing.T) {
	for _, doc := range []string{
		`{"statements":[{"vulnerability":{"name":"CVE-1"},"status":"not_affected","justification":"component_not_present"}]}`,
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected","justification":"code_not_present"}}]}`,
	} {
		if _, err := LoadVEX([]string{writeVEX(t, doc)}); err == nil {
			t.Errorf("accepted: %s", doc)
		}
	}
}

func TestCycloneDXVEX(t *testing.T) {
	p := writeVEX(t, `{"bomFormat":"CycloneDX","vulnerabilities":[
	 {"id":"CVE-2022-29078","analysis":{"state":"false_positive"},"affects":[{"ref":"pkg:npm/ejs@3.1.6"}]},
	 {"id":"CVE-2026-9","analysis":{"state":"exploitable"},"affects":[{"ref":"pkg:npm/qs@6.13.0"}]}]}`)
	stmts, err := LoadVEX([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	ejs := vulnFinding("pkg:npm/ejs@3.1.6", "GHSA-phwq-j96m-2c2q", "CVE-2022-29078")
	qs := vulnFinding("pkg:npm/qs@6.13.0", "GHSA-9", "CVE-2026-9")
	ApplyVEX([]*model.Finding{ejs, qs}, stmts)
	if !ejs.Suppressed || qs.Suppressed {
		t.Errorf("false_positive must suppress, exploitable must not: ejs=%v qs=%v", ejs.Suppressed, qs.Suppressed)
	}
}

// The latest statement about a vulnerability in a component decides: a later
// affected statement revokes an earlier not_affected one, by timestamp (also
// across documents and against the document order) and, without timestamps,
// by the order of the statements.
func TestVEXLatestStatementWins(t *testing.T) {
	const na = `{"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash@4.17.15"}],"status":"not_affected","justification":"vulnerable_code_not_in_execute_path"%s}`
	const af = `{"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash%s"}],"status":"%s"%s}`
	doc := func(ts string, stmts ...string) string {
		return `{"@context":"https://openvex.dev/ns/v0.2.0","timestamp":"` + ts + `","statements":[` + strings.Join(stmts, ",") + `]}`
	}
	at := func(ts string) string { return `,"timestamp":"` + ts + `"` }
	cases := []struct {
		name     string
		docs     []string
		suppress bool
		status   string
	}{
		{"later affected revokes", []string{doc("2026-11-01T00:00:00Z", fmt.Sprintf(na, at("2026-10-01T00:00:00Z")), fmt.Sprintf(af, "@4.17.15", "affected", at("2026-10-15T00:00:00Z")))}, false, "affected"},
		{"timestamps beat order", []string{doc("2026-11-01T00:00:00Z", fmt.Sprintf(af, "@4.17.15", "affected", at("2026-10-15T00:00:00Z")), fmt.Sprintf(na, at("2026-10-01T00:00:00Z")))}, false, "affected"},
		{"later not_affected re-suppresses", []string{doc("2026-11-01T00:00:00Z", fmt.Sprintf(af, "@4.17.15", "under_investigation", at("2026-10-01T00:00:00Z")), fmt.Sprintf(na, at("2026-10-15T00:00:00Z")))}, true, "not_affected"},
		{"order without timestamps", []string{`{"statements":[` + fmt.Sprintf(na, "") + "," + fmt.Sprintf(af, "@4.17.15", "affected", "") + `]}`}, false, "affected"},
		{"document timestamps across files", []string{doc("2026-10-20T00:00:00Z", fmt.Sprintf(af, "", "affected", "")), doc("2026-10-01T00:00:00Z", fmt.Sprintf(na, ""))}, false, "affected"},
		{"later fixed for all versions", []string{doc("2026-11-01T00:00:00Z", fmt.Sprintf(af, "@4.17.15", "affected", at("2026-10-01T00:00:00Z")), fmt.Sprintf(af, "", "fixed", at("2026-10-02T00:00:00Z")))}, true, "fixed"},
	}
	for _, c := range cases {
		var paths []string
		for _, d := range c.docs {
			paths = append(paths, writeVEX(t, d))
		}
		stmts, err := LoadVEX(paths)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		f := vulnFinding("pkg:npm/lodash@4.17.15", "GHSA-35jh-r3h4-6jhm", "CVE-2021-23337")
		ApplyVEX([]*model.Finding{f}, stmts)
		if f.Suppressed != c.suppress || f.Vuln.VEXStatus != c.status {
			t.Errorf("%s: suppressed=%v status=%q, want %v %q", c.name, f.Suppressed, f.Vuln.VEXStatus, c.suppress, c.status)
		}
	}
	// CycloneDX: lastUpdated orders the analyses
	p := writeVEX(t, `{"bomFormat":"CycloneDX","vulnerabilities":[
	 {"id":"CVE-2021-23337","analysis":{"state":"exploitable","lastUpdated":"2026-10-15T00:00:00Z"},"affects":[{"ref":"pkg:npm/lodash@4.17.15"}]},
	 {"id":"CVE-2021-23337","analysis":{"state":"not_affected","justification":"code_not_reachable","lastUpdated":"2026-10-01T00:00:00Z"},"affects":[{"ref":"pkg:npm/lodash@4.17.15"}]}]}`)
	stmts, err := LoadVEX([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	f := vulnFinding("pkg:npm/lodash@4.17.15", "GHSA-35jh-r3h4-6jhm", "CVE-2021-23337")
	ApplyVEX([]*model.Finding{f}, stmts)
	if f.Suppressed || f.Vuln.VEXStatus != "affected" {
		t.Errorf("CycloneDX: older not_affected applied over a later exploitable: %+v", f.Vuln)
	}
}

// OpenVEX aliases of the vulnerability are matched as well.
func TestVEXAliases(t *testing.T) {
	p := writeVEX(t, `{"statements":[{"vulnerability":{"name":"GHSA-35jh-r3h4-6jhm","aliases":["CVE-2021-23337"]},
	 "products":[{"@id":"pkg:npm/lodash@4.17.15"}],"status":"not_affected","impact_statement":"template() is never called"}]}`)
	stmts, err := LoadVEX([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	f := vulnFinding("pkg:npm/lodash@4.17.15", "CVE-2021-23337", "")
	if ApplyVEX([]*model.Finding{f}, stmts) != 1 || f.Vuln.VEXJustification != "template() is never called" {
		t.Errorf("alias not matched: %+v", f.Vuln)
	}
}

// Faulty statements make the whole document invalid (a usage error).
func TestVEXInvalidStatementsRejected(t *testing.T) {
	const prod = `"products":[{"@id":"pkg:npm/lodash@4.17.15"}]`
	cases := map[string]string{
		"no justification":        `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"not_affected"}]}`,
		"blank impact":            `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"not_affected","impact_statement":"  "}]}`,
		"unknown justification":   `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"not_affected","justification":"trust_me"}]}`,
		"unknown status":          `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"bogus_status"}]}`,
		"no status":               `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `}]}`,
		"no vulnerability":        `{"statements":[{` + prod + `,"status":"fixed"}]}`,
		"bad timestamp":           `{"timestamp":"yesterday","statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"fixed"}]}`,
		"bad statement timestamp": `{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"fixed","timestamp":"2026-13-01"}]}`,
		"cdx unknown state":       `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"maybe"},"affects":[{"ref":"pkg:npm/x@1"}]}]}`,
		"cdx empty state":         `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"detail":"x"},"affects":[{"ref":"pkg:npm/x@1"}]}]}`,
		"cdx not_affected bare":   `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected"},"affects":[{"ref":"pkg:npm/x@1"}]}]}`,
		"cdx unknown just.":       `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected","justification":"nope"},"affects":[{"ref":"pkg:npm/x@1"}]}]}`,
	}
	for name, doc := range cases {
		if _, err := LoadVEX([]string{writeVEX(t, doc)}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// accepted: impact statement instead of a justification, CycloneDX
	// detail, and a CycloneDX vulnerability without analysis (skipped)
	for _, doc := range []string{
		`{"statements":[{"vulnerability":{"name":"CVE-1"},` + prod + `,"status":"not_affected","impact_statement":"not used"}]}`,
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"not_affected","detail":"not used"},"affects":[{"ref":"pkg:npm/x@1"}]},{"id":"CVE-2"}]}`,
	} {
		if _, err := LoadVEX([]string{writeVEX(t, doc)}); err != nil {
			t.Errorf("rejected: %v", err)
		}
	}
}
