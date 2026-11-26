package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/expr-lang/expr/types"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func subject() Subject {
	g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
	lib := model.NewComponent("npm", "", "lib", "1.0.0")
	g.AddNode(lib)
	g.AddEdge(model.Edge{From: g.Root, To: lib.PURL})
	g.ComputeDepths()
	return Subject{
		Graph: g, Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		Findings: []*model.Finding{
			{ID: "MAL-2026-1", Kind: model.KindMalicious, Component: lib.PURL, Vuln: &model.Vulnerability{ID: "MAL-2026-1"}},
			{ID: "SSCA-CI-unpinned-action", Kind: model.KindCI, Rule: "unpinned-action", Evidence: map[string]any{"action_ref_type": "tag"}},
			// not about an action reference: rules on ci.action_ref_type do not apply
			{ID: "SSCA-CI-token-permissions", Kind: model.KindCI, Rule: "token-permissions"},
		},
		Scores: map[string]*model.Score{lib.PURL: {CRS: 100, Band: "critical"}},
	}
}

func TestDefaultPolicy(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(subject())
	if d.ExitCode != 1 {
		t.Fatalf("expected violation, got %+v", d)
	}
	rules := map[string]bool{}
	for _, v := range append(d.Violations, d.Warnings...) {
		rules[v.Rule] = true
	}
	for _, r := range []string{"known-malicious", "band-critical", "unpinned-ci-action"} {
		if !rules[r] {
			t.Errorf("rule %s not triggered: %+v", r, d)
		}
	}
	// the CI rule must not fire in component contexts
	n := 0
	for _, w := range d.Warnings {
		if w.Rule == "unpinned-ci-action" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("unpinned-ci-action fired %d times, want once (only for the unpinned action)", n)
	}
}

func TestExceptionsExpire(t *testing.T) {
	src := `version: 1
rules:
  - id: known-malicious
    when: vuln.id startswith 'MAL-'
    action: fail
exceptions:
  - component: pkg:npm/lib
    finding: MAL-2026-1
    reason: 'false positive, reviewed'
    expires: 2026-12-31
`
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(src), 0o644)
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s := subject()
	if d := p.Evaluate(s); d.ExitCode != 0 || len(d.Excepted) != 1 {
		t.Fatalf("exception not applied: %+v", d)
	}
	s.Now = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	d := p.Evaluate(s)
	if d.ExitCode != 1 || d.Incomplete {
		t.Fatalf("expired exception still applied: %+v", d)
	}
	// the expired exception is listed as a warning, not as incomplete analysis
	var w *Violation
	for i := range d.Warnings {
		if d.Warnings[i].Rule == "exception-expired" {
			w = &d.Warnings[i]
		}
	}
	if w == nil || w.Component != "pkg:npm/lib" || w.Finding != "MAL-2026-1" || !strings.Contains(w.Message, "2026-12-31") {
		t.Fatalf("expired exception not listed: %+v", d.Warnings)
	}
}

func TestExceptionNeedsReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte("exceptions:\n  - component: x\n    expires: 2027-01-01\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("exception without reason accepted")
	}
}

func load(t *testing.T, src string) (*Policy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// A policy that does not say what its author meant must be rejected at load
// time: each of these would otherwise disable a check without any message.
func TestPolicyRejectsMistakes(t *testing.T) {
	cases := map[string]string{
		"misspelt field":       "rules:\n  - id: x\n    when: vuln.severty == 'critical'\n    action: fail\n",
		"unknown root":         "rules:\n  - id: x\n    when: vulns.id startswith 'MAL-'\n    action: fail\n",
		"unknown signal":       "rules:\n  - id: x\n    when: signals.dependancy_confusion == true\n    action: fail\n",
		"type mismatch":        "rules:\n  - id: x\n    when: vuln.cvss == 'high'\n    action: fail\n",
		"unknown key":          "treshholds:\n  fail_on_band: low\n",
		"unknown nested key":   "thresholds:\n  fail_on: low\n",
		"unknown band":         "thresholds:\n  fail_on_band: hgh\n",
		"unknown incomplete":   "thresholds:\n  incomplete_analysis: ignore\n",
		"unknown weight":       "weights:\n  signals:\n    dependancy_confusion: 0.9\n",
		"unknown health":       "weights:\n  health:\n    stars: 0.5\n",
		"empty file":           "",
		"rule without when":    "rules:\n  - id: x\n    action: fail\n",
		"exception no expires": "exceptions:\n  - component: x\n    reason: ok\n",
		"registry not a URL":   "registries: [npm.mirror.example]\n",
	}
	for name, src := range cases {
		if _, err := load(t, src); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}

// Every field of the schema must be usable, and the policies shipped with the
// thesis material must still load.
func TestPolicySchemaAndShippedPolicies(t *testing.T) {
	var conds []string
	for root, typ := range Schema() {
		for field := range typ.(types.Map) {
			conds = append(conds, root+"."+field+" != nil")
		}
	}
	src := "rules:\n"
	for i, c := range conds {
		src += fmt.Sprintf("  - id: r%d\n    when: %s\n    action: info\n", i, c)
	}
	if _, err := load(t, src); err != nil {
		t.Fatalf("schema field rejected: %v", err)
	}
	for _, f := range []string{"../../../casestudy/acme-orders-api/.ssca/policy.yaml", "../../../corpus/c/zeroday/ssca-policy.yaml"} {
		if _, err := os.Stat(f); err != nil {
			continue // thesis material not checked out next to the module
		}
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// Rules written against the schema fire on the runtime environments.
func TestSchemaMatchesRuntime(t *testing.T) {
	p, err := load(t, `rules:
  - id: comp
    when: component.scope == 'runtime' and component.depth == 1 and component.direct and component.crs >= 100 and component.band == 'critical' and component.ecosystem == 'npm'
    action: fail
  - id: vul
    when: vuln.id startswith 'MAL-' and 'MAL-2026-1' not in vuln.aliases and not vuln.suppressed and vuln.cvss == 0.0
    action: fail
  - id: ci
    when: ci.action_ref_type == 'tag' and ci.rule == 'unpinned-action'
    action: fail
`)
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]bool{}
	for _, v := range p.Evaluate(subject()).Violations {
		fired[v.Rule] = true
	}
	for _, r := range []string{"comp", "vul", "ci"} {
		if !fired[r] {
			t.Errorf("rule %s did not fire", r)
		}
	}
}

// An exception must be scoped; a condition is read without its string
// literals; a condition that fails at run time makes the decision incomplete.
func TestExceptionScopeLiteralsAndErrors(t *testing.T) {
	if _, err := load(t, "exceptions:\n  - reason: everything\n    expires: 2099-01-01\n"); err == nil {
		t.Error("an exception without component, finding or rule was accepted")
	}
	p, err := load(t, `rules:
  - id: words
    when: finding.kind == 'ci' and finding.title contains 'vuln'
    action: fail
  - id: broken
    when: int(finding.title) > 1
    action: fail
`)
	if err != nil {
		t.Fatal(err)
	}
	sub := subject()
	sub.Findings = append(sub.Findings, &model.Finding{ID: "SSCA-CI-x", Kind: model.KindCI, Rule: "x", Title: "vuln in workflow"})
	d := p.Evaluate(sub)
	fired := false
	for _, v := range d.Violations {
		fired = fired || v.Rule == "words"
	}
	if !fired {
		t.Errorf("rule with 'vuln' inside a literal did not fire on a CI finding: %+v", d.Violations)
	}
	if len(d.Errors) == 0 || !d.Incomplete {
		t.Errorf("evaluation error not reported: %+v", d)
	}
}

// dev_heuristics is a known key; the built-in policy leaves it unset (on).
func TestDevHeuristicsKey(t *testing.T) {
	p, err := Load("")
	if err != nil || p.DevHeuristics != nil {
		t.Fatalf("default policy: %v, dev_heuristics %v", err, p.DevHeuristics)
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte("version: 1\ndev_heuristics: false\n"), 0o644)
	if p, err = Load(path); err != nil || p.DevHeuristics == nil || *p.DevHeuristics {
		t.Fatalf("dev_heuristics: false not read: %v", err)
	}
}

// The built-in rules on exploited and critical vulnerabilities apply to
// every production scope: a KEV vulnerability in a Maven provided or npm
// optional dependency fails the build like one in a runtime dependency,
// while one in a development or test dependency, or in a package that only an
// extra of a Python project needs, does not.
func TestDefaultPolicyProductionScopes(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range []model.Scope{model.ScopeRuntime, model.ScopeOptional, model.ScopeProvided, model.ScopeExtra, model.ScopeDev, model.ScopeTest} {
		g := model.NewGraph(model.NewComponent("maven", "x", "app", "1.0.0"))
		lib := model.NewComponent("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")
		lib.Scope = sc
		g.AddNode(lib)
		g.AddEdge(model.Edge{From: g.Root, To: lib.PURL, Scope: sc})
		g.ComputeDepths()
		d := p.Evaluate(Subject{Graph: g, Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			Findings: []*model.Finding{{ID: "GHSA-jfh8-c2jp-5v3q", Kind: model.KindVulnerability, Component: lib.PURL, Severity: model.SevCritical,
				Vuln: &model.Vulnerability{ID: "GHSA-jfh8-c2jp-5v3q", KEV: true, Reachable: "unknown"}}},
			Scores: map[string]*model.Score{lib.PURL: {CRS: 50, Band: "medium"}}})
		rules := map[string]bool{}
		for _, v := range d.Violations {
			rules[v.Rule] = true
		}
		want := sc.Production()
		if rules["exploited-in-runtime"] != want || rules["critical-reachable-cve"] != want {
			t.Errorf("scope %s: violations %v, want KEV and critical rules = %v", sc, rules, want)
		}
	}
}

// A missing provenance attestation on a line that had one blocks the build
// only together with a second malice signal; alone it is a warning
// (provenance-missing). The message of the blocking rule names every signal
// of its condition that the component raised.
func TestDefaultPolicyProvenanceRegression(t *testing.T) {
	p, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	reg := model.Signal{Name: "provenance_regression", Reason: "provenance missing although version 1.0.0 had it"}
	pub := model.Signal{Name: "publisher_changed", Reason: `published by "x", previous version by "y"`}
	for _, c := range []struct {
		name    string
		signals []model.Signal
		fail    string
		warn    string
	}{
		{"regression alone", []model.Signal{reg}, "", "provenance-missing"},
		{"regression and new publisher", []model.Signal{reg, pub}, "provenance-regression", ""},
		{"new publisher alone", []model.Signal{pub}, "", ""},
	} {
		g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
		lib := model.NewComponent("npm", "", "lib", "1.0.1")
		g.AddNode(lib)
		g.AddEdge(model.Edge{From: g.Root, To: lib.PURL})
		g.ComputeDepths()
		d := p.Evaluate(Subject{Graph: g, Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			Scores: map[string]*model.Score{lib.PURL: {CRS: 30, Band: "medium", Signals: c.signals}}})
		got := map[string]string{}
		for _, v := range d.Violations {
			got["fail "+v.Rule] = v.Message
		}
		for _, v := range d.Warnings {
			got["warn "+v.Rule] = v.Message
		}
		for _, r := range []string{"provenance-regression", "provenance-missing"} {
			_, f := got["fail "+r]
			_, w := got["warn "+r]
			if f != (c.fail == r) || w != (c.warn == r) {
				t.Errorf("%s: %s fail=%v warn=%v, decisions %v", c.name, r, f, w, got)
			}
		}
		if m := got["fail provenance-regression"]; c.fail != "" && !(strings.Contains(m, reg.Reason) && strings.Contains(m, pub.Reason)) {
			t.Errorf("%s: message %q does not name both signals", c.name, m)
		}
	}
}

// A scan without --policy uses .ssca/policy.yaml of the project, "builtin"
// forces the built-in policy, and VEX paths of a policy file are relative to
// that file.
func TestFindProjectPolicy(t *testing.T) {
	dir := t.TempDir()
	if p, found := Find(dir, ""); p != "" || found {
		t.Fatalf("no policy file: got %q, %v", p, found)
	}
	pf := filepath.Join(dir, ".ssca", "policy.yaml")
	os.MkdirAll(filepath.Dir(pf), 0o755)
	os.WriteFile(pf, []byte("version: 1\nvex: [vex/a.json, /abs/b.json]\n"), 0o644)
	if p, found := Find(dir, ""); p != pf || !found {
		t.Fatalf("project policy: got %q, %v", p, found)
	}
	if p, found := Find(dir, Builtin); p != "" || found {
		t.Fatalf("--policy builtin: got %q, %v", p, found)
	}
	if p, found := Find(dir, "other.yaml"); p != "other.yaml" || found {
		t.Fatalf("explicit policy: got %q, %v", p, found)
	}
	pol, err := Load(pf)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, ".ssca", "vex", "a.json"), "/abs/b.json"}
	if fmt.Sprint(pol.VEX) != fmt.Sprint(want) {
		t.Errorf("VEX paths %v, want %v", pol.VEX, want)
	}
}

// The baseline rules apply whatever the policy file says: a project policy
// without rules, or one that redefines known-malicious as a warning or a
// condition that never holds, still fails on a known-malicious package, a
// tampered lockfile entry and a KEV vulnerability of a shipped package. An
// exception still accepts one result, and a policy that fails these
// findings itself gets no second violation.
func TestBaselineRules(t *testing.T) {
	sub := subject()
	lib := sub.Graph.Components()[0].PURL
	sub.Findings = append(sub.Findings,
		&model.Finding{ID: "SSCA-LOCKFILE-SOURCE", Kind: model.KindIntegrity, Rule: "lockfile-source", Component: lib},
		&model.Finding{ID: "GHSA-kev", Kind: model.KindVulnerability, Component: lib, Vuln: &model.Vulnerability{ID: "GHSA-kev", KEV: true}})
	baseline := func(d Decision) string {
		var out []string
		for _, v := range d.Violations {
			if v.Baseline {
				out = append(out, v.Rule+"/"+v.Finding)
			}
		}
		return strings.Join(out, " ")
	}
	const all = "exploited-in-runtime/GHSA-kev integrity-failure/SSCA-LOCKFILE-SOURCE known-malicious/MAL-2026-1"
	for _, src := range []string{
		"version: 1\nrules: []\n",
		"version: 1\nrules:\n  - id: known-malicious\n    when: \"false\"\n    action: fail\n",
		"version: 1\nrules:\n  - id: known-malicious\n    when: vuln.id startswith 'MAL-'\n    action: warn\n",
	} {
		p, err := load(t, src)
		if err != nil {
			t.Fatal(err)
		}
		d := p.Evaluate(sub)
		if got := baseline(d); got != all || d.ExitCode != 1 {
			t.Errorf("policy %q: baseline violations %q (exit %d), want %q", src, got, d.ExitCode, all)
		}
	}
	p, err := load(t, "version: 1\nrules: []\nexceptions:\n  - {finding: MAL-2026-1, reason: withdrawn advisory, expires: 2027-01-01}\n")
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(sub)
	if got := baseline(d); strings.Contains(got, "MAL-2026-1") || len(d.Excepted) != 1 || !d.Excepted[0].Baseline {
		t.Errorf("exception not applied to the baseline rule: violations %q, excepted %+v", got, d.Excepted)
	}
	def, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if got := baseline(def.Evaluate(sub)); got != "" {
		t.Errorf("built-in policy got baseline violations %q, want none (it has the rules itself)", got)
	}
}

// extends: builtin applies the built-in rules and thresholds together with
// those of the file: disable removes a built-in rule, a rule of the file
// replaces the built-in rule of the same id, and a threshold the file sets
// replaces only that threshold.
func TestPolicyExtendsBuiltin(t *testing.T) {
	ids := func(p *Policy) string {
		var out []string
		for _, r := range p.Rules {
			out = append(out, r.ID+"="+r.Action)
		}
		return strings.Join(out, " ")
	}
	def, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	// only project settings: the policy is the built-in one
	p, err := load(t, "extends: builtin\ninternal:\n  scopes: ['@acme']\n  registry: https://npm.acme.example/\n")
	if err != nil {
		t.Fatal(err)
	}
	if ids(p) != ids(def) || p.Thresholds != def.Thresholds || len(p.Internal.Scopes) != 1 {
		t.Errorf("extends without changes: rules %s, thresholds %+v, internal %+v", ids(p), p.Thresholds, p.Internal)
	}
	if d := p.Evaluate(subject()); d.ExitCode != 1 {
		t.Errorf("built-in rules not applied: %+v", d)
	}
	p, err = load(t, "extends: builtin\ndisable: [cooldown, unpinned-ci-action]\nthresholds:\n  warn_on_band: medium\nrules:\n"+
		"  - id: provenance-missing\n    when: signals.provenance_regression == true\n    action: fail\n"+
		"  - id: no-deprecated\n    when: signals.deprecated == true\n    action: warn\n")
	if err != nil {
		t.Fatal(err)
	}
	got := ids(p)
	for _, want := range []string{"known-malicious=fail", "critical-reachable-cve=fail", "provenance-missing=fail", "no-deprecated=warn"} {
		if !strings.Contains(got, want) {
			t.Errorf("rules %s lack %s", got, want)
		}
	}
	if strings.Contains(got, "cooldown") || strings.Contains(got, "unpinned-ci-action") || strings.Contains(got, "provenance-missing=warn") {
		t.Errorf("disabled or replaced rule still applies: %s", got)
	}
	if th := p.Thresholds; th.FailOnBand != "critical" || th.WarnOnBand != "medium" || th.IncompleteAnalysis != "fail" {
		t.Errorf("thresholds %+v", th)
	}
	for _, w := range p.Evaluate(subject()).Warnings {
		if w.Rule == "unpinned-ci-action" {
			t.Errorf("disabled rule warned: %+v", w)
		}
	}
	// "none" switches an inherited band rule off
	if p, err = load(t, "extends: builtin\nthresholds:\n  fail_on_band: none\n"); err != nil || p.Thresholds.FailOnBand != "" {
		t.Errorf("fail_on_band: none: %v, %+v", err, p)
	}
	// a file without extends still replaces the built-in policy
	if p, err = load(t, "rules:\n  - id: x\n    when: vuln.id startswith 'X-'\n    action: fail\n"); err != nil || ids(p) != "x=fail" || p.Thresholds.FailOnBand != "" {
		t.Errorf("replacing policy: %v, %s, %+v", err, ids(p), p.Thresholds)
	}
	for name, src := range map[string]string{
		"unknown extends":    "extends: strict\n",
		"disable alone":      "disable: [cooldown]\n",
		"unknown rule":       "extends: builtin\ndisable: [cooldwn]\n",
		"baseline rule":      "extends: builtin\ndisable: [known-malicious]\n",
		"own rule":           "extends: builtin\ndisable: [x]\nrules:\n  - id: x\n    when: vuln.kev == true\n    action: warn\n",
		"rule defined twice": "extends: builtin\nrules:\n  - id: x\n    when: vuln.kev == true\n    action: warn\n  - id: x\n    when: vuln.kev == true\n    action: fail\n",
		"unknown unpinned":   "thresholds:\n  unpinned_dependencies: ignore\n",
	} {
		if _, err := load(t, src); err == nil {
			t.Errorf("%s: policy accepted", name)
		}
	}
}
