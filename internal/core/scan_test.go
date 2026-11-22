package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/policy"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// fetched records the advisory records requested from the mock.
var fetched sync.Map

// mock serves OSV, EPSS, KEV, deps.dev and the npm registry for the
// integration test of the whole pipeline (M0 -> M6).
func mock(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/osv/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
				Version string                `json:"version"`
			} `json:"queries"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var res []map[string]any
		for _, q := range req.Queries {
			var vs []map[string]string
			switch q.Package.Name + "@" + q.Version {
			case "a@1.2.0":
				vs = append(vs, map[string]string{"id": "GHSA-test-0001"}, map[string]string{"id": "GHSA-test-0002"})
			case "e@1.0.0":
				vs = append(vs, map[string]string{"id": "MAL-2026-0001"})
			case "lint@1.0.0":
				vs = append(vs, map[string]string{"id": "GHSA-test-0003"})
			case "evil@1.0.0":
				vs = append(vs, map[string]string{"id": "MAL-2026-0002"})
			}
			res = append(res, map[string]any{"vulns": vs})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	})
	mux.HandleFunc("/osv/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/osv/vulns/")
		fetched.Store(id, true)
		rec := map[string]any{"id": id, "summary": "test " + id}
		switch id {
		case "GHSA-test-0001":
			rec["aliases"] = []string{"CVE-2026-0001"}
			rec["severity"] = []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
			rec["affected"] = []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "a"},
				"ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "1.3.0"}}}}}}
		case "GHSA-test-0002": // the advisory range does not include 1.2.0: must be rejected locally
			rec["affected"] = []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "a"},
				"ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "2.0.0"}, {"fixed": "2.1.0"}}}}}}
		case "MAL-2026-0001":
			rec["affected"] = []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "e"}}}
		case "GHSA-test-0003": // high-severity advisory of a development tool
			rec["severity"] = []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
			rec["affected"] = []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "lint"},
				"ranges": []map[string]any{{"type": "SEMVER", "events": []map[string]string{{"introduced": "0"}, {"fixed": "2.0.0"}}}}}}
		case "MAL-2026-0002":
			rec["affected"] = []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "evil"}}}
		}
		json.NewEncoder(w).Encode(rec)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"cve": "CVE-2026-0001", "epss": "0.91"}}})
	})
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"vulnerabilities": []map[string]string{{"cveID": "CVE-2026-0001"}}})
	})
	// deps.dev release history of the typosquat test packages
	mux.HandleFunc("/depsdev/systems/npm/packages/", func(w http.ResponseWriter, r *http.Request) {
		var vs []map[string]any
		switch strings.TrimPrefix(r.URL.Path, "/depsdev/systems/npm/packages/") {
		case "expresss": // established: 2014-2019, 6 releases
			for i, d := range []string{"2014-03-01", "2015-01-10", "2016-05-02", "2017-07-07", "2018-02-02", "2019-09-09"} {
				vs = append(vs, map[string]any{"versionKey": map[string]string{"version": fmt.Sprintf("1.0.%d", i)}, "publishedAt": d + "T00:00:00Z"})
			}
		case "lodahs": // published a week before the scan
			vs = append(vs, map[string]any{"versionKey": map[string]string{"version": "1.0.0"}, "publishedAt": "2026-09-24T00:00:00Z"})
		default:
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"versions": vs})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return httptest.NewServer(mux)
}

func TestScanEndToEnd(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "testdata", "npm-v3")
	rep, doc, err := Scan(context.Background(), Options{
		Dir: dir, Net: netx.New("", false), Policy: pol, Provenance: false,
		Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	// report.json records the evaluation time (--now), not only the manifest
	if !rep.EvaluatedAt.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("evaluated_at %v", rep.EvaluatedAt)
	}
	// the development dependency t is part of the graph and of the SBOM
	// ... and so is the extraneous entry stale, which npm ci installs and M3 reports
	if rep.Stats.Components != 8 || len(doc.Components) != 8 || rep.Stats.ByScope["dev"] != 1 {
		t.Errorf("components: %d / %d, by scope %v", rep.Stats.Components, len(doc.Components), rep.Stats.ByScope)
	}
	if rep.Counters["osv_rejected_by_local_check"] != 1 {
		t.Errorf("local range check did not reject the out-of-range advisory: %v", rep.Counters)
	}
	rules := map[string]bool{}
	for _, v := range rep.Decision.Violations {
		rules[v.Rule] = true
	}
	extraneous := false
	for _, f := range rep.Findings {
		extraneous = extraneous || f.ID == "SSCA-LOCKFILE-EXTRANEOUS" && f.Component == "pkg:npm/stale@9.9.9"
	}
	if !extraneous {
		t.Errorf("extraneous lockfile entry stale@9.9.9 not reported")
	}
	for _, r := range []string{"known-malicious", "exploited-in-runtime", "critical-reachable-cve", "band-critical", "integrity-failure"} {
		if !rules[r] {
			t.Errorf("rule %s not triggered; violations %+v", r, rep.Decision.Violations)
		}
	}
	// the mock registry knows no version: nothing is verified, every
	// component is accounted for, and a missing version is not a failure
	if n := rep.HashCheck["not-on-registry"]; n != 8 || len(rep.Incomplete) != 0 {
		t.Errorf("hash check %v, incomplete %v", rep.HashCheck, rep.Incomplete)
	}
	if rep.Decision.ExitCode != 1 || len(rep.CRA) != 1 {
		t.Errorf("exit %d, CRA %v", rep.Decision.ExitCode, rep.CRA)
	}
	// malicious e@1.0.0 is reached through the d<->e cycle: risk must propagate to b
	var bRisk float64
	for _, s := range rep.TopDirect {
		if s.PURL == "pkg:npm/b@2.0.0" {
			bRisk = s.Subtree
		}
	}
	if bRisk != 100 {
		t.Errorf("subtree risk of b = %v, want 100", bRisk)
	}
	for _, f := range rep.Findings {
		if f.Kind == model.KindVulnerability && (f.Vuln.EPSS != 0.91 || !f.Vuln.KEV || f.Vuln.CVSS != 9.8) {
			t.Errorf("enrichment: %+v", f.Vuln)
		}
	}
}

// Development dependencies are in the graph by default: a known-malicious
// development package fails the build, while the vulnerability of a
// development tool is not reported (its record is not even fetched) unless
// IncludeDev asks for it, and then with the exposure factor 0.6.
// RuntimeOnly leaves them out entirely, as the runtime-only graph of
// earlier versions did.
func TestScanDevDependencies(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	scan := func(o Options) *report.Report {
		t.Helper()
		o.Dir, o.Net, o.Policy, o.Now, o.Version = filepath.Join("..", "..", "testdata", "npm-dev"), netx.New("", false), pol,
			time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "test"
		r, _, err := Scan(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ids := func(r *report.Report) map[string]string {
		m := map[string]string{}
		for _, f := range r.Findings {
			m[f.ID] = f.Component
		}
		return m
	}
	scopes := func(r *report.Report) map[string]string {
		m := map[string]string{}
		for _, c := range r.Components {
			m[c.Name] = fmt.Sprintf("%s/%d", c.Scope, c.Depth)
		}
		return m
	}

	fetched.Clear()
	def := scan(Options{})
	// c is a development dependency of the project and a runtime dependency
	// of a: it is runtime at depth 2
	want := map[string]string{"a": "runtime/1", "c": "runtime/2", "lint": "dev/1", "helper": "dev/2", "evil": "dev/1"}
	if got := scopes(def); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("scopes %v, want %v", got, want)
	}
	f := ids(def)
	if f["MAL-2026-0002"] != "pkg:npm/evil@1.0.0" {
		t.Errorf("known-malicious development dependency not reported: %v", f)
	}
	if _, ok := f["GHSA-test-0003"]; ok {
		t.Errorf("vulnerability of a development dependency reported by default")
	}
	if _, ok := fetched.Load("GHSA-test-0003"); ok {
		t.Errorf("advisory record of a development dependency fetched by default")
	}
	if def.Counters["dev_components_with_unreported_vulnerabilities"] != 1 {
		t.Errorf("counters %v", def.Counters)
	}
	failed := false
	for _, v := range def.Decision.Violations {
		failed = failed || v.Rule == "known-malicious" && v.Component == "pkg:npm/evil@1.0.0"
	}
	if !failed || def.Decision.ExitCode != 1 {
		t.Errorf("malicious dev dependency did not fail the build: %+v", def.Decision)
	}
	if def.Scope != (report.ScopeInfo{Graph: "all", Vulnerabilities: "runtime", DevHeuristics: true}) {
		t.Errorf("scope %+v", def.Scope)
	}
	if md := def.Markdown(); !strings.Contains(md, "### Development and test dependencies") || !strings.Contains(md, "MAL-2026-0002") {
		t.Errorf("summary lacks the development section:\n%s", md)
	}

	inc := scan(Options{IncludeDev: true})
	if ids(inc)["GHSA-test-0003"] != "pkg:npm/lint@1.0.0" {
		t.Errorf("--include-dev: vulnerability of lint not reported")
	}
	for _, s := range inc.Scores {
		if s.PURL == "pkg:npm/lint@1.0.0" && (s.C != 0.6 || s.V == 0 || s.Scope != model.ScopeDev) {
			t.Errorf("lint score %+v, want c = 0.6", s)
		}
	}

	rt := scan(Options{RuntimeOnly: true})
	if got := scopes(rt); fmt.Sprint(got) != fmt.Sprint(map[string]string{"a": "runtime/1", "c": "runtime/2"}) {
		t.Errorf("runtime-only graph %v", got)
	}
	if _, ok := ids(rt)["MAL-2026-0002"]; ok || rt.Scope.Graph != "runtime" {
		t.Errorf("runtime-only scan reports development packages")
	}

	// the policy can limit metadata and indicators to production packages
	off := false
	pol.DevHeuristics = &off
	nh := scan(Options{})
	pol.DevHeuristics = nil
	if ids(nh)["MAL-2026-0002"] == "" || nh.Scope.DevHeuristics {
		t.Errorf("dev_heuristics: false must keep the known-malicious check")
	}
}

// A lockfile that marks a production package as a development dependency
// must not hide its vulnerabilities: the package is analysed in the derived
// runtime scope (also with --runtime-only), and M3 reports the lockfile as
// an integrity finding, which fails the default policy.
func TestScanLockfileScopeMismatch(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"lib":"^1"}}`)
	write("package-lock.json", `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"lib":"^1"}},
"node_modules/lib":{"version":"1.0.0","dependencies":{"lint":"^1"}},
"node_modules/lint":{"version":"1.0.0","dev":true}}}`)
	for _, o := range []Options{{}, {RuntimeOnly: true}} {
		o.Dir, o.Net, o.Policy, o.Now, o.Version = dir, netx.New("", false), pol, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "test"
		r, _, err := Scan(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, f := range r.Findings {
			got[f.ID] = f.Component
		}
		if got["GHSA-test-0003"] != "pkg:npm/lint@1.0.0" || got["SSCA-LOCKFILE-SCOPE"] != "pkg:npm/lint@1.0.0" {
			t.Errorf("runtime-only=%v: findings %v, want the vulnerability and the lockfile-scope finding of lint", o.RuntimeOnly, got)
		}
		failed := false
		for _, v := range r.Decision.Violations {
			failed = failed || v.Rule == "integrity-failure" && v.Finding == "SSCA-LOCKFILE-SCOPE"
		}
		if !failed || r.Decision.ExitCode != 1 {
			t.Errorf("runtime-only=%v: decision %+v", o.RuntimeOnly, r.Decision)
		}
	}
}

// A lockfile that does not lock a dependency of package.json is out of sync:
// the scan is incomplete (exit code 2), not a pass over a smaller graph. An
// expired policy exception is a warning and does not make it incomplete.
func TestScanLockfileOutOfSync(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"lib":"^1"}}`)
	write("package-lock.json", `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"}}}`)
	write("policy.yaml", "version: 1\nexceptions:\n  - component: pkg:npm/lib\n    rule: band-high\n    reason: reviewed\n    expires: 2026-01-31\n")
	pol, err := policy.Load(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Dir: dir, Net: netx.New("", false), Policy: pol, Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Version: "test"}
	r, _, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision.ExitCode != 2 || len(r.Incomplete) != 1 || !strings.Contains(r.Incomplete[0], "lib@^1 (required by package.json)") {
		t.Fatalf("decision %+v, incomplete %v: want exit code 2 for the out-of-sync lockfile only", r.Decision, r.Incomplete)
	}
	expired := false
	for _, w := range r.Decision.Warnings {
		expired = expired || w.Rule == "exception-expired" && w.Component == "pkg:npm/lib"
	}
	if !expired {
		t.Errorf("warnings %+v: want the expired exception", r.Decision.Warnings)
	}
	// in sync: the expired exception alone leaves the scan complete
	write("package-lock.json", `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lib":"^1"}},
"node_modules/lib":{"version":"1.0.0","resolved":"`+srv.URL+`/npm/lib/-/lib-1.0.0.tgz"}}}`)
	if r, _, err = Scan(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Incomplete {
		if strings.Contains(s, "exception") || strings.Contains(s, "out of sync") {
			t.Errorf("incomplete %v", r.Incomplete)
		}
	}
}

// A name match is dismissed when the package has years of release history
// (the dismissal is named in the report notes); a young look-alike stays a
// typosquat finding.
func TestScanTyposquatEstablished(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app","version":"1.0.0","dependencies":{"expresss":"^1.0.5","lodahs":"^1.0.0"}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"expresss":"^1.0.5","lodahs":"^1.0.0"}},
"node_modules/expresss":{"version":"1.0.5","resolved":"https://registry.npmjs.org/expresss/-/expresss-1.0.5.tgz","integrity":"sha512-AAA="},
"node_modules/lodahs":{"version":"1.0.0","resolved":"https://registry.npmjs.org/lodahs/-/lodahs-1.0.0.tgz","integrity":"sha512-AAA="}}}`), 0o644)
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	rep, _, err := Scan(context.Background(), Options{Dir: dir, Net: netx.New("", false), Policy: pol,
		Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	squats := map[string]bool{}
	for _, f := range rep.Findings {
		if f.ID == "SSCA-TYPOSQUAT" {
			squats[f.Component] = true
		}
	}
	if !squats["pkg:npm/lodahs@1.0.0"] || squats["pkg:npm/expresss@1.0.5"] {
		t.Errorf("typosquat findings %v, want lodahs only", squats)
	}
	note := strings.Join(rep.Notes, "\n")
	if rep.Counters["typosquat_dismissed"] != 1 ||
		!strings.Contains(note, "typosquat dismissed: pkg:npm/expresss@1.0.5: established package: first release 2014-03-01, 6 releases over 5.5 years (name similar to express)") {
		t.Errorf("dismissal not reported: %v %q", rep.Counters["typosquat_dismissed"], note)
	}
}

// Reachability on a directory without source files of the application must
// not change the decision: every vulnerability is "unknown", the rule for
// critical reachable vulnerabilities still fires, and the report says why.
func TestScanReachabilityWithoutSource(t *testing.T) {
	srv := mock(t)
	defer srv.Close()
	vuln.API, vuln.EPSSURL, vuln.KEVURL = srv.URL+"/osv", srv.URL+"/epss", srv.URL+"/kev"
	risk.DepsDev, npm.Registry, npm.DownloadsAPI = srv.URL+"/depsdev", srv.URL+"/npm", srv.URL+"/downloads/"
	pol, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "testdata", "npm-v3") // package.json and package-lock.json only
	run := func(reach bool) *report.Report {
		rep, _, err := Scan(context.Background(), Options{
			Dir: dir, Net: netx.New("", false), Policy: pol, Reachability: reach,
			Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Version: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	without, with := run(false), run(true)
	if with.Decision.ExitCode != without.Decision.ExitCode || len(with.Decision.Violations) != len(without.Decision.Violations) {
		t.Errorf("decision changed: exit %d -> %d, violations %d -> %d", without.Decision.ExitCode, with.Decision.ExitCode,
			len(without.Decision.Violations), len(with.Decision.Violations))
	}
	fired := false
	for _, v := range with.Decision.Violations {
		fired = fired || v.Rule == "critical-reachable-cve"
	}
	if !fired {
		t.Errorf("critical-reachable-cve not triggered: %+v", with.Decision.Violations)
	}
	for _, f := range with.Findings {
		if f.Vuln != nil && f.Vuln.Reachable != "unknown" {
			t.Errorf("%s %s: reachable %q", f.Component, f.ID, f.Vuln.Reachable)
		}
	}
	note := false
	for _, n := range with.Notes {
		note = note || strings.HasPrefix(n, "reachability: no npm source files")
	}
	if !note || with.Counters["reach_no_source"] != 1 {
		t.Errorf("notes %v, counter %d", with.Notes, with.Counters["reach_no_source"])
	}
}

// Metadata sources that failed for some components give one incomplete
// reason per source with the number of components affected.
func TestMetadataUnavailable(t *testing.T) {
	comp := func(un ...string) *model.Component {
		c := model.NewComponent(model.NPM, "", "x", "1.0.0")
		c.Meta = &model.PackageMeta{Unavailable: un}
		return c
	}
	got := metadataUnavailable([]*model.Component{
		comp("deps.dev: HTTP 503", "npm registry: timeout"), comp("deps.dev: HTTP 503"), comp(), {Name: "no-meta"},
	})
	want := []string{
		"package metadata from deps.dev unavailable for 2 of 4 components (HTTP 503)",
		"package metadata from npm registry unavailable for 1 of 4 components (timeout)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The policy key data_snapshot requires an offline run on a sealed snapshot
// (any seal, or the named one); otherwise the scan stops with a self-check
// failure (exit code 4) before it starts. An unknown value is a usage error.
func TestDataSnapshotPolicy(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "sigstore-trusted_root.json"), []byte(`{}`), 0o644)
	seal, err := netx.SealCache(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pol := func(v string) *policy.Policy {
		f := filepath.Join(t.TempDir(), "p.yaml")
		os.WriteFile(f, []byte("version: 1\ndata_snapshot: "+v+"\n"), 0o644)
		p, err := policy.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		value   string
		offline bool
		ok      bool
	}{
		{"sealed", true, true},
		{"sealed", false, false},
		{seal.ID, true, true},
		{"sha256:0000", true, false},
	} {
		err := snapshotCheck(Options{Net: netx.New(dir, c.offline), Policy: pol(c.value)})
		if (err == nil) != c.ok {
			t.Errorf("data_snapshot %s, offline %v: %v", c.value, c.offline, err)
		}
	}
	// the saved trusted root is checked against the seal before the scan
	os.WriteFile(filepath.Join(dir, "sigstore-trusted_root.json"), []byte(`{"x":1}`), 0o644)
	if err := snapshotCheck(Options{Net: netx.New(dir, true), Policy: pol("sealed")}); err == nil {
		t.Errorf("changed trusted root not detected")
	}
	f := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(f, []byte("version: 1\ndata_snapshot: latest-verified\n"), 0o644)
	if _, err := policy.Load(f); err == nil {
		t.Errorf("unknown data_snapshot value accepted")
	}
}
