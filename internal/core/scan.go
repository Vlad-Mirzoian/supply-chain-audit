package core

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/ciaudit"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/integrity"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/policy"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/reach"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// Options configure a scan.
type Options struct {
	Dir       string
	Ecosystem string
	// The graph holds the development and test dependencies unless
	// RuntimeOnly is set. Known-malicious versions, lockfile integrity and the
	// malicious-package indicators are checked in every scope; vulnerabilities
	// of development and test dependencies are reported only with IncludeDev.
	IncludeDev   bool
	RuntimeOnly  bool
	ForceResolve bool
	Net          *netx.Client
	CacheDir     string
	Offline      bool
	Policy       *policy.Policy
	VEX          []string
	Reachability bool
	Provenance   bool
	NoMetadata   bool // skip M4 registry metadata (faster, fewer signals)
	Now          time.Time
	Version      string
}

// SelfCheckError signals exit code 4.
type SelfCheckError struct{ Err error }

func (e SelfCheckError) Error() string { return "self-check failed: " + e.Err.Error() }

// snapshotCheck enforces the policy key data_snapshot and checks the saved
// Sigstore trusted root of a sealed snapshot before the scan starts (the
// responses are checked as they are read).
func snapshotCheck(o Options) error {
	if o.Net == nil {
		return nil
	}
	if err := o.Net.SealError(); err != nil {
		return err
	}
	req := ""
	if o.Policy != nil {
		req = o.Policy.DataSnapshot
	}
	if req != "" && (!o.Net.Offline || o.Net.Seal == nil) {
		return fmt.Errorf("the policy requires a sealed data snapshot (data_snapshot: %s), but the run is not offline on a sealed snapshot", req)
	}
	if strings.HasPrefix(req, "sha256:") && req != o.Net.Seal.ID {
		return fmt.Errorf("the policy requires the data snapshot %s, the cache is sealed as %s", req, o.Net.Seal.ID)
	}
	if o.Net.Offline && o.Net.Seal != nil {
		for _, f := range []string{"sigstore-trusted_root.json", "sigstore-trusted_root.json.fetched"} {
			if err := o.Net.Seal.CheckFile(o.Net.CacheDir, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// Scan runs the full pipeline of Fig. 3.5 and returns the report and the
// generated SBOM document.
func Scan(ctx context.Context, o Options) (*report.Report, *sbom.Doc, error) {
	if err := data.SelfCheck(); err != nil {
		return nil, nil, SelfCheckError{err}
	}
	if err := snapshotCheck(o); err != nil {
		return nil, nil, SelfCheckError{err}
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	start := time.Now()
	stages := map[string]float64{}
	var stagesMu sync.Mutex // M2, M4 and M5 finish concurrently
	lap := func(name string, t0 time.Time) {
		d := time.Since(t0).Seconds()
		stagesMu.Lock()
		stages[name] = d
		stagesMu.Unlock()
	}
	r := &report.Report{Tool: "ssca", Version: o.Version, Started: start.UTC(), EvaluatedAt: o.Now.UTC(), Stages: stages, Counters: map[string]int{}}

	// M0
	t0 := time.Now()
	g, ecos, err := BuildGraph(ctx, o.Dir, o.Ecosystem, common.Options{Net: o.Net, IncludeDev: !o.RuntimeOnly, MaxRounds: 3, ForceResolve: o.ForceResolve})
	if err != nil {
		return nil, nil, fmt.Errorf("graph construction: %w", err)
	}
	lap("m0_graph", t0)
	comps := g.Components()
	devHeuristics := o.Policy.DevHeuristics == nil || *o.Policy.DevHeuristics
	r.Scope = report.ScopeInfo{Graph: "all", Vulnerabilities: "runtime", DevHeuristics: devHeuristics}
	if o.RuntimeOnly {
		r.Scope.Graph = "runtime"
	}
	if o.IncludeDev {
		r.Scope.Vulnerabilities = "all"
	}
	// components that get registry metadata and malicious-package signals
	heurComps := comps
	if !devHeuristics {
		heurComps = nil
		for _, c := range comps {
			if c.Scope.Production() {
				heurComps = append(heurComps, c)
			}
		}
	}
	r.Project = report.Project{Dir: o.Dir, Root: g.Root, Ecosystem: strings.Join(ecos, "+"), Inputs: g.Inputs, InputHashes: map[string]string{}}
	for _, in := range g.Inputs {
		r.Project.InputHashes[in] = report.HashFile(filepath.Join(o.Dir, in))
	}
	incomplete := append([]string{}, g.Incomplete...)
	// PyPI dependencies without a lockfile are a valid input, but their
	// versions are resolved at this run and their hashes are not pinned; the
	// policy can make that an incomplete analysis (npm without a lockfile
	// always is one)
	if o.Policy.Thresholds.UnpinnedDependencies == "fail" {
		if n := Unlocked(g.Inputs, comps)[model.PyPI]; n > 0 {
			verb := "versions are"
			if n == 1 {
				verb = "version is"
			}
			incomplete = append(incomplete, fmt.Sprintf("no lockfile for the PyPI dependencies: %d package %s not pinned with a hash "+
				"and resolved at this run (thresholds.unpinned_dependencies: fail)", n, verb))
		}
	}

	// M2, M4 metadata and M5 run concurrently; M3 and the signals need the metadata
	var (
		wg        sync.WaitGroup
		vulnFs    []*model.Finding
		vulnErr   error
		ciFs      []*model.Finding
		ciFiles   []string
		ciErrs    []string
		matcher   = vuln.NewMatcher(o.Net)
		collector = risk.NewCollector(o.Net, o.Now)
	)
	if !o.IncludeDev {
		matcher.VulnScope = func(c *model.Component) bool { return c.Scope.Production() }
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		t := time.Now()
		vulnFs, vulnErr = matcher.Match(ctx, comps)
		lap("m2_vulnerabilities", t)
	}()
	go func() {
		defer wg.Done()
		t := time.Now()
		if !o.NoMetadata {
			collector.Collect(ctx, heurComps)
		}
		lap("m4_metadata", t)
	}()
	go func() {
		defer wg.Done()
		t := time.Now()
		ciFs, ciFiles, ciErrs = ciaudit.Audit(o.Dir)
		lap("m5_ci", t)
	}()
	wg.Wait()
	if vulnErr != nil {
		incomplete = append(incomplete, "vulnerability data: "+vulnErr.Error())
	}
	for _, e := range ciErrs {
		incomplete = append(incomplete, "CI configuration "+e)
	}
	incomplete = append(incomplete, metadataUnavailable(heurComps)...)
	r.Project.CIFiles = ciFiles

	// M3
	t0 = time.Now()
	trust := &integrity.Trust{CacheDir: o.CacheDir, Offline: o.Offline}
	ver := &integrity.Verifier{Net: o.Net, Trust: trust,
		Provenance: o.Provenance, Expect: o.Policy.RequireProvenance,
		Registries: o.Policy.Registries, Internal: o.Policy.Internal.Registry,
		TrustedBuilders: o.Policy.TrustedBuilders}
	intFs, provResults, hashUnavailable := ver.Check(ctx, comps)
	intFs = append(intFs, ver.Repositories(g.Root, g.Repositories)...)
	lap("m3_integrity", t0)
	r.HashCheck = map[string]int{}
	for _, c := range comps {
		r.HashCheck[c.HashCheck]++
	}
	var hashMissing []string
	for purl, e := range hashUnavailable {
		hashMissing = append(hashMissing, "lockfile hash of "+purl+" could not be checked: "+e)
	}
	sort.Strings(hashMissing)
	incomplete = append(incomplete, hashMissing...)
	verified, notServed := 0, 0
	var unavailable []string
	for purl, pr := range provResults {
		if pr.Verified {
			verified++
		}
		if pr.Unavailable {
			unavailable = append(unavailable, "provenance of "+purl+" could not be checked: "+pr.Error)
		}
		if pr.NotServed {
			notServed++ // announced but not served by the registry: a warning, not an incomplete analysis
		}
	}
	sort.Strings(unavailable)
	incomplete = append(incomplete, unavailable...)
	r.Counters["provenance_verified"] = verified
	r.Counters["provenance_checked"] = len(provResults) - len(unavailable) - notServed
	r.Counters["provenance_unchecked"] = len(unavailable)
	r.Counters["provenance_not_served"] = notServed
	r.TrustedRootCopy = trust.SavedCopy(o.Now)

	// M4 signals
	t0 = time.Now()
	indexes := map[string]*risk.Index{} // typosquat index per ecosystem
	for _, eco := range ecos {
		if corpus, _, err := data.Corpus(eco, 0); err == nil && len(corpus) > 0 {
			internal := append([]string{}, o.Policy.Internal.Names...)
			indexes[eco] = risk.NewIndex(eco, corpus, internal)
		}
	}
	signals := map[string][]model.Signal{}
	var sigFs []*model.Finding
	var dismissed []string // typosquat matches dismissed for established packages
	for _, c := range heurComps {
		s, squats := risk.Signals(c, indexes[c.Ecosystem], o.Policy.Weights, o.Policy.Internal, o.Now)
		dismiss := func(why string) {
			target := squats[0].Target
			var rest []model.Signal
			for _, sg := range s {
				if sg.Name != "typosquat" {
					rest = append(rest, sg)
				}
			}
			s, squats = rest, nil
			r.Counters["typosquat_dismissed"]++
			if why != "" {
				dismissed = append(dismissed, fmt.Sprintf("%s: %s (name similar to %s)", c.PURL, why, target))
			}
		}
		if len(squats) > 0 {
			// confirm a name match with data that the corpus does not hold:
			// the release history (all ecosystems), and for npm the
			// candidate's real popularity (gap filter) and ownership
			if ok, why := risk.Established(c.Meta, o.Now); ok {
				dismiss(why)
			} else if c.Ecosystem == model.NPM && !o.NoMetadata && !confirmSquat(ctx, o, c, squats[0]) {
				dismiss("")
			}
		}
		signals[c.PURL] = s
		for _, sg := range s {
			switch sg.Name {
			case "typosquat":
				sigFs = append(sigFs, &model.Finding{ID: "SSCA-TYPOSQUAT", Kind: model.KindSignal, Rule: "typosquat", Component: c.PURL,
					Severity: model.SevHigh, Title: "Possible typosquat of " + squats[0].Target, Detail: sg.Reason, Module: "M4",
					Evidence: map[string]any{"target": squats[0].Target, "class": squats[0].Class, "similarity": squats[0].Similarity}})
			case "dependency_confusion":
				sigFs = append(sigFs, &model.Finding{ID: "SSCA-DEP-CONFUSION", Kind: model.KindConfusion, Rule: "dependency-confusion", Component: c.PURL,
					Severity: model.SevCritical, Title: "Internal package resolved from a public registry", Detail: sg.Reason, Module: "M4"})
			case "provenance_regression":
				sigFs = append(sigFs, &model.Finding{ID: "SSCA-PROV-REGRESSION", Kind: model.KindProvenance, Rule: "provenance-regression", Component: c.PURL,
					Severity: model.SevHigh, Title: "Provenance regression", Detail: sg.Reason, Module: "M4"})
			}
		}
		if c.Meta != nil && len(c.Meta.Incomplete) > 0 {
			r.Counters["metadata_incomplete"]++
		}
		if c.Meta != nil && len(c.Meta.Unavailable) > 0 {
			r.Counters["metadata_unavailable"]++
		}
	}
	sort.Strings(dismissed)
	lap("m4_signals", t0)

	findings := append(append(append(append([]*model.Finding{}, vulnFs...), intFs...), ciFs...), sigFs...)

	// optional reachability
	var reachNotes []string
	if o.Reachability {
		t0 = time.Now()
		// only shipped code is analysed: development and test packages are
		// not imported by the application at run time
		an := &reach.Analyzer{Net: o.Net, Dir: o.Dir}
		res := an.Run(ctx, g.ProductionView())
		for _, f := range findings {
			if f.Vuln != nil {
				if s, ok := res[f.Component]; ok {
					f.Vuln.Reachable = s
				}
			}
		}
		r.Reachability = res
		r.Counters["reach_archives_read"] = an.Analysed
		r.Counters["reach_archives_failed"] = an.Failed
		r.Counters["reach_no_source"] = len(an.NoSource)
		for _, eco := range an.NoSource {
			reachNotes = append(reachNotes, fmt.Sprintf("reachability: no %s source files of the application under %s; reachability of %s packages is unknown", eco, o.Dir, eco))
		}
		lap("reachability", t0)
	}

	// VEX
	if len(o.VEX) > 0 {
		stmts, err := vuln.LoadVEX(o.VEX)
		if err != nil {
			return nil, nil, fmt.Errorf("VEX: %w", err)
		}
		r.Counters["vex_suppressed"] = vuln.ApplyVEX(findings, stmts)
	}

	// Algorithm 3.3
	t0 = time.Now()
	byComp := map[string][]*model.Finding{}
	for _, f := range findings {
		if f.Component != "" {
			byComp[f.Component] = append(byComp[f.Component], f)
		}
	}
	scores := risk.ScoreGraph(g, risk.Input{Findings: byComp, Signals: signals}, o.Policy.Weights, o.Now)
	lap("m4_scoring", t0)

	// M6
	t0 = time.Now()
	r.Decision = o.Policy.Evaluate(policy.Subject{Graph: g, Findings: findings, Scores: scores, Incomplete: incomplete, Now: o.Now})
	for _, e := range r.Decision.Errors {
		incomplete = append(incomplete, "policy: "+e)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := model.SeverityRank(findings[i].Severity), model.SeverityRank(findings[j].Severity)
		if a != b {
			return a > b
		}
		return findings[i].Component+findings[i].ID < findings[j].Component+findings[j].ID
	})
	r.Findings = findings
	for _, s := range scores {
		r.Scores = append(r.Scores, s)
	}
	sort.Slice(r.Scores, func(i, j int) bool {
		if r.Scores[i].CRS != r.Scores[j].CRS {
			return r.Scores[i].CRS > r.Scores[j].CRS
		}
		return r.Scores[i].PURL < r.Scores[j].PURL
	})
	r.TopDirect = risk.TopDirect(g, scores)
	r.Incomplete = incomplete
	r.Notes = append(append([]string{}, g.Notes...), reachNotes...)
	for _, d := range dismissed {
		r.Notes = append(r.Notes, "typosquat dismissed: "+d)
	}
	r.Components = comps
	st := report.Stats{ByDepth: map[int]int{}, ByBand: map[string]int{}, ByScope: map[string]int{}, Edges: g.EdgeCount(), Cycles: len(g.Cycles), Conflicts: len(g.Conflicts)}
	for _, c := range comps {
		st.Components++
		st.ByScope[string(c.Scope)]++
		if c.Direct {
			st.Direct++
		}
		st.ByDepth[c.Depth]++
		if c.Depth > st.MaxDepth {
			st.MaxDepth = c.Depth
		}
	}
	for _, s := range scores {
		st.ByBand[s.Band]++
	}
	r.Stats = st
	for _, f := range findings {
		if f.Vuln != nil && f.Vuln.KEV && !f.Suppressed {
			if c := g.Nodes[f.Component]; c != nil && c.Scope.Production() {
				r.CRA = append(r.CRA, report.CRACandidate{Component: f.Component, Vuln: f.ID, CVEs: strings.Join(f.Vuln.CVEs(), ","), Reachable: f.Vuln.Reachable})
			}
		}
		r.Counters["findings_"+string(f.Kind)]++
		if f.Suppressed {
			r.Counters["suppressed"]++
		}
	}
	r.Counters["osv_rejected_by_local_check"] = matcher.Rejected
	if matcher.Omitted > 0 {
		r.Counters["dev_components_with_unreported_vulnerabilities"] = matcher.Omitted
	}
	lap("m6_policy_report", t0)
	if err := o.Net.SealError(); err != nil {
		return nil, nil, SelfCheckError{err}
	}
	r.Snapshot = o.Net.SnapshotID()
	if o.Net.Offline && o.Net.Seal != nil {
		r.SnapshotSeal = o.Net.Seal.ID
	}
	r.Network = map[string]int64{"requests": o.Net.Requests.Load(), "cache_hits": o.Net.CacheHits.Load()}
	r.DurationSec = time.Since(start).Seconds()

	doc := sbom.FromGraph(g, o.Version, o.Now)
	return r, doc, nil
}

// confirmSquat re-checks a suspected npm typosquat with the downloads API
// and the maintainers (risk.ConfirmNPMSquat); it records the downloads of
// the candidate in its metadata.
func confirmSquat(ctx context.Context, o Options, c *model.Component, s risk.Squat) bool {
	ok, d, _ := risk.ConfirmNPMSquat(ctx, npm.NewRegistry(o.Net), c.FullName(), c.Version, s.Target)
	if d >= 0 && c.Meta != nil {
		c.Meta.Downloads = d
	}
	return ok
}

// metadataUnavailable returns one incomplete reason per metadata source that
// could not be read for some components (model.PackageMeta.Unavailable). The
// malicious-package and health indicators of these components rest on less
// data than the scan claims, so the analysis is incomplete; a source that
// does not know a package ("not found") is not a failure.
func metadataUnavailable(comps []*model.Component) []string {
	count, example := map[string]int{}, map[string]string{}
	for _, c := range comps {
		if c.Meta == nil {
			continue
		}
		for _, u := range c.Meta.Unavailable {
			src, msg, _ := strings.Cut(u, ": ")
			count[src]++
			if example[src] == "" {
				example[src] = msg
			}
		}
	}
	srcs := make([]string, 0, len(count))
	for s := range count {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	var out []string
	for _, s := range srcs {
		out = append(out, fmt.Sprintf("package metadata from %s unavailable for %d of %d components (%s)", s, count[s], len(comps), example[s]))
	}
	return out
}
