// Package policy evaluates the declarative policy file:
// band thresholds, rules written as boolean expressions over findings and
// components, and time-limited exceptions that must carry a reason.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/types"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

// Rule is one policy rule.
type Rule struct {
	ID     string `yaml:"id"`
	When   string `yaml:"when"`
	Action string `yaml:"action"` // fail, warn, info
	prog   *vm.Program
	roots  map[string]bool
}

// Exception suppresses a rule result for one component until it expires.
type Exception struct {
	Component string `yaml:"component"`
	Finding   string `yaml:"finding"`
	Rule      string `yaml:"rule"`
	Reason    string `yaml:"reason"`
	Expires   string `yaml:"expires"`
}

// Policy is the parsed policy file.
type Policy struct {
	Version int `yaml:"version"`
	// Extends: "builtin" makes the file a change of the built-in policy
	// instead of its replacement: the built-in rules apply except those in
	// Disable, a rule of the file replaces the built-in rule of the same id,
	// and thresholds the file does not set keep their built-in values.
	Extends    string   `yaml:"extends"`
	Disable    []string `yaml:"disable"`
	Ecosystems []string `yaml:"ecosystems"`
	// DataSnapshot requires a sealed data snapshot: "sealed" (any seal) or
	// "sha256:<seal id>" (this one); the run must then be offline on it, and
	// every file it reads is checked against the seal (exit code 4 if not).
	DataSnapshot string `yaml:"data_snapshot"`
	Thresholds   struct {
		FailOnBand         string `yaml:"fail_on_band"`
		WarnOnBand         string `yaml:"warn_on_band"`
		IncompleteAnalysis string `yaml:"incomplete_analysis"`
		// UnpinnedDependencies decides about PyPI dependencies that come
		// from manifests without a lockfile (versions resolved at the run,
		// no hashes pinned by the project): "warn" (default) only warns,
		// "fail" makes the analysis incomplete, as npm without a lockfile.
		UnpinnedDependencies string `yaml:"unpinned_dependencies"`
	} `yaml:"thresholds"`
	Rules             []*Rule           `yaml:"rules"`
	Exceptions        []Exception       `yaml:"exceptions"`
	Weights           risk.Weights      `yaml:"weights"`
	Internal          risk.Internal     `yaml:"internal"`
	RequireProvenance map[string]string `yaml:"require_provenance"`
	// TrustedBuilders are the SLSA builder IDs whose provenance is accepted
	// (an entry ending in "/" is a prefix); empty means the GitHub-hosted
	// and GitLab.com runners.
	TrustedBuilders []string `yaml:"trusted_builders"`
	// Registries are npm registry mirrors (URL prefixes) that serve the
	// packages of the public registry; lockfile entries downloaded from them
	// are not reported as coming from outside the registry.
	Registries   []string `yaml:"registries"`
	VEX          []string `yaml:"vex"`
	Reachability bool     `yaml:"reachability"`
	Provenance   *bool    `yaml:"verify_provenance"`
	// DevHeuristics (default true) collects registry metadata and computes
	// the malicious-package indicators for development and test dependencies
	// too; false limits them to the production scopes. Known-malicious
	// versions and lockfile integrity are checked in every scope regardless.
	DevHeuristics *bool `yaml:"dev_heuristics"`
	baseline      []*Rule
}

// Baseline holds the rules that every policy applies, whatever its file
// says. The policy file is part of the project, so the pull request that adds
// a known-malicious or tampered package can also remove the rule that would
// stop it. A policy can still accept one result with an exception, which
// needs a reason and an expiry date and is listed in the report. A baseline
// rule adds a violation only for a finding that no rule of the policy failed
// or excepted, so a policy that keeps these rules (the built-in one does) is
// evaluated as before.
const Baseline = `- id: known-malicious
  when: vuln.id startswith 'MAL-'
  action: fail
- id: integrity-failure
  when: finding.kind == 'integrity' or finding.rule == 'provenance-invalid'
  action: fail
- id: exploited-in-runtime
  when: vuln.kev == true and component.production and not vuln.suppressed
  action: fail
`

// Default is used when no policy file is given. It contains the rules of
// the example policy of the thesis (thresholds, known-malicious,
// exploited-in-runtime, provenance-regression, provenance-missing, cooldown,
// unpinned-ci-action) and six more: critical-reachable-cve,
// integrity-failure, unsigned-artifact, dependency-confusion (fail),
// untrusted-builder and provenance-unavailable (warn).
const Default = `thresholds:
  fail_on_band: critical
  warn_on_band: high
  incomplete_analysis: fail
rules:
  - id: known-malicious
    when: vuln.id startswith 'MAL-'
    action: fail
  - id: exploited-in-runtime
    when: vuln.kev == true and component.production and not vuln.suppressed
    action: fail
  - id: critical-reachable-cve
    when: vuln.severity == 'critical' and vuln.reachable != 'no' and component.production and not vuln.suppressed
    action: fail
  - id: integrity-failure
    when: finding.kind == 'integrity' or finding.rule == 'provenance-invalid'
    action: fail
  - id: unsigned-artifact
    when: finding.rule == 'unsigned-artifact' or finding.rule == 'unexpected-source'
    action: fail
  - id: untrusted-builder
    when: finding.rule == 'untrusted-builder'
    action: warn
  - id: provenance-unavailable
    when: finding.rule == 'provenance-unavailable'
    action: warn
  - id: dependency-confusion
    when: signals.dependency_confusion == true
    action: fail
  - id: provenance-regression
    when: signals.provenance_regression == true and (signals.publisher_changed == true or signals.install_script_added == true or signals.young_new_dependency == true)
    action: fail
  - id: provenance-missing
    when: signals.provenance_regression == true and signals.publisher_changed != true and signals.install_script_added != true and signals.young_new_dependency != true
    action: warn
  - id: cooldown
    when: component.release_age_days < 7
    action: warn
  - id: unpinned-ci-action
    when: ci.action_ref_type != 'sha'
    action: warn
`

var (
	rootRe = regexp.MustCompile(`\b(vuln|component|signals|signal_values|ci|finding)\b`)
	// refRe marks rules about action references: they apply only to the CI
	// findings that concern an action reference (unpinned-action)
	refRe = regexp.MustCompile(`\bci\.action_ref_type\b`)
	// string literals of a condition; a root name inside one ("... contains
	// 'vuln'") does not make the rule depend on that context
	literalRe = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)
)

// rootsOf returns the contexts a condition reads.
func rootsOf(cond string) map[string]bool {
	code := literalRe.ReplaceAllString(cond, "''")
	roots := map[string]bool{}
	for _, m := range rootRe.FindAllString(code, -1) {
		roots[m] = true
	}
	if refRe.MatchString(code) {
		roots[actionRef] = true
	}
	return roots
}

// actionRef is the pseudo-context of the findings that carry an action
// reference type.
const actionRef = "ci.action_ref_type"

// Schema lists every field a rule condition may reference, with its type. It
// must be kept in step with the environments built in Evaluate. Conditions are
// type-checked against it, so that a misspelt field is a load error instead of
// a rule that silently never fires.
func Schema() types.Map {
	sig, val := types.Map{"typosquat": types.Bool}, types.Map{"typosquat": types.Float64}
	for name := range risk.DefaultWeights().Signals {
		sig[name], val[name] = types.Bool, types.Float64
	}
	return types.Map{
		"finding": types.Map{"id": types.String, "kind": types.String, "rule": types.String,
			"severity": types.String, "title": types.String, "suppressed": types.Bool},
		"component": types.Map{"purl": types.String, "name": types.String, "ecosystem": types.String,
			"version": types.String, "scope": types.String, "production": types.Bool, "direct": types.Bool, "depth": types.Int,
			"release_age_days": types.Float64, "crs": types.Float64, "band": types.String, "subtree_risk": types.Float64,
			"hash_check": types.String},
		"vuln": types.Map{"id": types.String, "aliases": types.Array(types.String), "cvss": types.Float64,
			"epss": types.Float64, "kev": types.Bool, "severity": types.String, "reachable": types.String,
			"suppressed": types.Bool, "fixed": types.Bool},
		"ci":            types.Map{"rule": types.String, "action_ref_type": types.String, "file": types.String},
		"signals":       sig,
		"signal_values": val,
	}
}

// Load reads a policy file; an empty path loads the default policy.
func Load(path string) (*Policy, error) {
	src := []byte(Default)
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		src = b
	}
	p, err := decode(src)
	if err != nil {
		return nil, err
	}
	if p.Extends != "" || len(p.Disable) > 0 {
		if err := p.inherit(); err != nil {
			return nil, err
		}
	}
	for key, band := range map[string]*string{"fail_on_band": &p.Thresholds.FailOnBand, "warn_on_band": &p.Thresholds.WarnOnBand} {
		// "none" switches the band rule off, also against an inherited value
		if *band == "none" {
			*band = ""
		}
		if *band != "" && model.SeverityRank(*band) == 0 {
			return nil, fmt.Errorf("policy: thresholds.%s: unknown band %q (critical, high, medium, low or none)", key, *band)
		}
	}
	if d := p.DataSnapshot; d != "" && d != "sealed" && !(strings.HasPrefix(d, "sha256:") && len(d) > len("sha256:")) {
		return nil, fmt.Errorf("policy: data_snapshot: unknown value %q (sealed or sha256:<seal id>)", d)
	}
	switch p.Thresholds.IncompleteAnalysis {
	case "", "fail", "warn":
	default:
		return nil, fmt.Errorf("policy: thresholds.incomplete_analysis: unknown value %q (fail or warn)", p.Thresholds.IncompleteAnalysis)
	}
	switch p.Thresholds.UnpinnedDependencies {
	case "", "fail", "warn":
	default:
		return nil, fmt.Errorf("policy: thresholds.unpinned_dependencies: unknown value %q (fail or warn)", p.Thresholds.UnpinnedDependencies)
	}
	for _, r := range p.Registries {
		if u, err := url.Parse(r); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("policy: registries: %q is not an http(s) URL", r)
		}
	}
	def := risk.DefaultWeights()
	for name := range p.Weights.Signals {
		if _, ok := def.Signals[name]; !ok {
			return nil, fmt.Errorf("policy: weights.signals: unknown signal %q", name)
		}
	}
	for name := range p.Weights.Health {
		if _, ok := def.Health[name]; !ok {
			return nil, fmt.Errorf("policy: weights.health: unknown indicator %q", name)
		}
	}
	if p.Weights.HealthFactor == 0 {
		p.Weights.HealthFactor = def.HealthFactor
	}
	if p.Weights.TyposquatFactor == 0 {
		p.Weights.TyposquatFactor = def.TyposquatFactor
	}
	if p.Weights.CooldownDays == 0 {
		p.Weights.CooldownDays = def.CooldownDays
	}
	if p.Weights.Signals == nil {
		p.Weights.Signals = def.Signals
	}
	if p.Weights.Health == nil {
		p.Weights.Health = def.Health
	}
	if p.Thresholds.IncompleteAnalysis == "" {
		p.Thresholds.IncompleteAnalysis = "fail"
	}
	if p.Thresholds.UnpinnedDependencies == "" {
		p.Thresholds.UnpinnedDependencies = "warn"
	}
	if err := compileRules(p.Rules); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal([]byte(Baseline), &p.baseline); err != nil {
		return nil, fmt.Errorf("baseline policy: %w", err)
	}
	if err := compileRules(p.baseline); err != nil {
		return nil, fmt.Errorf("baseline %w", err)
	}
	for _, e := range p.Exceptions {
		if strings.TrimSpace(e.Component+e.Finding+e.Rule) == "" {
			// it would suppress every violation of every rule
			return nil, fmt.Errorf("policy: an exception must name a component, a finding or a rule (reason %q)", e.Reason)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("policy: exception for %s has no reason", e.Component)
		}
		if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
			return nil, fmt.Errorf("policy: exception for %s needs an expiry date (YYYY-MM-DD)", e.Component)
		}
	}
	// VEX documents named by a policy file are resolved relative to that
	// file, so that the policy works whatever the working directory is
	// (a discovered .ssca/policy.yaml names .ssca/vex/x.json as vex/x.json)
	if path != "" {
		for i, v := range p.VEX {
			if !filepath.IsAbs(v) {
				p.VEX[i] = filepath.Join(filepath.Dir(path), v)
			}
		}
	}
	return p, nil
}

// decode parses a policy document; a misspelt key (e.g. "treshholds") is an
// error, not ignored.
func decode(src []byte) (*Policy, error) {
	p := &Policy{}
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(p); err != nil {
		if errors.Is(err, io.EOF) {
			err = errors.New("empty policy file")
		}
		return nil, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

// baselineIDs are the ids of the Baseline rules.
var baselineIDs = []string{"known-malicious", "integrity-failure", "exploited-in-runtime"}

// inherit applies extends: builtin and disable. The rules are those of the
// built-in policy without the disabled ones, with a rule of the file in
// place of the built-in rule of the same id, followed by the other rules of
// the file; a threshold the file does not set keeps its built-in value. The
// built-in policy sets nothing else, so every other key is the file's.
func (p *Policy) inherit() error {
	switch p.Extends {
	case Builtin:
	case "":
		return errors.New("policy: disable needs extends: builtin (a policy file without it replaces the built-in policy, so it lists the rules that apply)")
	default:
		return fmt.Errorf("policy: extends: unknown value %q (builtin)", p.Extends)
	}
	base, err := decode([]byte(Default))
	if err != nil {
		return fmt.Errorf("built-in %w", err)
	}
	own, builtin := map[string]*Rule{}, map[string]bool{}
	for _, r := range p.Rules {
		if own[r.ID] != nil {
			return fmt.Errorf("policy: rule %s is defined twice", r.ID)
		}
		own[r.ID] = r
	}
	var ids []string
	for _, r := range base.Rules {
		builtin[r.ID] = true
		ids = append(ids, r.ID)
	}
	off := map[string]bool{}
	for _, id := range p.Disable {
		switch {
		case slices.Contains(baselineIDs, id):
			return fmt.Errorf("policy: disable: %s is a baseline rule, which every policy applies", id)
		case own[id] != nil:
			return fmt.Errorf("policy: disable: %s is a rule of this file", id)
		case !builtin[id]:
			return fmt.Errorf("policy: disable: %q is not a rule of the built-in policy (%s)", id, strings.Join(ids, ", "))
		}
		off[id] = true
	}
	var rules []*Rule
	for _, r := range base.Rules {
		switch {
		case off[r.ID]:
		case own[r.ID] != nil:
			rules = append(rules, own[r.ID])
		default:
			rules = append(rules, r)
		}
	}
	for _, r := range p.Rules {
		if !builtin[r.ID] {
			rules = append(rules, r)
		}
	}
	p.Rules = rules
	t, bt := &p.Thresholds, base.Thresholds
	for _, x := range []struct{ v, def *string }{
		{&t.FailOnBand, &bt.FailOnBand}, {&t.WarnOnBand, &bt.WarnOnBand},
		{&t.IncompleteAnalysis, &bt.IncompleteAnalysis}, {&t.UnpinnedDependencies, &bt.UnpinnedDependencies},
	} {
		if *x.v == "" {
			*x.v = *x.def
		}
	}
	return nil
}

// compileRules checks the rules and compiles their conditions.
func compileRules(rules []*Rule) error {
	env := Schema()
	for _, r := range rules {
		if r.ID == "" || r.When == "" {
			return fmt.Errorf("policy: rule without id or condition")
		}
		switch r.Action {
		case "fail", "warn", "info":
		default:
			return fmt.Errorf("policy: rule %s: unknown action %q", r.ID, r.Action)
		}
		cond := strings.ReplaceAll(r.When, " startswith ", " startsWith ")
		prog, err := expr.Compile(cond, expr.Env(env), expr.AsBool())
		if err != nil {
			return fmt.Errorf("policy: rule %s: %w", r.ID, err)
		}
		r.prog = prog
		r.roots = rootsOf(r.When)
	}
	return nil
}

// ProjectFiles are the policy files that a scan uses when no policy is given
// on the command line, relative to the project directory, in this order.
var ProjectFiles = []string{".ssca/policy.yaml", ".ssca/policy.yml"}

// Builtin is the --policy value that selects the built-in policy even when
// the project has a policy file.
const Builtin = "builtin"

// Find selects the policy file of a scan: an explicit path (flag), the
// built-in policy (flag == Builtin, result ""), or else the first of
// ProjectFiles that exists in dir ("" if none: the built-in policy).
// discovered reports that the file was found in the project.
func Find(dir, flag string) (path string, discovered bool) {
	switch flag {
	case Builtin:
		return "", false
	case "":
		for _, f := range ProjectFiles {
			p := filepath.Join(dir, f)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, true
			}
		}
		return "", false
	}
	return flag, false
}

// Violation is one triggered rule.
type Violation struct {
	Rule      string `json:"rule"`
	Action    string `json:"action"`
	Component string `json:"component,omitempty"`
	Finding   string `json:"finding,omitempty"`
	Message   string `json:"message"`
	Excepted  string `json:"excepted,omitempty"`
	// Baseline marks a violation of a baseline rule that the policy file
	// left out or weakened.
	Baseline bool `json:"baseline,omitempty"`
}

// Decision is the result of policy evaluation.
type Decision struct {
	Violations []Violation `json:"violations"`
	Warnings   []Violation `json:"warnings"`
	Excepted   []Violation `json:"excepted,omitempty"`
	Incomplete bool        `json:"incomplete"`
	// Errors lists rule conditions that could not be evaluated; they make the
	// decision incomplete instead of counting as "not violated".
	Errors   []string `json:"errors,omitempty"`
	ExitCode int      `json:"exit_code"`
	Verdict  string   `json:"verdict"`
}

// Subject is everything the policy can see.
type Subject struct {
	Graph      *model.Graph
	Findings   []*model.Finding
	Scores     map[string]*model.Score
	Incomplete []string
	Now        time.Time
}

func componentEnv(c *model.Component, s *model.Score, now time.Time) map[string]any {
	m := map[string]any{
		"purl": c.PURL, "name": c.FullName(), "ecosystem": c.Ecosystem, "version": c.Version,
		"scope": string(c.Scope), "production": c.Scope.Production(), "direct": c.Direct, "depth": c.Depth, "release_age_days": 1e9,
		"hash_check": c.HashCheck,
	}
	if c.Meta != nil && !c.Meta.PublishedAt.IsZero() {
		m["release_age_days"] = now.Sub(c.Meta.PublishedAt).Hours() / 24
	}
	if s != nil {
		m["crs"], m["band"], m["subtree_risk"] = s.CRS, s.Band, s.Subtree
	}
	return m
}

func signalEnv(s *model.Score) (map[string]any, map[string]any) {
	b, v := map[string]any{}, map[string]any{}
	if s == nil {
		return b, v
	}
	for _, sg := range s.Signals {
		b[sg.Name] = true
		v[sg.Name] = sg.Value
	}
	return b, v
}

// Evaluate applies the policy.
func (p *Policy) Evaluate(sub Subject) Decision {
	// empty lists rather than null in report.json
	d := Decision{Violations: []Violation{}, Warnings: []Violation{}}
	now := sub.Now
	run := func(r *Rule, env map[string]any, subject string) bool {
		out, err := expr.Run(r.prog, env)
		if err != nil {
			d.Errors = append(d.Errors, fmt.Sprintf("rule %s on %s: %v", r.ID, subject, err))
			return false
		}
		return out == true
	}
	// record files a triggered rule; it reports whether the result is
	// settled (a violation or an exception)
	record := func(r *Rule, comp, finding, msg string, baseline bool) bool {
		v := Violation{Rule: r.ID, Action: r.Action, Component: comp, Finding: finding, Message: msg, Baseline: baseline}
		if ex := p.exception(comp, finding, r.ID, now); ex != "" {
			v.Excepted = ex
			d.Excepted = append(d.Excepted, v)
			return true
		}
		switch r.Action {
		case "fail":
			d.Violations = append(d.Violations, v)
			return true
		case "warn":
			d.Warnings = append(d.Warnings, v)
		}
		return false
	}
	// finding contexts
	for _, f := range sub.Findings {
		env := map[string]any{"finding": map[string]any{"id": f.ID, "kind": string(f.Kind), "rule": f.Rule, "severity": f.Severity, "title": f.Title, "suppressed": f.Suppressed}}
		has := map[string]bool{"finding": true}
		if f.Component != "" {
			if c := sub.Graph.Nodes[f.Component]; c != nil {
				env["component"] = componentEnv(c, sub.Scores[c.PURL], now)
				env["signals"], env["signal_values"] = signalEnv(sub.Scores[c.PURL])
				has["component"], has["signals"], has["signal_values"] = true, true, true
			}
		}
		if f.Vuln != nil {
			v := f.Vuln
			env["vuln"] = map[string]any{"id": v.ID, "aliases": v.Aliases, "cvss": v.CVSS, "epss": v.EPSS, "kev": v.KEV,
				"severity": f.Severity, "reachable": v.Reachable, "suppressed": f.Suppressed, "fixed": len(v.Fixed) > 0}
			has["vuln"] = true
		}
		if f.Kind == model.KindCI {
			// action_ref_type exists only for findings about an action
			// reference; rules that read it are not applied to the others
			ref, _ := f.Evidence["action_ref_type"].(string)
			env["ci"] = map[string]any{"rule": f.Rule, "action_ref_type": ref, "file": f.File}
			has["ci"], has[actionRef] = true, ref != ""
		}
		settled := false
		for _, r := range p.Rules {
			if !covers(r.roots, has) || onlyComponent(r.roots) {
				continue
			}
			if run(r, env, f.ID) && record(r, f.Component, f.ID, f.Title, false) {
				settled = true
			}
		}
		for _, r := range p.baseline {
			if settled || !covers(r.roots, has) {
				continue
			}
			if run(r, env, f.ID) {
				settled = record(r, f.Component, f.ID, f.Title, true)
			}
		}
	}
	// component contexts (rules that look only at components and signals)
	for _, c := range sub.Graph.Components() {
		s := sub.Scores[c.PURL]
		env := map[string]any{"component": componentEnv(c, s, now)}
		env["signals"], env["signal_values"] = signalEnv(s)
		for _, r := range p.Rules {
			if !onlyComponent(r.roots) {
				continue
			}
			if run(r, env, c.PURL) {
				record(r, c.PURL, "", signalMessage(r, s), false)
			}
		}
		if s != nil {
			if p.Thresholds.FailOnBand != "" && model.SeverityRank(s.Band) >= model.SeverityRank(p.Thresholds.FailOnBand) {
				record(&Rule{ID: "band-" + p.Thresholds.FailOnBand, Action: "fail"}, c.PURL, "", fmt.Sprintf("CRS %.1f (%s)", s.CRS, s.Band), false)
			} else if p.Thresholds.WarnOnBand != "" && model.SeverityRank(s.Band) >= model.SeverityRank(p.Thresholds.WarnOnBand) {
				record(&Rule{ID: "band-" + p.Thresholds.WarnOnBand, Action: "warn"}, c.PURL, "", fmt.Sprintf("CRS %.1f (%s)", s.CRS, s.Band), false)
			}
		}
	}
	// an expired exception no longer applies; it is listed as a warning so
	// that the owner renews or removes it (it does not make the analysis
	// incomplete: the results it covered are evaluated as usual)
	for _, e := range p.Expired(now) {
		what := e.Rule
		if what == "" {
			what = "all rules"
		} else {
			what = "rule " + what
		}
		d.Warnings = append(d.Warnings, Violation{Rule: "exception-expired", Action: "warn", Component: e.Component, Finding: e.Finding,
			Message: fmt.Sprintf("exception for %s expired on %s (%s)", what, e.Expires, e.Reason)})
	}
	sortV := func(v []Violation) {
		sort.Slice(v, func(i, j int) bool {
			if v[i].Rule != v[j].Rule {
				return v[i].Rule < v[j].Rule
			}
			return v[i].Component+v[i].Finding < v[j].Component+v[j].Finding
		})
	}
	sortV(d.Violations)
	sortV(d.Warnings)
	sort.Strings(d.Errors)
	d.Incomplete = len(sub.Incomplete) > 0 || len(d.Errors) > 0
	switch {
	case len(d.Violations) > 0:
		d.ExitCode, d.Verdict = 1, "FAIL"
	case d.Incomplete && p.Thresholds.IncompleteAnalysis == "fail":
		d.ExitCode, d.Verdict = 2, "INCOMPLETE"
	default:
		d.ExitCode, d.Verdict = 0, "PASS"
	}
	return d
}

func covers(roots, has map[string]bool) bool {
	for r := range roots {
		if !has[r] {
			return false
		}
	}
	return true
}

func onlyComponent(roots map[string]bool) bool {
	for r := range roots {
		if r != "component" && r != "signals" && r != "signal_values" {
			return false
		}
	}
	return len(roots) > 0
}

func (p *Policy) exception(comp, finding, rule string, now time.Time) string {
	for _, e := range p.Exceptions {
		exp, _ := time.Parse("2006-01-02", e.Expires)
		if now.After(exp.Add(24 * time.Hour)) {
			continue // expired exceptions no longer apply
		}
		if e.Component != "" && !(comp == e.Component || strings.HasPrefix(comp, e.Component+"@")) {
			continue
		}
		if e.Finding != "" && e.Finding != finding {
			continue
		}
		if e.Rule != "" && e.Rule != rule {
			continue
		}
		return e.Reason + " (until " + e.Expires + ")"
	}
	return ""
}

// Expired lists exceptions whose expiry date has passed.
func (p *Policy) Expired(now time.Time) []Exception {
	var out []Exception
	for _, e := range p.Exceptions {
		exp, _ := time.Parse("2006-01-02", e.Expires)
		if now.After(exp.Add(24 * time.Hour)) {
			out = append(out, e)
		}
	}
	return out
}

// signalMessage explains a component rule by the reasons of the signals that
// its condition names and that the component raised (a rule that combines
// several signals lists all of them); without such a signal the message is
// the rule id.
func signalMessage(r *Rule, s *model.Score) string {
	if s == nil || !r.roots["signals"] {
		return r.ID
	}
	var reasons []string
	for _, sg := range s.Signals {
		if regexp.MustCompile(`\bsignals\.` + regexp.QuoteMeta(sg.Name) + `\b`).MatchString(r.When) {
			reasons = append(reasons, sg.Reason)
		}
	}
	if len(reasons) == 0 {
		return r.ID
	}
	return strings.Join(reasons, "; ")
}
