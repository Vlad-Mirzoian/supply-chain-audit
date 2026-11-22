// Package report is the output part of module M6: the JSON report, SARIF
// 2.1.0 for code-scanning dashboards, Markdown for pull requests, HTML, and
// the evidence bundle with hashes of all inputs and outputs.
package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/integrity"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/policy"
)

// Report is the complete result of one scan.
type Report struct {
	Tool    string    `json:"tool"`
	Version string    `json:"version"`
	Started time.Time `json:"started"`
	// EvaluatedAt is the evaluation time: the time against which release
	// ages, VEX statements and policy exceptions are judged (--now in a
	// reproducible run, else the start of the run).
	EvaluatedAt time.Time          `json:"evaluated_at"`
	DurationSec float64            `json:"duration_seconds"`
	Stages      map[string]float64 `json:"stage_seconds"`
	Project     Project            `json:"project"`
	Scope       ScopeInfo          `json:"scope"`
	Snapshot    string             `json:"data_snapshot"`
	// SnapshotSeal is the ID of the sealed snapshot an offline run used.
	SnapshotSeal string `json:"data_snapshot_seal,omitempty"`
	// TrustedRootCopy is set when --offline verified signatures against the
	// saved Sigstore trusted root, whose date and age a reader should see.
	TrustedRootCopy *integrity.RootCopy `json:"trusted_root_copy,omitempty"`
	Policy          PolicyInfo          `json:"policy"`
	Network         map[string]int64    `json:"network"`
	Stats           Stats               `json:"stats"`
	Findings        []*model.Finding    `json:"findings"`
	Scores          []*model.Score      `json:"scores"`
	TopDirect       []*model.Score      `json:"top_direct_dependencies"`
	Incomplete      []string            `json:"incomplete,omitempty"`
	Notes           []string            `json:"notes,omitempty"`
	Decision        policy.Decision     `json:"decision"`
	CRA             []CRACandidate      `json:"cra_article14_candidates"`
	Counters        map[string]int      `json:"counters"`
	// HashCheck counts the components by outcome of the lockfile hash check
	// (integrity.Hash* values), so that unchecked components are visible.
	HashCheck  map[string]int     `json:"hash_check"`
	Components []*model.Component `json:"components"`
	// Reachability is the package-level verdict for every component (yes/no).
	Reachability map[string]string `json:"reachability,omitempty"`
}

// PolicyInfo names the policy that a scan applied, so that a report shows
// whether the project's own rules were used.
type PolicyInfo struct {
	// Source is "built-in" or the policy file (relative to the project
	// directory when Discovered).
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
	// Discovered: the file was found in the project (.ssca/policy.yaml)
	// rather than given with --policy.
	Discovered bool `json:"discovered,omitempty"`
	// Forced: --policy builtin, the project's policy file (if any) was
	// deliberately not used.
	Forced bool `json:"forced,omitempty"`
}

// Describe is the one-line description used in the summaries.
func (p PolicyInfo) Describe() string {
	switch {
	case p.Forced:
		return "built-in default policy (--policy builtin)"
	case p.Source == "" || p.Source == "built-in":
		return "built-in default policy (the project has no .ssca/policy.yaml)"
	case p.Discovered:
		return p.Source + " (found in the project)"
	}
	return p.Source + " (--policy)"
}

// Project describes the audited project and its inputs.
type Project struct {
	Dir         string            `json:"dir"`
	Root        string            `json:"root"`
	Ecosystem   string            `json:"ecosystem"`
	Inputs      []string          `json:"inputs"`
	InputHashes map[string]string `json:"input_sha256"`
	CIFiles     []string          `json:"ci_files,omitempty"`
}

// ScopeInfo records which dependency scopes were analysed and how.
type ScopeInfo struct {
	// Graph is "all" (development and test dependencies included) or
	// "runtime" (--runtime-only).
	Graph string `json:"graph"`
	// Vulnerabilities is "runtime" (the default: vulnerabilities of
	// development and test dependencies are not reported) or "all"
	// (--include-dev).
	Vulnerabilities string `json:"vulnerabilities"`
	// DevHeuristics says whether metadata and malicious-package indicators
	// were computed for development and test dependencies.
	DevHeuristics bool `json:"dev_heuristics"`
}

// Stats summarises the graph.
type Stats struct {
	Components int            `json:"components"`
	Direct     int            `json:"direct"`
	Edges      int            `json:"edges"`
	MaxDepth   int            `json:"max_depth"`
	ByDepth    map[int]int    `json:"by_depth"`
	Cycles     int            `json:"cycles"`
	Conflicts  int            `json:"conflicts"`
	ByBand     map[string]int `json:"by_band"`
	ByScope    map[string]int `json:"by_scope"`
}

// CRACandidate is an actively exploited vulnerability in a shipped component
// (Cyber Resilience Act, Article 14).
type CRACandidate struct {
	Component string `json:"component"`
	Vuln      string `json:"vulnerability"`
	CVEs      string `json:"cves"`
	Reachable string `json:"reachable"`
}

// HashFile returns the SHA-256 of a file.
func HashFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------- SARIF

func level(sev string) string {
	switch sev {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	}
	return "note"
}

// SARIF renders findings as SARIF 2.1.0.
func (r *Report) SARIF() ([]byte, error) {
	type rule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Desc struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
		Props map[string]any `json:"properties"`
	}
	rules := map[string]*rule{}
	// SARIF 2.1.0 requires arrays: a run without findings has "results": []
	results := []map[string]any{}
	lockfile := "package.json"
	if len(r.Project.Inputs) > 0 {
		lockfile = r.Project.Inputs[0]
	}
	loc := newLocator(r.Project.Dir, r.Project.Inputs)
	comps := map[string]*model.Component{}
	for _, c := range r.Components {
		comps[c.PURL] = c
	}
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		rid := f.ID
		if f.Rule != "" && f.Kind != model.KindVulnerability {
			rid = "ssca/" + f.Rule
		}
		if _, ok := rules[rid]; !ok {
			x := &rule{ID: rid, Name: string(f.Kind)}
			x.Desc.Text = f.Title
			x.Props = map[string]any{"tags": []string{"supply-chain", string(f.Kind)}}
			if f.Vuln != nil {
				x.Props["security-severity"] = fmt.Sprintf("%.1f", f.Vuln.CVSS)
			}
			rules[rid] = x
		}
		uri, line := f.File, f.Line
		if uri == "" {
			uri, line = loc.find(comps[f.Component])
		}
		if uri == "" {
			uri = lockfile
		}
		if line < 1 {
			line = 1
		}
		msg := f.Title
		if f.Component != "" {
			msg = f.Component + ": " + msg
		}
		if f.Detail != "" {
			msg += " — " + f.Detail
		}
		res := map[string]any{
			"ruleId": rid, "level": level(f.Severity), "message": map[string]string{"text": msg},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": filepath.ToSlash(uri)},
				"region":           map[string]int{"startLine": line}}}},
			"partialFingerprints": map[string]string{"ssca/v1": fingerprint(rid, f.Component, f.File)},
		}
		results = append(results, res)
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rl := []*rule{}
	for _, id := range ids {
		rl = append(rl, rules[id])
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "ssca", "version": r.Version, "informationUri": model.HomeURL, "rules": rl}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:12])
}

// ---------------------------------------------------------------- Markdown

// Markdown renders a short summary for pull requests and CI job summaries.
func (r *Report) Markdown() string {
	var b strings.Builder
	icon := map[string]string{"PASS": "✅", "FAIL": "❌", "INCOMPLETE": "⚠️"}[r.Decision.Verdict]
	fmt.Fprintf(&b, "## %s ssca supply-chain audit: %s\n\n", icon, r.Decision.Verdict)
	fmt.Fprintf(&b, "Project %s (%s), %d components (%d direct, max depth %d), scanned in %.1f s. Data snapshot `%s`.\n\n",
		code(r.Project.Root), r.Project.Ecosystem, r.Stats.Components, r.Stats.Direct, r.Stats.MaxDepth, r.DurationSec, r.Snapshot)
	if r.TrustedRootCopy != nil {
		fmt.Fprintf(&b, "Sigstore trusted root: %s (--offline, not refreshed through TUF).\n\n", r.TrustedRootCopy)
	}
	fmt.Fprintf(&b, "Policy: %s.\n\n", r.Policy.Describe())
	fmt.Fprintf(&b, "| Band | Components |\n|---|---|\n")
	for _, band := range []string{"critical", "high", "medium", "low"} {
		fmt.Fprintf(&b, "| %s | %d |\n", band, r.Stats.ByBand[band])
	}
	if h := r.HashSummary(); h != "" {
		b.WriteString("\n" + h + "\n")
	}
	if len(r.Decision.Violations) > 0 {
		b.WriteString("\n### Policy violations (build blocked)\n\n| Rule | Component | Finding | Message |\n|---|---|---|---|\n")
		for _, v := range r.Decision.Violations {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", esc(ruleName(v)), code(v.Component), esc(v.Finding), esc(v.Message))
		}
	}
	if len(r.Decision.Warnings) > 0 {
		fmt.Fprintf(&b, "\n### Warnings (%d)\n\n", len(r.Decision.Warnings))
		for i, v := range r.Decision.Warnings {
			if i == 15 {
				fmt.Fprintf(&b, "- … %d more\n", len(r.Decision.Warnings)-15)
				break
			}
			fmt.Fprintf(&b, "- **%s** %s %s\n", esc(v.Rule), code(v.Component), esc(v.Message))
		}
	}
	if len(r.TopDirect) > 0 {
		b.WriteString("\n### Direct dependencies with the highest subtree risk\n\n| Direct dependency | Subtree risk | Worst path |\n|---|---|---|\n")
		for i, s := range r.TopDirect {
			if i == 5 || s.Subtree < 25 {
				break
			}
			fmt.Fprintf(&b, "| %s | %.1f | %s |\n", code(s.PURL), s.Subtree, esc(strings.Join(s.WorstPath, " → ")))
		}
	}
	b.WriteString(r.devMarkdown())
	if len(r.CRA) > 0 {
		b.WriteString("\n### CRA Article 14 candidates (actively exploited)\n\n")
		for _, c := range r.CRA {
			fmt.Fprintf(&b, "- %s %s (%s), reachable: %s\n", code(c.Component), esc(c.Vuln), esc(c.CVEs), esc(c.Reachable))
		}
	}
	for _, s := range CompactIncomplete(r.Incomplete, 5) {
		fmt.Fprintf(&b, "\n> incomplete: %s", esc(s))
	}
	b.WriteString("\n")
	return b.String()
}

// DevSection is what the reports say about development and test
// dependencies: how many there are, what was checked for them and the
// findings and scores that concern them.
type DevSection struct {
	Dev, Test, Extra int
	Heading          string
	Note             string
	Findings         []*model.Finding
	Scores           []*model.Score // medium band or higher
}

// Dev returns the development and test section, or nil when the graph has
// no such dependencies.
func (r *Report) Dev() *DevSection {
	d := &DevSection{}
	nonProd := map[string]bool{}
	for _, c := range r.Components {
		switch c.Scope {
		case model.ScopeDev:
			d.Dev++
		case model.ScopeTest:
			d.Test++
		case model.ScopeExtra:
			d.Extra++
		default:
			continue
		}
		nonProd[c.PURL] = true
	}
	if d.Dev+d.Test+d.Extra == 0 {
		return nil
	}
	d.Heading = "Development and test dependencies"
	if d.Extra > 0 {
		d.Heading = "Development, test and extra dependencies"
	}
	checks := "known-malicious versions, lockfile integrity and malicious-package indicators"
	if !r.Scope.DevHeuristics {
		checks = "known-malicious versions and lockfile integrity (malicious-package indicators disabled by the policy)"
	}
	d.Note = fmt.Sprintf("%d development and %d test dependencies are not shipped with the application but run on developer machines and in CI. Checked for them: %s", d.Dev, d.Test, checks)
	if d.Extra > 0 {
		d.Note = fmt.Sprintf("%d development and %d test dependencies are not shipped with the application but run on developer machines and in CI; %d packages are needed only by extras of the project, which are installed on request. Checked for them: %s", d.Dev, d.Test, d.Extra, checks)
	}
	if r.Scope.Vulnerabilities == "all" {
		d.Note += " and vulnerabilities (--include-dev)."
	} else {
		d.Note += "; vulnerabilities are not reported for them (--include-dev reports them"
		if n := r.Counters["dev_components_with_unreported_vulnerabilities"]; n > 0 {
			d.Note += fmt.Sprintf("; advisories exist for %d of them", n)
		}
		d.Note += ")."
	}
	for _, f := range r.Findings {
		if nonProd[f.Component] && !f.Suppressed {
			d.Findings = append(d.Findings, f)
		}
	}
	for _, s := range r.Scores {
		if nonProd[s.PURL] && model.SeverityRank(s.Band) >= model.SeverityRank(model.SevMedium) {
			d.Scores = append(d.Scores, s)
		}
	}
	return d
}

func (r *Report) devMarkdown() string {
	d := r.Dev()
	if d == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n### " + d.Heading + "\n\n" + d.Note + "\n")
	if len(d.Findings) > 0 {
		b.WriteString("\n| Severity | Finding | Component | Title |\n|---|---|---|---|\n")
		for i, f := range d.Findings {
			if i == 15 {
				fmt.Fprintf(&b, "| | … %d more | | |\n", len(d.Findings)-15)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.Severity, esc(f.ID), code(f.Component), esc(f.Title))
		}
	}
	if len(d.Scores) > 0 {
		b.WriteString("\n| Component | Scope | CRS | Band | Signals |\n|---|---|---|---|---|\n")
		for i, s := range d.Scores {
			if i == 10 {
				fmt.Fprintf(&b, "| … %d more | | | | |\n", len(d.Scores)-10)
				break
			}
			var sig []string
			for _, x := range s.Signals {
				sig = append(sig, x.Name)
			}
			if s.Override != "" {
				sig = append(sig, s.Override)
			}
			fmt.Fprintf(&b, "| %s | %s | %.1f | %s | %s |\n", code(s.PURL), s.Scope, s.CRS, s.Band, esc(strings.Join(sig, ", ")))
		}
	}
	if len(d.Findings) == 0 && len(d.Scores) == 0 {
		b.WriteString("\nNo findings and no component above the low band.\n")
	}
	return b.String()
}

// hashLabels describe the outcomes of the lockfile hash check, in the order
// in which the summary lists them.
var hashLabels = []struct{ status, label string }{
	{integrity.HashMismatch, "differ from the registry"},
	{integrity.HashUnavailable, "registry data unavailable"},
	{integrity.HashOtherSource, "not from the public registry"},
	{integrity.HashNoLockfile, "no hash in the lockfile"},
	{integrity.HashNoReference, "no registry hash of the same algorithm"},
	{integrity.HashNotFound, "version not on the registry"},
}

// HashSummary says for how many components the lockfile hash was compared
// with the registry, and why the others were not.
func (r *Report) HashSummary() string {
	if len(r.HashCheck) == 0 {
		return ""
	}
	total := 0
	for _, n := range r.HashCheck {
		total += n
	}
	s := fmt.Sprintf("Lockfile hashes: %d of %d components verified against the registry", r.HashCheck[integrity.HashVerified], total)
	var rest []string
	for _, l := range hashLabels {
		if n := r.HashCheck[l.status]; n > 0 {
			rest = append(rest, fmt.Sprintf("%d %s", n, l.label))
		}
	}
	if len(rest) > 0 {
		s += "; " + strings.Join(rest, ", ")
	}
	return s + "."
}

// esc makes text safe for a cell of a Markdown table and for a list item of
// the summary: a pipe would end the cell, a line break the row, and angle
// brackets would let a package name or an advisory title insert HTML into the
// job summary of the CI system.
func esc(s string) string {
	return mdText.Replace(s)
}

var mdText = strings.NewReplacer("|", "\\|", "\r\n", " ", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;")

// code is a value shown as inline code (purls, identifiers): inside a code
// span HTML is not interpreted, but a pipe still ends a table cell and a
// backtick would end the span, so the backticks are dropped.
func code(s string) string {
	return "`" + mdCode.Replace(s) + "`"
}

var mdCode = strings.NewReplacer("|", "\\|", "`", "", "\r\n", " ", "\n", " ", "\r", " ")

// ---------------------------------------------------------------- HTML

var page = template.Must(template.New("r").Funcs(template.FuncMap{
	"join": strings.Join, "f1": func(x float64) string { return fmt.Sprintf("%.1f", x) },
}).Parse(`<!doctype html><html><head><meta charset="utf-8"><title>ssca report</title>
<style>body{font:14px system-ui,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;margin:8px 0 20px}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}
th{background:#f3f3f3}.critical{color:#b00020;font-weight:600}.high{color:#c75300}.medium{color:#8a6d00}.low{color:#555}</style></head><body>
<h1>Supply-chain audit: {{.Decision.Verdict}}</h1>
<p>{{.Project.Root}} — {{.Stats.Components}} components, {{.Stats.Edges}} edges, max depth {{.Stats.MaxDepth}}; snapshot {{.Snapshot}}; {{f1 .DurationSec}} s.</p>
{{with .TrustedRootCopy}}<p>Sigstore trusted root: {{.}} (--offline, not refreshed through TUF)</p>{{end}}
<p>Policy: {{.Policy.Describe}}</p>
<p>{{.HashSummary}}</p>
<h2>Policy violations</h2><table><tr><th>Rule</th><th>Component</th><th>Finding</th><th>Message</th></tr>
{{range .Decision.Violations}}<tr><td>{{.Rule}}{{if .Baseline}} (baseline){{end}}</td><td>{{.Component}}</td><td>{{.Finding}}</td><td>{{.Message}}</td></tr>{{end}}</table>
<h2>Highest composite risk scores</h2><table><tr><th>Component</th><th>Scope</th><th>CRS</th><th>c</th><th>V</th><th>H</th><th>M</th><th>Signals</th></tr>
{{range $i, $s := .Scores}}{{if lt $i 40}}<tr><td>{{$s.PURL}}</td><td>{{$s.Scope}}</td><td class="{{$s.Band}}">{{f1 $s.CRS}}</td><td>{{f1 $s.C}}</td><td>{{printf "%.2f" $s.V}}</td><td>{{printf "%.2f" $s.H}}</td><td>{{printf "%.2f" $s.M}}</td>
<td>{{range $s.Signals}}{{.Reason}}<br>{{end}}{{$s.Override}}</td></tr>{{end}}{{end}}</table>
{{with .Dev}}<h2>{{.Heading}}</h2><p>{{.Note}}</p>
{{if .Findings}}<table><tr><th>Severity</th><th>ID</th><th>Component</th><th>Title</th></tr>
{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td>{{.ID}}</td><td>{{.Component}}</td><td>{{.Title}}</td></tr>{{end}}</table>{{end}}
{{if .Scores}}<table><tr><th>Component</th><th>Scope</th><th>CRS</th><th>Signals</th></tr>
{{range .Scores}}<tr><td>{{.PURL}}</td><td>{{.Scope}}</td><td class="{{.Band}}">{{f1 .CRS}}</td><td>{{range .Signals}}{{.Reason}}<br>{{end}}{{.Override}}</td></tr>{{end}}</table>{{end}}{{end}}
<h2>Findings</h2><table><tr><th>Severity</th><th>ID</th><th>Component / file</th><th>Title</th><th>Status</th></tr>
{{range .Findings}}<tr><td class="{{.Severity}}">{{.Severity}}</td><td>{{.ID}}</td><td>{{.Component}}{{.File}}</td><td>{{.Title}}</td><td>{{if .Suppressed}}suppressed: {{.Reason}}{{end}}{{if .Vuln}} reachable: {{.Vuln.Reachable}}{{end}}</td></tr>{{end}}</table>
</body></html>`))

// HTML renders a static HTML report.
func (r *Report) HTML() ([]byte, error) {
	var b bytes.Buffer
	err := page.Execute(&b, r)
	return b.Bytes(), err
}

// ---------------------------------------------------------------- evidence

// EvidenceFiles are the names of all files that a scan may write to the
// output directory. Files left from an earlier run are removed first, so that
// the directory never holds outputs that the manifest does not cover.
var EvidenceFiles = []string{"report.json", "findings.sarif", "summary.md", "report.html",
	"sbom.cdx.json", "sbom.spdx.json", "reachability.openvex.json", "manifest.json"}

// Evidence writes the evidence bundle: all outputs plus a manifest with the
// SHA-256 of every file, the input hashes and the data snapshot id. created
// is the time recorded in the manifest (the --now time in reproducible runs).
func (r *Report) Evidence(dir string, extra map[string][]byte, created time.Time) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, name := range EvidenceFiles {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	files := map[string][]byte{}
	for k, v := range extra {
		files[k] = v
	}
	var err error
	if files["report.json"], err = json.MarshalIndent(r, "", "  "); err != nil {
		return fmt.Errorf("report.json: %w", err)
	}
	if files["findings.sarif"], err = r.SARIF(); err != nil {
		return fmt.Errorf("findings.sarif: %w", err)
	}
	if files["report.html"], err = r.HTML(); err != nil {
		return fmt.Errorf("report.html: %w", err)
	}
	files["summary.md"] = []byte(r.Markdown())
	manifest := map[string]any{
		"tool": r.Tool, "version": r.Version, "created": created.UTC().Format(time.RFC3339),
		"data_snapshot": r.Snapshot, "inputs": r.Project.InputHashes, "verdict": r.Decision.Verdict,
		"policy": r.Policy,
	}
	if r.SnapshotSeal != "" {
		manifest["data_snapshot_seal"] = r.SnapshotSeal
	}
	hashes := map[string]string{}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
		h := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(h[:])
	}
	manifest["files"] = hashes
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), mb, 0o644)
}

// ruleName names the rule of a violation; a baseline rule, which applies
// whatever the policy file says, is marked as such.
func ruleName(v policy.Violation) string {
	if v.Baseline {
		return v.Rule + " (baseline)"
	}
	return v.Rule
}
