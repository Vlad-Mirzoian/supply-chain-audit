package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// ---------------------------------------------------------------- VEX

// Statement is one normalised VEX statement.
type Statement struct {
	Vulnerability string
	// Aliases are further identifiers of the vulnerability (OpenVEX
	// vulnerability.aliases); the statement matches a finding through any of
	// them.
	Aliases  []string
	Products []string // purls (or CycloneDX bom-refs)
	// Subcomponents are the components of a product that the statement is
	// about (OpenVEX); when present, they are matched instead of Products.
	Subcomponents []string
	Status        string // not_affected, affected, fixed, under_investigation
	Justification string
	Source        string
	// Time is when the statement was made (statement timestamp, else the
	// document timestamp; zero when the document gives none). Seq is the
	// position among all loaded statements. The latest statement about a
	// vulnerability in a component decides its status.
	Time time.Time
	Seq  int
}

// VEX status values (OpenVEX) and the justification labels of the two
// formats. A not_affected statement must give a justification or an impact
// statement (OpenVEX 0.2.0) or, in CycloneDX, a justification or detail.
var (
	vexStatuses = map[string]bool{"not_affected": true, "affected": true, "fixed": true, "under_investigation": true}

	openVEXJustifications = map[string]bool{
		"component_not_present": true, "vulnerable_code_not_present": true,
		"vulnerable_code_not_in_execute_path":               true,
		"vulnerable_code_cannot_be_controlled_by_adversary": true,
		"inline_mitigations_already_exist":                  true,
	}

	cdxStates = map[string]string{
		"not_affected": "not_affected", "false_positive": "not_affected",
		"resolved": "fixed", "resolved_with_pedigree": "fixed",
		"exploitable": "affected", "in_triage": "under_investigation",
	}
	cdxJustifications = map[string]bool{
		"code_not_present": true, "code_not_reachable": true, "requires_configuration": true,
		"requires_dependency": true, "requires_environment": true, "protected_by_compiler": true,
		"protected_at_runtime": true, "protected_at_perimeter": true, "protected_by_mitigating_control": true,
	}
)

// parseVEXTime reads an optional RFC 3339 timestamp.
func parseVEXTime(s, what string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: invalid timestamp %q", what, s)
	}
	return t, nil
}

// LoadVEX reads OpenVEX or CycloneDX VEX documents. A document is rejected
// (the caller treats this as a usage error) when a statement names no
// product, since applying it to every component would suppress the
// vulnerability everywhere; when a status is missing or unknown; when a
// not_affected statement gives no reason or an unknown justification label;
// and when a timestamp cannot be read.
func LoadVEX(paths []string) ([]Statement, error) {
	type product struct {
		ID          string `json:"@id"`
		Identifiers struct {
			PURL string `json:"purl"`
		} `json:"identifiers"`
	}
	ref := func(p product) string {
		if p.Identifiers.PURL != "" {
			return p.Identifiers.PURL
		}
		return p.ID
	}
	var out []Statement
	add := func(st Statement) {
		st.Seq = len(out)
		out = append(out, st)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var probe map[string]any
		if err := json.Unmarshal(b, &probe); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if _, ok := probe["statements"]; ok {
			var doc struct {
				Timestamp  string `json:"timestamp"`
				Statements []struct {
					Vulnerability struct {
						Name    string   `json:"name"`
						ID      string   `json:"@id"`
						Aliases []string `json:"aliases"`
					} `json:"vulnerability"`
					Products []struct {
						product
						Subcomponents []product `json:"subcomponents"`
					} `json:"products"`
					Status        string `json:"status"`
					Justification string `json:"justification"`
					Impact        string `json:"impact_statement"`
					Timestamp     string `json:"timestamp"`
				} `json:"statements"`
			}
			if err := json.Unmarshal(b, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			docTime, err := parseVEXTime(doc.Timestamp, p)
			if err != nil {
				return nil, err
			}
			for i, s := range doc.Statements {
				st := Statement{Vulnerability: s.Vulnerability.Name, Aliases: s.Vulnerability.Aliases,
					Status: s.Status, Justification: s.Justification, Source: p, Time: docTime}
				if st.Vulnerability == "" {
					st.Vulnerability = s.Vulnerability.ID
				}
				where := fmt.Sprintf("%s: statement %d (%s)", p, i+1, st.Vulnerability)
				if st.Vulnerability == "" && len(st.Aliases) == 0 {
					return nil, fmt.Errorf("%s names no vulnerability", where)
				}
				if s.Timestamp != "" {
					if st.Time, err = parseVEXTime(s.Timestamp, where); err != nil {
						return nil, err
					}
				}
				switch {
				case s.Status == "":
					return nil, fmt.Errorf("%s has no status", where)
				case !vexStatuses[s.Status]:
					return nil, fmt.Errorf("%s has unknown status %q (want not_affected, affected, fixed or under_investigation)", where, s.Status)
				}
				if s.Status == "not_affected" {
					if s.Justification == "" && strings.TrimSpace(s.Impact) == "" {
						return nil, fmt.Errorf("%s: not_affected needs a justification or an impact_statement", where)
					}
					if s.Justification != "" && !openVEXJustifications[s.Justification] {
						return nil, fmt.Errorf("%s has unknown justification %q", where, s.Justification)
					}
				}
				if st.Justification == "" {
					st.Justification = s.Impact
				}
				for _, pr := range s.Products {
					st.Products = append(st.Products, ref(pr.product))
					for _, sc := range pr.Subcomponents {
						st.Subcomponents = append(st.Subcomponents, ref(sc))
					}
				}
				if len(st.Products) == 0 {
					return nil, fmt.Errorf("%s names no product", where)
				}
				add(st)
			}
			continue
		}
		// CycloneDX VEX
		var cdx struct {
			Metadata struct {
				Timestamp string `json:"timestamp"`
			} `json:"metadata"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Updated  string `json:"updated"`
				Analysis *struct {
					State         string `json:"state"`
					Justification string `json:"justification"`
					Detail        string `json:"detail"`
					LastUpdated   string `json:"lastUpdated"`
				} `json:"analysis"`
				Affects []struct {
					Ref string `json:"ref"`
				} `json:"affects"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &cdx); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		docTime, err := parseVEXTime(cdx.Metadata.Timestamp, p)
		if err != nil {
			return nil, err
		}
		for _, v := range cdx.Vulnerabilities {
			where := fmt.Sprintf("%s: vulnerability %s", p, v.ID)
			// a vulnerability without an analysis (as listed by a scanner
			// in a BOM) states nothing about exploitability
			if v.Analysis == nil {
				continue
			}
			a := v.Analysis
			status, ok := cdxStates[a.State]
			if !ok {
				if a.State == "" {
					return nil, fmt.Errorf("%s: analysis has no state", where)
				}
				return nil, fmt.Errorf("%s has unknown analysis state %q", where, a.State)
			}
			st := Statement{Vulnerability: v.ID, Status: status, Justification: a.Justification, Source: p, Time: docTime}
			if a.Justification != "" && !cdxJustifications[a.Justification] {
				return nil, fmt.Errorf("%s has unknown justification %q", where, a.Justification)
			}
			switch {
			case a.State == "false_positive" && st.Justification == "":
				st.Justification = "false_positive"
			case a.State == "not_affected" && st.Justification == "":
				if strings.TrimSpace(a.Detail) == "" {
					return nil, fmt.Errorf("%s: not_affected needs a justification or a detail", where)
				}
				st.Justification = a.Detail
			}
			for _, t := range []string{v.Updated, a.LastUpdated} {
				if t != "" {
					if st.Time, err = parseVEXTime(t, where); err != nil {
						return nil, err
					}
				}
			}
			for _, af := range v.Affects {
				st.Products = append(st.Products, af.Ref)
			}
			if len(st.Products) == 0 {
				return nil, fmt.Errorf("%s has no affects", where)
			}
			add(st)
		}
	}
	return out, nil
}

func stripQualifiers(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

// purlMatches reports whether a purl (or bom-ref) of a VEX statement denotes
// the component. A purl without a version covers every version.
func purlMatches(ref, comp string) bool {
	norm := func(s string) string { return strings.ReplaceAll(stripQualifiers(s), "%40", "@") }
	r, c := norm(ref), norm(comp)
	if r == c || strings.HasSuffix(r, "/"+strings.TrimPrefix(c, "pkg:")) {
		return true
	}
	if strings.HasPrefix(r, "pkg:") && !strings.Contains(r[strings.LastIndex(r, "/")+1:], "@") {
		return strings.HasPrefix(c, r+"@")
	}
	return false
}

// matches reports whether the statement is about this vulnerability (any of
// its identifiers) in this component.
func (s Statement) matches(ids []string, comp string) bool {
	hitID := containsStr(ids, s.Vulnerability)
	for _, a := range s.Aliases {
		hitID = hitID || containsStr(ids, a)
	}
	if !hitID {
		return false
	}
	targets := s.Products
	if len(s.Subcomponents) > 0 {
		targets = s.Subcomponents
	}
	for _, p := range targets {
		if purlMatches(p, comp) {
			return true
		}
	}
	return false
}

// later reports whether s was made after t: by time, and in document order
// (files in the order given, statements in the order written) when the times
// are equal or missing.
func (s Statement) later(t Statement) bool {
	if !s.Time.Equal(t.Time) {
		return s.Time.After(t.Time)
	}
	return s.Seq > t.Seq
}

// ApplyVEX gives every vulnerability finding the status of the latest VEX
// statement about it, so that a later affected or under_investigation
// statement revokes an earlier not_affected one. Findings whose latest status
// is not_affected or fixed are suppressed; they stay in the report with their
// justification. It returns the number of suppressed findings.
func ApplyVEX(findings []*model.Finding, stmts []Statement) int {
	n := 0
	for _, f := range findings {
		if f.Vuln == nil || f.Kind != model.KindVulnerability {
			continue
		}
		ids := append([]string{f.Vuln.ID}, f.Vuln.Aliases...)
		var best *Statement
		for i := range stmts {
			if stmts[i].matches(ids, f.Component) && (best == nil || stmts[i].later(*best)) {
				best = &stmts[i]
			}
		}
		if best == nil {
			continue
		}
		f.Vuln.VEXStatus = best.Status
		if best.Status != "not_affected" && best.Status != "fixed" {
			continue
		}
		f.Suppressed = true
		f.Vuln.VEXJustification = best.Justification
		f.Reason = "VEX " + best.Status + " (" + best.Justification + ") from " + best.Source
		n++
	}
	return n
}
