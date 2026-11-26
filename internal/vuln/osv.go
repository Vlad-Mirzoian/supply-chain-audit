// Package vuln is module M2: vulnerability matching through the OSV.dev
// batch API, local re-checking of version ranges, enrichment with CVSS, EPSS
// and CISA KEV, and VEX filtering.
package vuln

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/maven"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// API is the OSV.dev endpoint.
var API = "https://api.osv.dev/v1"

// Event is one entry of an OSV range.
type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// OSV is the subset of the OSV schema used by the suite.
type OSV struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Withdrawn string   `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string  `json:"type"`
			Events []Event `json:"events"`
		} `json:"ranges"`
		Versions          []string       `json:"versions"`
		DatabaseSpecific  map[string]any `json:"database_specific"`
		EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

func osvEcosystem(eco string) string {
	switch eco {
	case model.NPM:
		return "npm"
	case model.PyPI:
		return "PyPI"
	case model.Maven:
		return "Maven"
	}
	return eco
}

// Compare dispatches to the ecosystem version comparator.
func Compare(eco, a, b string) int {
	switch eco {
	case model.NPM:
		return npm.Compare(a, b)
	case model.PyPI:
		return pypi.Compare(a, b)
	case model.Maven:
		return maven.Compare(a, b)
	}
	return strings.Compare(a, b)
}

// Matcher queries OSV and enriches the results.
type Matcher struct {
	Net   *netx.Client
	EPSS  *EPSS
	KEV   *KEV
	mu    sync.Mutex
	cache map[string]*OSV
	// Rejected counts advisories returned by OSV that the local range check
	// did not confirm (the ranges are checked again locally).
	Rejected int
	// VulnScope selects the components whose vulnerabilities are reported
	// (nil: all). Known-malicious versions (MAL- records) are reported for
	// every component; for the others the vulnerability records are not even
	// fetched, and Omitted counts the components that had any.
	VulnScope func(*model.Component) bool
	Omitted   int
}

// NewMatcher creates a matcher.
func NewMatcher(n *netx.Client) *Matcher {
	return &Matcher{Net: n, EPSS: &EPSS{Net: n}, KEV: &KEV{Net: n}, cache: map[string]*OSV{}}
}

type query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

// Match returns vulnerability and malicious-package findings for comps.
func (m *Matcher) Match(ctx context.Context, comps []*model.Component) ([]*model.Finding, error) {
	ids := make([][]string, len(comps))
	const batch = 1000
	for start := 0; start < len(comps); start += batch {
		end := min(start+batch, len(comps))
		var qs []query
		for _, c := range comps[start:end] {
			var q query
			q.Package.Name, q.Package.Ecosystem, q.Version = c.FullName(), osvEcosystem(c.Ecosystem), c.Version
			qs = append(qs, q)
		}
		for len(qs) > 0 {
			var resp struct {
				Results []struct {
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulns"`
					NextPageToken string `json:"next_page_token"`
				} `json:"results"`
			}
			if err := m.Net.PostJSON(ctx, API+"/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
				return nil, fmt.Errorf("OSV querybatch: %w", err)
			}
			var next []query
			for i, r := range resp.Results {
				idx := start + i
				if qs[i].PageToken != "" {
					idx = indexOf(comps, qs[i])
				}
				for _, v := range r.Vulns {
					ids[idx] = append(ids[idx], v.ID)
				}
				if r.NextPageToken != "" {
					q := qs[i]
					q.PageToken = r.NextPageToken
					next = append(next, q)
				}
			}
			qs = next
		}
	}
	// components outside VulnScope keep only the known-malicious records
	for i, c := range comps {
		if m.VulnScope == nil || m.VulnScope(c) || len(ids[i]) == 0 {
			continue
		}
		var mal []string
		for _, id := range ids[i] {
			if strings.HasPrefix(id, "MAL-") {
				mal = append(mal, id)
			}
		}
		if len(mal) < len(ids[i]) {
			m.Omitted++
		}
		ids[i] = mal
	}
	// fetch full records in parallel
	all := map[string]bool{}
	for _, l := range ids {
		for _, id := range l {
			all[id] = true
		}
	}
	if err := m.fetchAll(ctx, all); err != nil {
		return nil, err
	}
	var out []*model.Finding
	var cves []string
	for i, c := range comps {
		recs := m.dedupe(ids[i])
		for _, r := range recs {
			if r.Withdrawn != "" {
				continue
			}
			if !m.confirm(c, r) {
				m.mu.Lock()
				m.Rejected++
				m.mu.Unlock()
				continue
			}
			f := m.finding(c, r)
			out = append(out, f)
			if f.Vuln != nil {
				cves = append(cves, f.Vuln.CVEs()...)
			}
		}
	}
	// enrichment
	scores, err := m.EPSS.Scores(ctx, cves)
	if err != nil {
		scores = nil
	}
	kev, kerr := m.KEV.Set(ctx)
	for _, f := range out {
		if f.Vuln == nil {
			continue
		}
		for _, cve := range f.Vuln.CVEs() {
			if s := scores[cve]; s > f.Vuln.EPSS {
				f.Vuln.EPSS = s
			}
			if kerr == nil && kev[cve] {
				f.Vuln.KEV = true
			}
		}
	}
	if err != nil || kerr != nil {
		return out, fmt.Errorf("enrichment incomplete: epss=%v kev=%v", err, kerr)
	}
	return out, nil
}

func indexOf(comps []*model.Component, q query) int {
	for i, c := range comps {
		if c.FullName() == q.Package.Name && c.Version == q.Version && osvEcosystem(c.Ecosystem) == q.Package.Ecosystem {
			return i
		}
	}
	return 0
}

func (m *Matcher) fetchAll(ctx context.Context, ids map[string]bool) error {
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	var firstErr error
	var emu sync.Mutex
	for id := range ids {
		m.mu.Lock()
		_, ok := m.cache[id]
		m.mu.Unlock()
		if ok {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var r OSV
			if err := m.Net.GetJSON(ctx, API+"/vulns/"+id, &r); err != nil {
				emu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				emu.Unlock()
				return
			}
			m.mu.Lock()
			m.cache[id] = &r
			m.mu.Unlock()
		}(id)
	}
	wg.Wait()
	return firstErr
}

// dedupe merges records that are aliases of each other, preferring GHSA and
// MAL identifiers, so that one flaw is counted once.
func (m *Matcher) dedupe(ids []string) []*OSV {
	m.mu.Lock()
	defer m.mu.Unlock()
	sort.Slice(ids, func(i, j int) bool {
		return prefRank(ids[i]) < prefRank(ids[j]) || prefRank(ids[i]) == prefRank(ids[j]) && ids[i] < ids[j]
	})
	seen := map[string]bool{}
	var out []*OSV
	for _, id := range ids {
		r := m.cache[id]
		if r == nil || seen[id] {
			continue
		}
		dup := false
		for _, a := range r.Aliases {
			if seen[a] {
				dup = true
			}
		}
		seen[id] = true
		for _, a := range r.Aliases {
			seen[a] = true
		}
		if !dup {
			out = append(out, r)
		}
	}
	return out
}

func prefRank(id string) int {
	switch {
	case strings.HasPrefix(id, "MAL-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	case strings.HasPrefix(id, "CVE-"):
		return 3
	}
	return 2
}

// confirm re-checks the affected ranges with the ecosystem comparator.
func (m *Matcher) confirm(c *model.Component, r *OSV) bool {
	eco := osvEcosystem(c.Ecosystem)
	name := c.FullName()
	if c.Ecosystem == model.PyPI {
		name = pypi.Normalise(name)
	}
	matched := false
	for _, a := range r.Affected {
		an := a.Package.Name
		if c.Ecosystem == model.PyPI {
			an = pypi.Normalise(an)
		}
		if a.Package.Ecosystem != eco || an != name {
			continue
		}
		matched = true
		for _, v := range a.Versions {
			if v == c.Version {
				return true
			}
		}
		for _, rg := range a.Ranges {
			if rg.Type == "GIT" {
				continue
			}
			if AffectedBy(c.Ecosystem, c.Version, rg.Events) {
				return true
			}
		}
		if len(a.Ranges) == 0 && len(a.Versions) == 0 {
			return true // whole package affected (typical for MAL- records)
		}
	}
	return !matched && strings.HasPrefix(r.ID, "MAL-")
}

// AffectedBy evaluates an OSV event list for one version.
func AffectedBy(eco, v string, events []Event) bool {
	// events are sorted by version; walk them and track the state
	type ev struct {
		kind, ver string
	}
	var evs []ev
	for _, e := range events {
		switch {
		case e.Introduced != "":
			evs = append(evs, ev{"i", e.Introduced})
		case e.Fixed != "":
			evs = append(evs, ev{"f", e.Fixed})
		case e.LastAffected != "":
			evs = append(evs, ev{"l", e.LastAffected})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].ver == "0" {
			return evs[j].ver != "0"
		}
		if evs[j].ver == "0" {
			return false
		}
		return Compare(eco, evs[i].ver, evs[j].ver) < 0
	})
	affected := false
	for _, e := range evs {
		var c int
		if e.ver == "0" {
			c = 1
		} else {
			c = Compare(eco, v, e.ver)
		}
		switch e.kind {
		case "i":
			if c >= 0 {
				affected = true
			}
		case "f":
			if c >= 0 {
				affected = false
			}
		case "l":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected
}

func (m *Matcher) finding(c *model.Component, r *OSV) *model.Finding {
	v := &model.Vulnerability{ID: r.ID, Aliases: r.Aliases, Summary: r.Summary, Reachable: "unknown", LocallyConfirmed: true}
	v.CVSS, v.CVSSVector = baseScore(r)
	for _, a := range r.Affected {
		for _, rg := range a.Ranges {
			for _, e := range rg.Events {
				if e.Fixed != "" {
					v.Fixed = append(v.Fixed, e.Fixed)
				}
			}
		}
	}
	f := &model.Finding{
		ID: r.ID, Kind: model.KindVulnerability, Component: c.PURL, Vuln: v,
		Title: r.Summary, Module: "M2",
	}
	if strings.HasPrefix(r.ID, "MAL-") {
		f.Kind = model.KindMalicious
		f.Severity = model.SevCritical
		v.CVSS = 10
		if f.Title == "" {
			f.Title = "Known malicious package version"
		}
		return f
	}
	f.Severity = sevOf(v.CVSS, r)
	if f.Title == "" {
		f.Title = r.ID
	}
	return f
}

func baseScore(r *OSV) (float64, string) {
	var v3, v4 string
	for _, s := range r.Severity {
		switch s.Type {
		case "CVSS_V4":
			v4 = s.Score
		case "CVSS_V3":
			v3 = s.Score
		}
	}
	if v4 != "" {
		if c, err := cvss40.ParseVector(v4); err == nil {
			return c.Score(), v4
		}
	}
	if v3 != "" {
		vec := strings.Replace(v3, "CVSS:3.0/", "CVSS:3.1/", 1)
		if c, err := cvss31.ParseVector(vec); err == nil {
			return c.BaseScore(), v3
		}
	}
	// fall back to the GHSA qualitative rating
	if s, ok := r.DatabaseSpecific["severity"].(string); ok {
		switch strings.ToUpper(s) {
		case "CRITICAL":
			return 9.5, ""
		case "HIGH":
			return 7.5, ""
		case "MODERATE", "MEDIUM":
			return 5.5, ""
		case "LOW":
			return 2.5, ""
		}
	}
	return 5.0, "" // neutral value
}

func sevOf(score float64, r *OSV) string {
	switch {
	case score >= 9:
		return model.SevCritical
	case score >= 7:
		return model.SevHigh
	case score >= 4:
		return model.SevMedium
	case score > 0:
		return model.SevLow
	}
	return model.SevInfo
}
