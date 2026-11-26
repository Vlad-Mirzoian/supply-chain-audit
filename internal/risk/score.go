package risk

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/graph"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Weights are the policy parameters of the composite risk score (CRS).
type Weights struct {
	HealthFactor    float64            `yaml:"health_factor"`
	TyposquatFactor float64            `yaml:"typosquat_factor"`
	CooldownDays    float64            `yaml:"cooldown_days"`
	Signals         map[string]float64 `yaml:"signals"`
	Health          map[string]float64 `yaml:"health"`
}

// DefaultWeights returns the expert estimates of the weights with the health
// factor calibrated on corpus (a) (0.4 instead of 0.5: poor health alone
// gives at most CRS 40, the Medium band).
func DefaultWeights() Weights {
	return Weights{
		HealthFactor: 0.4, TyposquatFactor: 0.7, CooldownDays: 7,
		Signals: map[string]float64{
			"install_script": 0.4, "install_script_added": 0.5, "publisher_changed": 0.4,
			"provenance_regression": 0.4, "young_new_dependency": 0.5, "version_jump": 0.5,
			"cooldown": 0.2, "dependency_confusion": 0.9, "deprecated": 0.1,
		},
		Health: map[string]float64{"scorecard": 0.40, "recency": 0.25, "maintainers": 0.15, "provenance": 0.20},
	}
}

func (w Weights) sig(name string) float64 {
	if v, ok := w.Signals[name]; ok {
		return v
	}
	return DefaultWeights().Signals[name]
}

// Internal describes the organisation's private packages (dependency
// confusion check).
type Internal struct {
	Scopes   []string `yaml:"scopes"`
	Names    []string `yaml:"names"`
	Registry string   `yaml:"registry"`
}

// IsInternal reports whether a package name belongs to the organisation.
func (in Internal) IsInternal(name string) bool {
	for _, s := range in.Scopes {
		if strings.HasPrefix(name, strings.TrimSuffix(s, "/")+"/") {
			return true
		}
	}
	for _, n := range in.Names {
		if n == name {
			return true
		}
	}
	return false
}

// Signals computes the malicious-indicator signals m_j of one component.
func Signals(c *model.Component, ix *Index, w Weights, in Internal, now time.Time) ([]model.Signal, []Squat) {
	var out []model.Signal
	add := func(name string, v float64, reason string) {
		if v > 0 {
			out = append(out, model.Signal{Name: name, Value: math.Min(v, 1), Reason: reason})
		}
	}
	var squats []Squat
	if ix != nil && !in.IsInternal(c.FullName()) {
		dl := int64(-1)
		if c.Meta != nil && c.Meta.Downloads > 0 {
			dl = c.Meta.Downloads
		}
		squats = ix.Check(c.FullName(), dl)
		if len(squats) > 0 {
			s := squats[0]
			add("typosquat", w.TyposquatFactor*s.Similarity,
				fmt.Sprintf("name similar to popular package %q (%s, similarity %.2f)", s.Target, s.Class, s.Similarity))
		}
	}
	if in.IsInternal(c.FullName()) && in.Registry != "" && c.Resolved != "" && !strings.HasPrefix(c.Resolved, in.Registry) {
		add("dependency_confusion", w.sig("dependency_confusion"),
			fmt.Sprintf("internal package resolved from %s instead of %s", host(c.Resolved), host(in.Registry)))
	}
	m := c.Meta
	if m == nil {
		return out, squats
	}
	if len(m.InstallScripts) > 0 {
		if m.PreviousVersion != "" && len(m.PrevInstallScripts) == 0 {
			add("install_script_added", w.sig("install_script_added"), "install-time script added in this release: "+m.InstallScripts[0])
		} else {
			add("install_script", w.sig("install_script"), "install-time script: "+m.InstallScripts[0])
		}
	}
	// a change of publisher is suspicious only if the new account was not a
	// maintainer before and the release is not published from CI with
	// provenance (moving to trusted publishing is the opposite of an attack)
	if m.Publisher != "" && m.PreviousPublisher != "" && m.Publisher != m.PreviousPublisher &&
		!anyIn(strings.Split(m.Publisher, ", "), m.PrevMaintainers) && !m.HasProvenance {
		add("publisher_changed", w.sig("publisher_changed"), fmt.Sprintf("published by %q, previous version by %q", m.Publisher, m.PreviousPublisher))
	}
	if m.PrevHasProvenance && !m.HasProvenance {
		add("provenance_regression", w.sig("provenance_regression"), "provenance missing although version "+m.PreviousVersion+" had it")
	}
	if len(m.NewDependencies) > 0 && m.NewDepMinAgeDays >= 0 && m.NewDepMinAgeDays < w.CooldownDays {
		add("young_new_dependency", w.sig("young_new_dependency"),
			fmt.Sprintf("new dependency %s is %.1f days old", strings.Join(m.NewDependencies, ", "), m.NewDepMinAgeDays))
	}
	if jump(c.Version, m.PreviousVersion) {
		add("version_jump", w.sig("version_jump"), "anomalous version jump from "+m.PreviousVersion+" to "+c.Version)
	} else if m.PreviousVersion == "" && major(c.Version) >= 90 {
		add("version_jump", w.sig("version_jump"), "first published version is "+c.Version)
	}
	if !m.PublishedAt.IsZero() {
		age := now.Sub(m.PublishedAt).Hours() / 24
		if age >= 0 && age < w.CooldownDays {
			add("cooldown", w.sig("cooldown"), fmt.Sprintf("release is %.1f days old (cooldown %.0f days)", age, w.CooldownDays))
		}
	}
	if m.Deprecated != "" {
		add("deprecated", w.sig("deprecated"), "deprecated: "+m.Deprecated)
	}
	return out, squats
}

func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.Index(u, "/"); i > 0 {
		return u[:i]
	}
	return u
}

func major(v string) int {
	v = strings.TrimPrefix(v, "v")
	f := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' })
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(f[0])
	return n
}

func jump(cur, prev string) bool {
	if prev == "" {
		return false
	}
	a, b := major(prev), major(cur)
	return b-a >= 10 || (a < 50 && b >= 90)
}

// Health computes the health deficit H with rescaled weights.
func Health(c *model.Component, w Weights, now time.Time) (float64, []model.Signal) {
	m := c.Meta
	if m == nil {
		return 0, nil
	}
	var ind []model.Signal
	if m.Scorecard >= 0 {
		ind = append(ind, model.Signal{Name: "scorecard", Value: 1 - m.Scorecard/10, Reason: fmt.Sprintf("Scorecard %.1f", m.Scorecard)})
	}
	if !m.LatestReleaseAt.IsZero() {
		months := now.Sub(m.LatestReleaseAt).Hours() / 24 / 30.44
		ind = append(ind, model.Signal{Name: "recency", Value: math.Min(math.Max(months, 0)/24, 1), Reason: fmt.Sprintf("last release %.0f months ago", months)})
	}
	if m.Maintainers > 0 {
		v := 0.0
		switch m.Maintainers {
		case 1:
			v = 1
		case 2:
			v = 0.5
		}
		ind = append(ind, model.Signal{Name: "maintainers", Value: v, Reason: fmt.Sprintf("%d maintainer(s)", m.Maintainers)})
	}
	if c.Ecosystem != model.Maven {
		v := 1.0
		if m.AnyProvenance {
			v = 0
		}
		ind = append(ind, model.Signal{Name: "provenance", Value: v, Reason: fmt.Sprintf("publishes provenance: %v", m.AnyProvenance)})
	}
	var num, den float64
	for _, s := range ind {
		wt := w.Health[s.Name]
		num += wt * s.Value
		den += wt
	}
	if den == 0 {
		return 0, ind
	}
	return num / den, ind
}

// Exposure is the exposure factor c of the CRS.
func Exposure(c *model.Component, unreachable bool) float64 {
	var x float64
	// optional (npm) and provided (Maven) dependencies run in production
	// like runtime ones: npm installs optional packages by default, and the
	// container supplies provided ones at run time
	switch {
	case c.Scope.Production():
		x = 0.8
		if c.Direct {
			x = 1.0
		}
	case c.Scope == model.ScopeTest:
		x = 0.3
	default: // dev
		x = 0.6
	}
	if unreachable {
		x /= 2
	}
	return x
}

// NoisyOr combines probability-like values.
func NoisyOr(xs []float64) float64 {
	p := 1.0
	for _, x := range xs {
		p *= 1 - math.Min(math.Max(x, 0), 1)
	}
	return 1 - p
}

// VulnProb is the probability p of one vulnerability from CVSS and EPSS.
func VulnProb(cvss, epss float64, kev bool) float64 {
	e := epss
	if kev {
		e = 1
	}
	return cvss / 10 * (0.3 + 0.7*e)
}

// Input bundles the per-component evidence for ScoreGraph.
type Input struct {
	Findings map[string][]*model.Finding
	Signals  map[string][]model.Signal
}

// ScoreGraph computes the CRS of every node and the subtree risk with the
// worst path for every node.
func ScoreGraph(g *model.Graph, in Input, w Weights, now time.Time) map[string]*model.Score {
	scores := map[string]*model.Score{}
	for _, c := range g.Components() {
		s := &model.Score{PURL: c.PURL, Scope: c.Scope}
		scores[c.PURL] = s
		var probs []float64
		unreachable, anyVuln := true, false
		for _, f := range in.Findings[c.PURL] {
			if f.Kind == model.KindMalicious && !f.Suppressed {
				s.Override = "known malicious (" + f.ID + ")"
			}
			if f.Kind != model.KindVulnerability || f.Suppressed || f.Vuln == nil {
				continue
			}
			anyVuln = true
			if f.Vuln.Reachable != "no" {
				unreachable = false
			}
			probs = append(probs, VulnProb(f.Vuln.CVSS, f.Vuln.EPSS, f.Vuln.KEV))
		}
		s.V = NoisyOr(probs)
		s.C = Exposure(c, anyVuln && unreachable)
		s.H, s.Health = Health(c, w, now)
		s.Signals = in.Signals[c.PURL]
		var ms []float64
		for _, sg := range s.Signals {
			ms = append(ms, sg.Value)
		}
		s.M = NoisyOr(ms)
		s.CRS = 100 * (1 - (1-s.C*s.V)*(1-w.HealthFactor*s.H)*(1-s.M))
		if s.Override != "" {
			s.CRS = 100
		}
		s.CRS = math.Round(s.CRS*10) / 10
		s.Band = model.BandOf(s.CRS)
	}
	// propagation over the condensation (lines 10-14)
	sccs := graph.Tarjan(g)
	comp := graph.Condensation(sccs)
	rk := make([]float64, len(sccs))
	worstChild := make([]string, len(sccs))
	best := make([]string, len(sccs))
	plen := make([]int, len(sccs)) // length of the worst path below the SCC
	for i, members := range sccs { // sinks first = reverse topological order
		for _, v := range members {
			if s := scores[v]; s != nil && (best[i] == "" || s.CRS > rk[i] || s.CRS == rk[i] && v < best[i]) {
				rk[i], best[i] = s.CRS, v
			}
		}
		// ties are broken by the shorter path and then by the PURL, so that
		// the worst path does not depend on the order of the lockfile entries
		for _, v := range members {
			for _, e := range g.Out[v] {
				j := comp[e.To]
				if j == i || rk[j] < rk[i] || rk[j] == rk[i] && worstChild[i] == "" {
					continue
				}
				if rk[j] > rk[i] || plen[j]+1 < plen[i] || plen[j]+1 == plen[i] && e.To < worstChild[i] {
					rk[i], worstChild[i], plen[i] = rk[j], e.To, plen[j]+1
				}
			}
		}
	}
	for id, s := range scores {
		i := comp[id]
		s.Subtree = rk[i]
		path := []string{id}
		for cur := i; worstChild[cur] != ""; {
			nxt := worstChild[cur]
			path = append(path, nxt)
			cur = comp[nxt]
			if len(path) > 64 {
				break
			}
		}
		if last := path[len(path)-1]; scores[last] != nil && scores[last].CRS < s.Subtree {
			// the maximum sits inside the SCC of the last node
			path = append(path, best[comp[last]])
		}
		s.WorstPath = path
	}
	return scores
}

// TopDirect returns the direct dependencies ordered by subtree risk; equal
// subtree risks are ordered by the dependency's own CRS and then by PURL, so
// that the order does not depend on the order of the edges.
func TopDirect(g *model.Graph, scores map[string]*model.Score) []*model.Score {
	var out []*model.Score
	for _, e := range g.Out[g.Root] {
		if s := scores[e.To]; s != nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Subtree != b.Subtree {
			return a.Subtree > b.Subtree
		}
		if a.CRS != b.CRS {
			return a.CRS > b.CRS
		}
		return a.PURL < b.PURL
	})
	return out
}

// anyIn reports whether one of xs occurs in ys (case-insensitive).
func anyIn(xs, ys []string) bool {
	for _, x := range xs {
		for _, y := range ys {
			if strings.EqualFold(y, x) {
				return true
			}
		}
	}
	return false
}
