package risk

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// The worked example of the thesis must be reproduced by the implementation.
func TestWorkedExampleTable34(t *testing.T) {
	crs := func(c, v, h, m float64) float64 { return 100 * (1 - (1-c*v)*(1-0.5*h)*(1-m)) }
	cases := []struct {
		c, v, h, m, want float64
	}{
		{0.8, VulnProb(7.5, 0.02, false), 0.14, 0, 24.7},
		{0.8, VulnProb(9.8, 0.94, false), 0.25, 0, 78.2},
		{0.6, 0, 0.90, 0, 45.0},
		{0.8, 0, 0.09, NoisyOr([]float64{0.4, 0.4, 0.5}), 82.8},
		{1.0, 0, 0.58, NoisyOr([]float64{0.7 * 0.92, 0.4}), 84.8},
	}
	for i, c := range cases {
		got := crs(c.c, c.v, c.h, c.m)
		if math.Abs(got-c.want) > 0.25 {
			t.Errorf("component %d: CRS %.1f, want %.1f", i+1, got, c.want)
		}
	}
}

func TestPropagationThroughCycle(t *testing.T) {
	g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
	mk := func(n string) *model.Component {
		c := model.NewComponent("npm", "", n, "1.0.0")
		g.AddNode(c)
		return c
	}
	a, d, e, c := mk("a"), mk("d"), mk("e"), mk("c")
	g.AddEdge(model.Edge{From: g.Root, To: a.PURL})
	g.AddEdge(model.Edge{From: a.PURL, To: d.PURL})
	g.AddEdge(model.Edge{From: d.PURL, To: e.PURL})
	g.AddEdge(model.Edge{From: e.PURL, To: d.PURL})
	g.AddEdge(model.Edge{From: e.PURL, To: c.PURL})
	g.ComputeDepths()
	in := Input{Findings: map[string][]*model.Finding{
		c.PURL: {{Kind: model.KindMalicious, ID: "MAL-1"}},
	}}
	s := ScoreGraph(g, in, DefaultWeights(), time.Now())
	if s[c.PURL].CRS != 100 || s[a.PURL].Subtree != 100 || s[d.PURL].Subtree != 100 {
		t.Fatalf("propagation failed: a=%v d=%v c=%v", s[a.PURL].Subtree, s[d.PURL].Subtree, s[c.PURL].CRS)
	}
	if p := s[a.PURL].WorstPath; p[len(p)-1] != c.PURL {
		t.Fatalf("worst path does not end at the malicious node: %v", p)
	}
}

// With several equally risky subtrees the worst path must not depend on the
// order of the edges (that is, on the lockfile order): the shortest path wins,
// then the smallest PURL.
func TestWorstPathTieBreak(t *testing.T) {
	build := func(reverse bool) map[string]*model.Score {
		g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
		purl := func(n string) string { return model.MakePURL("npm", "", n, "1.0.0") }
		for _, n := range []string{"x", "p", "q", "m1", "m2", "m3", "deep", "m4"} {
			g.AddNode(model.NewComponent("npm", "", n, "1.0.0"))
		}
		edges := [][2]string{{"app", "x"}, {"x", "q"}, {"x", "p"}, {"x", "deep"}, {"q", "m2"}, {"p", "m1"},
			{"deep", "m4"}, {"m4", "m3"}, {"app", "deep"}}
		if reverse {
			for i, j := 0, len(edges)-1; i < j; i, j = i+1, j-1 {
				edges[i], edges[j] = edges[j], edges[i]
			}
		}
		for _, e := range edges {
			g.AddEdge(model.Edge{From: purl(e[0]), To: purl(e[1])})
		}
		g.ComputeDepths()
		mal := map[string][]*model.Finding{}
		for _, n := range []string{"m1", "m2", "m3"} {
			mal[purl(n)] = []*model.Finding{{Kind: model.KindMalicious, ID: "MAL-" + n}}
		}
		return ScoreGraph(g, Input{Findings: mal}, DefaultWeights(), time.Now())
	}
	want := []string{"pkg:npm/x@1.0.0", "pkg:npm/p@1.0.0", "pkg:npm/m1@1.0.0"}
	for _, reverse := range []bool{false, true} {
		s := build(reverse)
		got := s["pkg:npm/x@1.0.0"].WorstPath
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("reverse=%v: worst path %v, want %v", reverse, got, want)
		}
		// x -> deep -> m4 -> m3 is longer than x -> p -> m1
		if p := s["pkg:npm/deep@1.0.0"].WorstPath; len(p) != 3 {
			t.Errorf("reverse=%v: worst path of deep %v", reverse, p)
		}
	}
}

// Direct dependencies with equal subtree risk are ordered by their own CRS
// and then by PURL, whatever the order of the root's edges.
func TestTopDirectTieOrder(t *testing.T) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	scores := map[string]*model.Score{}
	for _, perm := range [][]string{{"c", "a", "b"}, {"b", "c", "a"}, {"a", "b", "c"}} {
		g := model.NewGraph(root)
		for _, n := range perm {
			c := g.AddNode(model.NewComponent(model.NPM, "", n, "1.0.0"))
			g.AddEdge(model.Edge{From: root.PURL, To: c.PURL})
			crs := map[string]float64{"a": 10, "b": 30, "c": 10}[n]
			scores[c.PURL] = &model.Score{PURL: c.PURL, CRS: crs, Subtree: 50}
		}
		var got []string
		for _, s := range TopDirect(g, scores) {
			got = append(got, s.PURL)
		}
		if strings.Join(got, " ") != "pkg:npm/b@1.0.0 pkg:npm/a@1.0.0 pkg:npm/c@1.0.0" {
			t.Errorf("order %v", got)
		}
	}
}

// The calibrated health factor: a package with the worst
// possible health and no other risk gets CRS 40, the Medium band, so poor
// health alone no longer produces a High warning.
func TestHealthAloneIsMedium(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
	lib := model.NewComponent("npm", "", "abandoned", "0.1.0")
	lib.Meta = &model.PackageMeta{Scorecard: 0, LatestReleaseAt: now.AddDate(-5, 0, 0), Maintainers: 1}
	g.AddNode(lib)
	g.AddEdge(model.Edge{From: g.Root, To: lib.PURL})
	g.ComputeDepths()
	w := DefaultWeights()
	if w.HealthFactor != 0.4 {
		t.Fatalf("health factor %.2f, want 0.4", w.HealthFactor)
	}
	s := ScoreGraph(g, Input{}, w, now)[lib.PURL]
	if s.H != 1 || s.CRS != 40 || s.Band != "medium" {
		t.Errorf("H %.2f CRS %.1f band %s, want 1, 40, medium", s.H, s.CRS, s.Band)
	}
}
