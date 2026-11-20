package main

import (
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

func index(t *testing.T, eco string) (*risk.Index, map[int][]string) {
	c, _, err := data.Corpus(eco, 0)
	if err != nil {
		t.Fatal(err)
	}
	byLen := map[int][]string{}
	for _, p := range c {
		byLen[len(p.Name)] = append(byLen[len(p.Name)], p.Name)
	}
	return risk.NewIndex(eco, c, nil), byLen
}

// The evaluation must score a name exactly as the scan does: the whole
// dictionary is protected and the popularity of the name is unknown.
func TestScoreAsScan(t *testing.T) {
	x, byLen := index(t, "npm")
	c, _, _ := data.Corpus("npm", 0)
	last := c[len(c)-1].Name // the least popular protected name
	r := row{Eco: "npm", Name: last}
	score(&r, x, byLen, nil, time.Time{})
	if r.Full != 0 || r.Gap != 0 || r.NoGap != 0 {
		t.Errorf("dictionary name %s scored %+v", last, r)
	}
	r = row{Eco: "npm", Name: "loadsh"}
	score(&r, x, byLen, nil, time.Time{})
	want := x.Check("loadsh", -1) // what risk.Signals computes without metadata
	if len(want) == 0 || r.Gap < want[0].Similarity || r.Target != "lodash" {
		t.Errorf("loadsh: %+v, scan candidates %+v", r, want)
	}
}

func TestGuardDismisses(t *testing.T) {
	x, byLen := index(t, "npm")
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	hist := map[string]*model.PackageMeta{"npm/loadsh": {FirstReleaseAt: now.AddDate(-5, 0, 0), LatestReleaseAt: now.AddDate(-1, 0, 0), Releases: 9}}
	r := row{Eco: "npm", Name: "loadsh"}
	score(&r, x, byLen, hist, now)
	if r.Full != 0 || r.Gap == 0 || r.Dismissed == "" {
		t.Errorf("established name not dismissed: %+v", r)
	}
}
