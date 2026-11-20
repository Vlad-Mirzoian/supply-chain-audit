package risk

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

// Values from the text of Section 3.5.2.
func TestWeightedDistanceExamples(t *testing.T) {
	cases := []struct {
		a, b string
		d    float64
	}{
		{"loadsh", "lodash", 0.5},       // transposition
		{"crossenv", "cross-env", 0.25}, // separator removed
		{"reqyests", "requests", 0.5},   // neighbouring key
		{"l0dash", "lodash", 0.25},      // look-alike character
		{"expres", "express", 1.0},      // other deletion
		{"rnoment", "moment", 0.25},     // rn -> m
	}
	for _, c := range cases {
		if got := WeightedDL(c.a, c.b, 2); !near(got, c.d) {
			t.Errorf("d(%s,%s) = %v, want %v", c.a, c.b, got, c.d)
		}
	}
	if s := Similarity("loadsh", "lodash", 0.5); !near(s, 0.92) {
		t.Errorf("similarity loadsh = %v", s)
	}
	if s := Similarity("crossenv", "cross-env", 0.25); !near(s, 0.97) {
		t.Errorf("similarity crossenv = %v", s)
	}
}

func TestBandCutoff(t *testing.T) {
	if d := WeightedDL("abcdefgh", "zyxwvuts", 2); d <= 2 {
		t.Fatalf("expected cut-off, got %v", d)
	}
}

func TestIndexChecks(t *testing.T) {
	corpus := []Popular{{"lodash", 50_000_000}, {"cross-env", 10_000_000}, {"python-dateutil", 90_000_000},
		{"@typescript-eslint/parser", 40_000_000}, {"react", 80_000_000}, {"react-dom", 70_000_000}}
	ix := NewIndex("npm", corpus, []string{"acme-billing"})
	if got := ix.Check("loadsh", 0); len(got) == 0 || got[0].Target != "lodash" {
		t.Errorf("loadsh: %v", got)
	}
	if got := ix.Check("crossenv", 0); len(got) == 0 || got[0].Target != "cross-env" {
		t.Errorf("crossenv: %v", got)
	}
	if got := ix.Check("lodash-utils", 0); len(got) == 0 || got[0].Class != "affix" {
		t.Errorf("affix: %v", got)
	}
	if got := ix.Check("dateutil-python", 0); len(got) == 0 || got[0].Class != "token-order" {
		t.Errorf("token order: %v", got)
	}
	if got := ix.Check("@typescript_eslint/parser", 0); len(got) == 0 || got[0].Class != "scope" {
		t.Errorf("scope: %v", got)
	}
	if got := ix.Check("acme-biling", 0); len(got) == 0 || got[0].Target != "acme-billing" {
		t.Errorf("internal name: %v", got)
	}
	// popular names are never squats of each other
	if got := ix.Check("react-dom", -1); len(got) != 0 {
		t.Errorf("react-dom flagged: %v", got)
	}
	// the popularity gap removes a similar but popular legitimate package
	if got := ix.Check("reacts", 5_000_000); len(got) != 0 {
		t.Errorf("gap filter failed: %v", got)
	}
}

// A name match of an established package (years of release history) is
// dismissed; a young package, a short or single-release history and a
// package without metadata are not established.
func TestEstablished(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	d := func(s string) time.Time { v, _ := time.Parse("2006-01-02", s); return v }
	toronado := &model.PackageMeta{FirstReleaseAt: d("2013-02-05"), LatestReleaseAt: d("2020-12-10"), Releases: 12}
	if ok, why := Established(toronado, now); !ok || !strings.Contains(why, "first release 2013-02-05, 12 releases over 7.8 years") {
		t.Errorf("toronado: %v %q", ok, why)
	}
	for name, m := range map[string]*model.PackageMeta{
		"no metadata":         nil,
		"no history":          {},
		"young":               {FirstReleaseAt: d("2025-12-01"), LatestReleaseAt: d("2026-10-01"), Releases: 30},
		"few releases":        {FirstReleaseAt: d("2015-01-01"), LatestReleaseAt: d("2019-01-01"), Releases: 4},
		"one burst":           {FirstReleaseAt: d("2020-01-01"), LatestReleaseAt: d("2020-03-01"), Releases: 9},
		"old but single-shot": {FirstReleaseAt: d("2018-01-01"), LatestReleaseAt: d("2018-01-01"), Releases: 1},
	} {
		if ok, _ := Established(m, now); ok {
			t.Errorf("%s: established", name)
		}
	}
	// the evaluation time counts, not the wall clock (--now)
	if ok, _ := Established(toronado, d("2014-01-01")); ok {
		t.Error("established before its history existed")
	}
}
