// Command ssca-roc scores a labelled list of package names with the name check
// of internal/risk for ROC analysis of the typosquatting detector, configured as the scan uses
// it: the whole embedded dictionary is protected (data.Corpus(eco, 0), as in
// core.Scan) and the popularity of every name is unknown (downloads -1, as in
// risk.Signals for a component without registry metadata), so the corpus floor
// is used for the popularity-gap filter. The npm confirmation of a match with
// the candidate's real downloads and maintainers (core.confirmSquat) needs the
// registry and is not modelled.
// Input: JSON lines {eco, name, label, source, ...} on stdin; other fields are
// copied to the output.
//
// Outputs per name: score_full (popularity gap and, with --history, the
// established-package guard: the configuration of ssca), score_gap (gap
// only), score_nogap (neither) and score_levenshtein (plain Levenshtein
// similarity, distance at most 2, against the same dictionary).
//
// --history gives the deps.dev release history of the names (JSON lines
// {eco, name, status, times}); the guard is evaluated at --now.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

type row struct {
	Eco   string `json:"eco"`
	Name  string `json:"name"`
	Label int    `json:"label"`
	// outputs
	Full      float64 `json:"score_full"`
	Gap       float64 `json:"score_gap"`
	NoGap     float64 `json:"score_nogap"`
	Lev       float64 `json:"score_levenshtein"`
	Dismissed string  `json:"guard_dismissed,omitempty"`
	Target    string  `json:"predicted_target,omitempty"`
	TargetLev string  `json:"predicted_target_lev,omitempty"`
}

// unknownDownloads is what risk.Signals passes for a component without
// registry metadata.
const unknownDownloads = -1

// lev is the plain unit-cost Levenshtein distance.
func lev(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := 1
			if a[i-1] == b[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func main() {
	top := flag.Int("top", 0, "size of the protected dictionary (0: the whole dictionary, as the scan)")
	histPath := flag.String("history", "", "deps.dev release history of the names (JSON lines)")
	nowFlag := flag.String("now", "", "evaluation time of the established-package guard (RFC 3339)")
	flag.Parse()
	hist, now := loadHistory(*histPath, *nowFlag)
	ix := map[string]*risk.Index{}
	byLen := map[string]map[int][]string{}
	for _, eco := range []string{"npm", "pypi"} {
		c, _, err := data.Corpus(eco, *top)
		if err != nil {
			panic(err)
		}
		ix[eco] = risk.NewIndex(eco, c, nil)
		byLen[eco] = map[int][]string{}
		for _, p := range c {
			byLen[eco][len(p.Name)] = append(byLen[eco][len(p.Name)], p.Name)
		}
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var extra map[string]any
		var r row
		if json.Unmarshal(sc.Bytes(), &extra) != nil || json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		x := ix[r.Eco]
		if x == nil {
			fmt.Fprintln(os.Stderr, "unknown ecosystem:", r.Eco)
			os.Exit(3)
		}
		score(&r, x, byLen[r.Eco], hist, now)
		b, _ := json.Marshal(r)
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		for k, v := range extra {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
		b, _ = json.Marshal(out)
		w.Write(append(b, '\n'))
	}
}

// score fills the outputs of r.
func score(r *row, x *risk.Index, byLen map[int][]string, hist map[string]*model.PackageMeta, now time.Time) {
	r.Gap, r.Target = x.Score(r.Name, unknownDownloads, true)
	r.NoGap, _ = x.Score(r.Name, unknownDownloads, false)
	r.Full = r.Gap
	if hist != nil {
		if ok, why := risk.Established(hist[r.Eco+"/"+r.Name], now); ok && r.Full > 0 {
			r.Full, r.Dismissed = 0, why
		}
	}
	// baseline: best plain Levenshtein similarity among names within +-2
	// characters, excluding the name itself (SpellBound-style, no weights)
	best := 0.0
	for d := -2; d <= 2; d++ {
		for _, p := range byLen[len(r.Name)+d] {
			if p == r.Name {
				continue
			}
			dist := lev(r.Name, p)
			if dist > 2 {
				continue
			}
			s := 1 - float64(dist)/float64(max(len(r.Name), len(p)))
			if s > best {
				best, r.TargetLev = s, p
			}
		}
	}
	r.Lev = best
}

// loadHistory reads the release history into package metadata as the scan
// computes it from deps.dev (first and latest release, number of releases).
func loadHistory(path, nowS string) (map[string]*model.PackageMeta, time.Time) {
	if path == "" {
		return nil, time.Time{}
	}
	now, err := time.Parse(time.RFC3339, nowS)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--history needs --now:", err)
		os.Exit(3)
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	defer f.Close()
	out := map[string]*model.PackageMeta{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var h struct {
			Eco, Name string
			Status    int
			Times     []time.Time
		}
		if json.Unmarshal(sc.Bytes(), &h) != nil || h.Status != 200 {
			continue
		}
		m := &model.PackageMeta{}
		for _, t := range h.Times {
			if t.IsZero() {
				continue
			}
			m.Releases++
			if m.FirstReleaseAt.IsZero() || t.Before(m.FirstReleaseAt) {
				m.FirstReleaseAt = t
			}
			if t.After(m.LatestReleaseAt) {
				m.LatestReleaseAt = t
			}
		}
		out[h.Eco+"/"+h.Name] = m
	}
	return out, now
}
