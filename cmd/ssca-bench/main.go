// Command ssca-bench measures how the CPU-bound parts of the suite scale with
// the size of the dependency graph (NFR-01, NFR-02, Table 3.17). It generates
// synthetic package-lock.json files, so no network access is involved.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/core"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/graph"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/policy"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// synth writes a lockfile with n packages, about 2.6 edges per package, a
// few cycles and a depth distribution similar to real npm projects.
func synth(dir string, n int, rng *rand.Rand) error {
	pk := map[string]any{}
	direct := map[string]string{}
	name := func(i int) string { return "pkg-" + strconv.Itoa(i) }
	for i := 0; i < n; i++ {
		deps := map[string]string{}
		// edges point mostly to later packages (deeper), sometimes back (cycles)
		k := rng.Intn(5)
		for j := 0; j < k; j++ {
			t := i + 1 + rng.Intn(max(1, min(200, n-i-1)))
			if rng.Float64() < 0.01 {
				t = rng.Intn(i + 1)
			}
			if t < n && t != i {
				deps[name(t)] = "^1.0.0"
			}
		}
		pk["node_modules/"+name(i)] = map[string]any{"version": "1.0.0", "integrity": "sha512-AAAA", "dependencies": deps}
		if i < max(10, n/50) {
			direct[name(i)] = "^1.0.0"
		}
	}
	pk[""] = map[string]any{"name": "bench", "version": "1.0.0", "dependencies": direct}
	lock, _ := json.Marshal(map[string]any{"name": "bench", "version": "1.0.0", "lockfileVersion": 3, "packages": pk})
	man, _ := json.Marshal(map[string]any{"name": "bench", "version": "1.0.0", "dependencies": direct})
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), lock, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "package.json"), man, 0o644)
}

type peak struct {
	stop chan struct{}
	max  uint64
}

func watch() *peak {
	p := &peak{stop: make(chan struct{})}
	go func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > p.max {
				p.max = m.HeapInuse
			}
			select {
			case <-p.stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	return p
}

func main() {
	sizes := []int{1000, 2000, 5000, 10000, 20000, 50000, 100000}
	if len(os.Args) > 1 {
		sizes = nil
		for _, s := range strings.Split(os.Args[1], ",") {
			n, _ := strconv.Atoi(s)
			sizes = append(sizes, n)
		}
	}
	corpus, _, _ := data.Corpus("npm", 0)
	t0 := time.Now()
	ix := risk.NewIndex("npm", corpus, nil)
	indexTime := time.Since(t0).Seconds()
	pol, _ := policy.Load("")
	fmt.Printf("# typosquat index: %d names built in %.2fs\n", ix.Size(), indexTime)
	fmt.Println("n,edges,graph_s,tarjan_s,score_s,typosquat_s,sbom_s,diff_s,policy_s,total_s,peak_heap_mb")
	for _, n := range sizes {
		rng := rand.New(rand.NewSource(int64(n)))
		dir, _ := os.MkdirTemp("", "bench")
		if err := synth(dir, n, rng); err != nil {
			panic(err)
		}
		runtime.GC()
		pk := watch()
		start := time.Now()
		lap := func() float64 { s := time.Since(start).Seconds(); start = time.Now(); return s }
		g, _, err := core.BuildGraph(context.Background(), dir, "npm", common.Options{})
		if err != nil {
			panic(err)
		}
		tg := lap()
		sccs := graph.Tarjan(g)
		_ = graph.Cycles(g, sccs)
		tt := lap()
		// synthetic findings: 5% of components carry one vulnerability
		findings := map[string][]*model.Finding{}
		var all []*model.Finding
		for i, c := range g.Components() {
			if i%20 == 0 {
				f := &model.Finding{ID: "GHSA-" + strconv.Itoa(i), Kind: model.KindVulnerability, Component: c.PURL, Severity: "high",
					Vuln: &model.Vulnerability{ID: "GHSA-" + strconv.Itoa(i), CVSS: 7.5, EPSS: 0.1, Reachable: "unknown"}}
				findings[c.PURL] = append(findings[c.PURL], f)
				all = append(all, f)
			}
		}
		scores := risk.ScoreGraph(g, risk.Input{Findings: findings}, pol.Weights, time.Now())
		ts := lap()
		for _, c := range g.Components() {
			ix.Check(c.Name, 0)
		}
		tq := lap()
		doc := sbom.FromGraph(g, "bench", time.Now())
		_, _ = doc.CycloneDX("bench", "1.0.0")
		tb := lap()
		other := *doc
		other.Components = append([]sbom.Comp{}, doc.Components[:len(doc.Components)*9/10]...)
		_ = sbom.Diff(doc, &other, sbom.ReleaseVsRelease, vuln.Compare, nil)
		td := lap()
		_ = pol.Evaluate(policy.Subject{Graph: g, Findings: all, Scores: scores, Now: time.Now()})
		tp := lap()
		close(pk.stop)
		total := tg + tt + ts + tq + tb + td + tp
		fmt.Printf("%d,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.1f\n", len(g.Components()), g.EdgeCount(), tg, tt, ts, tq, tb, td, tp, total, float64(pk.max)/(1<<20))
		os.RemoveAll(dir)
	}
}
