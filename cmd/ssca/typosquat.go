// typosquat: check of package names against the corpus of popular names
// (M4), with the confirmation that scan applies to a name match.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

func cmdTyposquat(args []string) int {
	fs := flag.NewFlagSet("typosquat", flag.ContinueOnError)
	g := addNet(fs)
	eco := fs.String("ecosystem", "npm", "npm or pypi")
	top := fs.Int("top", 0, "use only the N most popular names of the corpus")
	namesOnly := fs.Bool("names-only", false, "compare the names with the built-in corpus only, without the network: a match\nis not confirmed with the release history and, for npm, the downloads and maintainers")
	nowFlag := fs.String("now", "", "time (RFC 3339) against which the release history is judged, for reproducible runs")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if *top < 0 {
		fmt.Fprintln(os.Stderr, "error: --top must not be negative")
		return exitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: ssca typosquat [--ecosystem npm|pypi] [--top N] [--names-only] [--offline] NAME...")
		return exitUsage
	}
	// Maven has no corpus of popular names: an empty corpus would report
	// every name as "ok"
	switch *eco {
	case "npm", "pypi":
	case "maven":
		fmt.Fprintln(os.Stderr, "error: no corpus of popular Maven names: typosquat checks npm or pypi names")
		return exitUsage
	default:
		fmt.Fprintf(os.Stderr, "error: unknown ecosystem %q (npm or pypi)\n", *eco)
		return exitUsage
	}
	for _, n := range fs.Args() {
		if strings.TrimSpace(n) == "" {
			fmt.Fprintln(os.Stderr, "error: empty package name")
			return exitUsage
		}
	}
	now, ok := parseNow(*nowFlag)
	if !ok {
		return exitUsage
	}
	if *namesOnly {
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		for _, f := range []string{"offline", "cache", "now"} {
			if set[f] {
				fmt.Fprintf(os.Stderr, "error: --%s does not apply to --names-only, which reads no registry data\n", f)
				return exitUsage
			}
		}
	}
	corpus, src, err := data.Corpus(*eco, *top)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	ix := risk.NewIndex(*eco, corpus, nil)
	check := func(n string) typoResult { return typoResult{squats: ix.Check(n, -1)} }
	var net *netx.Client
	if !*namesOnly {
		net = g.client()
		c := &squatConfirmer{eco: *eco, now: nowOr(now), col: risk.NewCollector(net, nowOr(now)), reg: npm.NewRegistry(net)}
		check = func(n string) typoResult { return c.check(n, ix.Check(n, -1)) }
	}
	// the result is printed only after the self-check of a sealed snapshot
	var buf bytes.Buffer
	suspect := printTyposquat(&buf, *eco, ix.Size(), src, fs.Args(), check)
	if !selfCheck(net) {
		return exitSelfCheck
	}
	_, _ = buf.WriteTo(os.Stdout)
	if suspect {
		return exitViolation
	}
	return exitOK
}

// typoResult is the outcome for one name: the look-alike targets of the
// corpus; dismissed, why a match is no typosquat after all; note, why a
// match that stands could not be confirmed with registry data.
type typoResult struct {
	squats    []risk.Squat
	dismissed string
	note      string
}

// squatConfirmer confirms a name match as scan does (internal/core): a
// package with years of release history is established and no typosquat
// (risk.Established), and an npm candidate is re-checked with its downloads
// and maintainers (risk.ConfirmNPMSquat).
type squatConfirmer struct {
	eco string
	now time.Time
	col *risk.Collector
	reg *npm.RegistryClient
}

func (c *squatConfirmer) check(name string, squats []risk.Squat) typoResult {
	r := typoResult{squats: squats}
	if len(squats) == 0 {
		return r
	}
	ctx := context.Background()
	m, err := c.col.History(ctx, c.eco, name)
	switch {
	case errors.Is(err, netx.ErrNotFound):
		r.note = "not in the " + map[string]string{model.NPM: "npm registry", model.PyPI: "PyPI index"}[c.eco]
		return r
	case err != nil:
		r.note = "release history unavailable: " + err.Error()
		return r
	}
	if ok, why := risk.Established(m, c.now); ok {
		r.dismissed = why
		return r
	}
	if c.eco == model.NPM {
		p, err := c.reg.Packument(ctx, name)
		if err != nil {
			r.note = "npm registry unavailable: " + err.Error()
			return r
		}
		if latest := p.DistTags["latest"]; latest != "" {
			if ok, _, why := risk.ConfirmNPMSquat(ctx, c.reg, name, latest, squats[0].Target); !ok {
				r.dismissed = why
			}
		}
	}
	return r
}

// printTyposquat prints one line per name, with all look-alike targets on
// it, and reports whether any name is suspect.
func printTyposquat(w io.Writer, eco string, size int, src string, names []string, check func(string) typoResult) bool {
	// the source description of the corpus is long; its first part names it
	if i := strings.Index(src, ";"); i > 0 {
		src = src[:i]
	}
	fmt.Fprintf(w, "corpus: %d %s names (%s)\n", size, eco, strings.TrimSpace(src))
	width := 0
	for _, n := range names {
		width = max(width, len(n))
	}
	suspect := 0
	for _, n := range names {
		res := check(n)
		if len(res.squats) == 0 {
			fmt.Fprintf(w, "  %-*s  ok\n", width, n)
			continue
		}
		var parts []string
		for _, s := range res.squats {
			parts = append(parts, fmt.Sprintf("%s (%.2f, %s)", s.Target, s.Similarity, strings.ReplaceAll(s.Class, "-", " ")))
		}
		if res.dismissed != "" {
			fmt.Fprintf(w, "  %-*s  ok: like %s, but %s\n", width, n, strings.Join(parts, ", "), res.dismissed)
			continue
		}
		suspect++
		line := fmt.Sprintf("  %-*s  suspect: %s", width, n, strings.Join(parts, ", "))
		if res.note != "" {
			line += " (" + res.note + ")"
		}
		fmt.Fprintln(w, line)
	}
	switch {
	case suspect == 1:
		fmt.Fprintf(w, "1 of %s looks like a popular package\n", count(len(names), "name"))
	case suspect > 1:
		fmt.Fprintf(w, "%d of %s look like popular packages\n", suspect, count(len(names), "name"))
	}
	return suspect > 0
}
