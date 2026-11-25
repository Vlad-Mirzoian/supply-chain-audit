// diff: comparison of two SBOMs (Algorithm 3.4).

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	mode := fs.String("mode", string(sbom.DeclaredVsObserved), "declared-vs-observed | release-vs-release | vendor-vs-generated")
	asJSON := fs.Bool("json", false, "print JSON")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: ssca diff [--mode M] baseline.json compared.json")
		return exitUsage
	}
	switch sbom.Mode(*mode) {
	case sbom.DeclaredVsObserved, sbom.ReleaseVsRelease, sbom.VendorVsGenerated:
	default:
		fmt.Fprintf(os.Stderr, "error: unknown mode %q (declared-vs-observed, release-vs-release or vendor-vs-generated)\n", *mode)
		return exitUsage
	}
	a, err := sbom.Read(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	b, err := sbom.Read(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	res := sbom.Diff(a, b, sbom.Mode(*mode), vuln.Compare, nil)
	if *asJSON {
		// the reasons why an input SBOM may lack components, by file, as
		// the text output notes them
		inc := map[string][]string{}
		for _, x := range []struct {
			name string
			d    *sbom.Doc
		}{{fs.Arg(0), a}, {fs.Arg(1), b}} {
			if len(x.d.Incomplete) > 0 {
				inc[x.name] = x.d.Incomplete
			}
		}
		out, _ := json.MarshalIndent(struct {
			sbom.DiffResult
			Incomplete map[string][]string `json:"incomplete,omitempty"`
		}{res, inc}, "", "  ")
		fmt.Println(string(out))
	} else {
		printDiff(os.Stdout, fs.Arg(0), fs.Arg(1), a, b, res)
	}
	return diffExit(a, b, res)
}

// diffExit is 1 if a change is high or critical; otherwise 2 if one of the
// SBOMs states that it is incomplete (its missing packages may hide or fake
// changes, so the result is not a pass), else 0.
func diffExit(a, b *sbom.Doc, res sbom.DiffResult) int {
	for _, c := range res.Changes {
		if model.SeverityRank(c.Severity) >= model.SeverityRank(model.SevHigh) {
			return exitViolation
		}
	}
	if len(a.Incomplete) > 0 || len(b.Incomplete) > 0 {
		return exitIncomplete
	}
	return exitOK
}

// printDiff is the text form of the diff: a header with the similarity and
// the number of changes per severity, then one line per change, the most
// severe first.
func printDiff(w io.Writer, nameA, nameB string, a, b *sbom.Doc, res sbom.DiffResult) {
	mark := ""
	if len(a.Incomplete) > 0 || len(b.Incomplete) > 0 {
		mark = " — INCOMPLETE (see below)"
	}
	fmt.Fprintf(w, "%s: %s (%s) → %s (%s)%s\n", res.Mode, nameA, count(len(a.Components), "component"), nameB, count(len(b.Components), "component"), mark)
	for _, x := range []struct {
		name string
		d    *sbom.Doc
	}{{nameA, a}, {nameB, b}} {
		if len(x.d.Incomplete) > 0 {
			fmt.Fprintf(w, "  note: %s states that it is incomplete, so missing packages may not be real changes\n", x.name)
		}
	}
	union := res.Both + res.OnlyA + res.OnlyB
	sim := fmt.Sprintf("similarity %.3f (Jaccard: %d of %s in both)", res.Jaccard, res.Both, count(union, "package"))
	if len(res.Changes) == 0 {
		fmt.Fprintf(w, "%s, no changes\n", sim)
		return
	}
	sevs := make([]string, len(res.Changes))
	for i, c := range res.Changes {
		sevs[i] = c.Severity
	}
	fmt.Fprintf(w, "%s, %s: %s\n", sim, count(len(res.Changes), "change"), severityCounts(sevs))
	if res.Mode == sbom.DeclaredVsObserved && slices.ContainsFunc(res.Changes, func(c sbom.Change) bool { return c.Class == "MISSING" || c.Class == "PHANTOM" }) {
		fmt.Fprintln(w, "  (MISSING: declared in the first SBOM only; PHANTOM: observed in the second SBOM only)")
	}
	changes := slices.Clone(res.Changes)
	slices.SortStableFunc(changes, func(x, y sbom.Change) int { return bySeverity(x.Severity, y.Severity) })
	cw, kw := 0, 0
	for _, c := range changes {
		cw = max(cw, len(c.Class))
		if !strings.HasPrefix(c.Class, "EDGE_") {
			kw = max(kw, len(c.Key))
		}
	}
	kw = min(kw, 40)
	for _, c := range changes {
		var what string
		switch {
		case strings.HasPrefix(c.Class, "EDGE_"):
			// the key of an edge change is its target; From and To are the edge
			what = c.From + " → " + c.To
		case c.From == "":
			what = fmt.Sprintf("%-*s  %s", kw, c.Key, versions(c.To))
		case c.To == "":
			what = fmt.Sprintf("%-*s  %s", kw, c.Key, versions(c.From))
		default:
			what = fmt.Sprintf("%-*s  %s → %s", kw, c.Key, versions(c.From), versions(c.To))
		}
		if c.Detail != "" {
			what += " (" + c.Detail + ")"
		}
		fmt.Fprintf(w, "  %-8s %-*s  %s\n", c.Severity, cw, c.Class, strings.TrimRight(what, " "))
	}
}

// versions separates the versions of a package that occurs several times.
func versions(v string) string { return strings.ReplaceAll(v, ",", ", ") }
