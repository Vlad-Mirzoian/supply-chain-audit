// typosquat: offline check of package names (Algorithm 3.2).

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/data"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
)

func cmdTyposquat(args []string) int {
	fs := flag.NewFlagSet("typosquat", flag.ContinueOnError)
	eco := fs.String("ecosystem", "npm", "npm or pypi")
	top := fs.Int("top", 0, "use only the N most popular names of the corpus")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: ssca typosquat [--ecosystem npm|pypi] [--top N] NAME...")
		return exitUsage
	}
	// Maven has no corpus of popular names: an empty corpus would report
	// every name as "ok"
	if *eco != "npm" && *eco != "pypi" {
		fmt.Fprintf(os.Stderr, "error: no corpus of popular names for ecosystem %q (npm or pypi)\n", *eco)
		return exitUsage
	}
	for _, n := range fs.Args() {
		if strings.TrimSpace(n) == "" {
			fmt.Fprintln(os.Stderr, "error: empty package name")
			return exitUsage
		}
	}
	corpus, src, err := data.Corpus(*eco, *top)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	ix := risk.NewIndex(*eco, corpus, nil)
	if printTyposquat(os.Stdout, *eco, ix.Size(), src, fs.Args(), func(n string) []risk.Squat { return ix.Check(n, -1) }) {
		return exitViolation
	}
	return exitOK
}

// printTyposquat prints one line per name, with all look-alike targets on
// it, and reports whether any name is suspect.
func printTyposquat(w io.Writer, eco string, size int, src string, names []string, check func(string) []risk.Squat) bool {
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
		if len(res) == 0 {
			fmt.Fprintf(w, "  %-*s  ok\n", width, n)
			continue
		}
		suspect++
		var parts []string
		for _, s := range res {
			parts = append(parts, fmt.Sprintf("%s (%.2f, %s)", s.Target, s.Similarity, strings.ReplaceAll(s.Class, "-", " ")))
		}
		fmt.Fprintf(w, "  %-*s  suspect: %s\n", width, n, strings.Join(parts, ", "))
	}
	switch {
	case suspect == 1:
		fmt.Fprintf(w, "1 of %s looks like a popular package\n", count(len(names), "name"))
	case suspect > 1:
		fmt.Fprintf(w, "%d of %s look like popular packages\n", suspect, count(len(names), "name"))
	}
	return suspect > 0
}
