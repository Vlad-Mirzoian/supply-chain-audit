// output: helpers for the text output of the subcommands, which people read
// in a terminal; scripts use the exit codes and the --json output.

package main

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
)

// count is "1 cycle", "4 cycles"; plural is the plural form of word if it is
// not word+"s".
func count(n int, word string, plural ...string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	if len(plural) > 0 {
		return fmt.Sprintf("%d %s", n, plural[0])
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// incompleteMark ends the first line of an incomplete result, so that it is
// visible with head -1.
func incompleteMark(reasons []string) string {
	switch n := len(report.CompactIncomplete(reasons, 5)); n {
	case 0:
		return ""
	case 1:
		return " — INCOMPLETE (1 reason, see below)"
	default:
		return fmt.Sprintf(" — INCOMPLETE (%d reasons, see below)", n)
	}
}

// printIncomplete lists the reasons of an incomplete analysis. The snapshot
// is named only when data was missing from it, not for problems of the
// project itself (an out-of-sync lockfile).
func printIncomplete(w io.Writer, g *global, reasons []string) {
	for _, s := range report.CompactIncomplete(reasons, 5) {
		fmt.Fprintln(w, "  incomplete:", s)
	}
	if g.offline && slices.ContainsFunc(reasons, func(s string) bool { return strings.Contains(s, netx.ErrOffline.Error()) }) {
		fmt.Fprintf(w, "  (offline data snapshot: %s; --json lists every reason)\n", g.cacheDir)
	}
}

// bySeverity orders findings or changes from critical to info; the sort is
// stable, so items of one severity keep their order.
func bySeverity(a, b string) int { return model.SeverityRank(b) - model.SeverityRank(a) }

// severityCounts is "2 critical, 5 high, 13 medium" for the severities that
// occur, from critical to info.
func severityCounts(sevs []string) string {
	n := map[string]int{}
	for _, s := range sevs {
		n[s]++
	}
	var parts []string
	for _, s := range []string{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo} {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

// wrap breaks text into lines of at most width characters (a longer word,
// such as a URL, gets a line of its own) and indents every line.
func wrap(text string, width int, indent string) string {
	var b strings.Builder
	line := 0
	for _, word := range strings.Fields(text) {
		n := len([]rune(word))
		switch {
		case line == 0:
			b.WriteString(indent)
		case line+1+n > width:
			b.WriteString("\n" + indent)
			line = 0
		default:
			b.WriteByte(' ')
			line++
		}
		b.WriteString(word)
		line += n
	}
	return b.String()
}
