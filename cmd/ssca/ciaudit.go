// ci-audit: audit of CI workflows and local actions (M5).

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/ciaudit"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
)

func cmdCIAudit(args []string) int {
	fs := flag.NewFlagSet("ci-audit", flag.ContinueOnError)
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", dir)
		return exitUsage
	}
	findings, files, problems := ciaudit.Audit(dir)
	printCIAudit(os.Stdout, findings, files, problems)
	for _, f := range findings {
		if model.SeverityRank(f.Severity) >= model.SeverityRank(model.SevHigh) {
			return exitViolation
		}
	}
	if len(problems) > 0 {
		return exitIncomplete
	}
	return exitOK
}

// printCIAudit groups the findings by file, in the order of the files, and
// orders them by line; the explanation of a finding is wrapped below its
// title.
func printCIAudit(w io.Writer, findings []*model.Finding, files, problems []string) {
	head := fmt.Sprintf("%s (workflows and local actions), %s", count(len(files), "CI file"), count(len(findings), "finding"))
	if len(findings) > 0 {
		sevs := make([]string, len(findings))
		for i, f := range findings {
			sevs[i] = f.Severity
		}
		head += ": " + severityCounts(sevs)
	}
	fmt.Fprintln(w, head+incompleteMark(problems))
	byFile := map[string][]*model.Finding{}
	var order []string
	for _, f := range findings {
		if byFile[f.File] == nil {
			order = append(order, f.File)
		}
		byFile[f.File] = append(byFile[f.File], f)
	}
	for _, file := range order {
		fs := byFile[file]
		slices.SortStableFunc(fs, func(a, b *model.Finding) int {
			if a.Line != b.Line {
				return a.Line - b.Line
			}
			return bySeverity(a.Severity, b.Severity)
		})
		lw := len(strconv.Itoa(fs[len(fs)-1].Line))
		fmt.Fprintf(w, "\n%s (%s)\n", file, count(len(fs), "finding"))
		for _, f := range fs {
			fmt.Fprintf(w, "  %*d  %-8s  %s\n", lw, f.Line, f.Severity, f.Title)
			if f.Detail != "" {
				indent := fmt.Sprintf("%*s", 2+lw+2+8+2, "")
				fmt.Fprintln(w, wrap(f.Detail, 96-len(indent), indent))
			}
		}
	}
	if len(problems) > 0 {
		fmt.Fprintln(w)
		for _, p := range report.CompactIncomplete(problems, 5) {
			fmt.Fprintln(w, "  incomplete:", p)
		}
	}
}
