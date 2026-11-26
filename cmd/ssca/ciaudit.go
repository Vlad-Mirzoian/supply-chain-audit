// ci-audit: audit of CI workflows and local actions (M5).

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/ciaudit"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
)

func cmdCIAudit(args []string) int {
	fs := flag.NewFlagSet("ci-audit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the audited files, the findings and the reasons of an incomplete audit as JSON")
	asSARIF := fs.Bool("sarif", false, "print the findings as SARIF 2.1.0 (for code scanning; the reasons of an\nincomplete audit are tool execution notifications)")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if *asJSON && *asSARIF {
		fmt.Fprintln(os.Stderr, "error: --json and --sarif exclude each other")
		return exitUsage
	}
	dir, ok := projectDir(fs)
	if !ok {
		return exitUsage
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", dir)
		return exitUsage
	}
	findings, files, problems := ciaudit.Audit(dir)
	switch {
	case *asJSON:
		printJSON(ciAuditJSON(dir, findings, files, problems))
	case *asSARIF:
		b, err := ciAuditSARIF(dir, findings, problems)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: SARIF:", err)
			return exitIncomplete
		}
		fmt.Println(string(b))
	default:
		printCIAudit(os.Stdout, findings, files, problems)
	}
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

// ciAuditJSON is the --json form of ci-audit: the audited files relative to
// the directory, the findings and the reasons why the audit is incomplete
// (empty lists rather than null).
func ciAuditJSON(dir string, findings []*model.Finding, files, problems []string) any {
	rel := []string{}
	for _, f := range files {
		if r, err := filepath.Rel(dir, f); err == nil {
			f = r
		}
		rel = append(rel, filepath.ToSlash(f))
	}
	return struct {
		Files      []string         `json:"files"`
		Findings   []*model.Finding `json:"findings"`
		Incomplete []string         `json:"incomplete"`
	}{rel, append([]*model.Finding{}, findings...), append([]string{}, problems...)}
}

// ciAuditSARIF is the SARIF form of ci-audit, written as the SARIF report of
// scan; the reasons of an incomplete audit are tool execution notifications
// of an unsuccessful invocation.
func ciAuditSARIF(dir string, findings []*model.Finding, problems []string) ([]byte, error) {
	b, err := (&report.Report{Version: Version, Project: report.Project{Dir: dir}, Findings: findings}).SARIF()
	if err != nil || len(problems) == 0 {
		return b, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var notes []map[string]any
	for _, p := range problems {
		notes = append(notes, map[string]any{"level": "error", "message": map[string]string{"text": p}})
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	run["invocations"] = []map[string]any{{"executionSuccessful": false, "toolExecutionNotifications": notes}}
	return json.MarshalIndent(doc, "", "  ")
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
	if len(files) == 0 && len(problems) == 0 {
		// exit code 0 with nothing audited: say what was looked for, so
		// that a wrong directory does not pass unnoticed
		fmt.Fprintln(w, "  no CI files found: ci-audit reads .github/workflows/*.yml and *.yaml, the local actions they use and .gitlab-ci.yml")
	}
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
