// scan: the full audit with policy evaluation (M0-M6).

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/core"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/policy"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// listFlag is a repeatable string flag (--vex).
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	g := addGlobal(fs)
	g.addIncludeDev(fs)
	policyPath := fs.String("policy", "", "policy file (default: .ssca/policy.yaml of the project if present,\nelse the built-in policy of Listing 3.1; \"builtin\" forces the built-in policy)")
	out := fs.String("out", "ssca-out", "output directory for reports and the evidence bundle")
	var vex listFlag
	fs.Var(&vex, "vex", "VEX document (OpenVEX or CycloneDX), repeatable")
	reachFlag := fs.Bool("reachability", false, "enable package-level reachability analysis (downloads archives)")
	prov := fs.Bool("provenance", true, "verify npm provenance and PEP 740 attestations with Sigstore")
	noMeta := fs.Bool("no-metadata", false, "skip registry metadata (health and malice signals)")
	quiet := fs.Bool("quiet", false, "do not print the summary")
	nowFlag := fs.String("now", "", "evaluation time (RFC 3339), for reproducible runs")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	dir, ok := projectDir(fs)
	if !ok || !g.checkTarget(dir) {
		return exitUsage
	}
	polFile, discovered := policy.Find(dir, *policyPath)
	pol, err := policy.Load(polFile)
	if err != nil {
		if polFile != "" {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", polFile, err)
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		return exitUsage
	}
	polInfo, err := policyInfo(dir, polFile, discovered, pol)
	polInfo.Forced = *policyPath == policy.Builtin
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsage
	}
	vex = append(vex, pol.VEX...)
	// a faulty VEX document is a usage error like a faulty policy, and it is
	// reported before any network access
	if len(vex) > 0 {
		if _, err := vuln.LoadVEX(vex); err != nil {
			fmt.Fprintln(os.Stderr, "error: VEX:", err)
			return exitUsage
		}
	}
	if pol.Provenance != nil {
		// the policy decides, also against the command line: a pull request
		// cannot switch the verification off with a flag in the workflow
		set := false
		fs.Visit(func(f *flag.Flag) { set = set || f.Name == "provenance" })
		if set && *prov != *pol.Provenance {
			fmt.Fprintf(os.Stderr, "warning: --provenance=%t is overridden by verify_provenance: %t of the policy\n", *prov, *pol.Provenance)
		}
		*prov = *pol.Provenance
	}
	now, ok := parseNow(*nowFlag)
	if !ok {
		return exitUsage
	}
	opts := core.Options{
		Dir: dir, Ecosystem: g.eco, IncludeDev: g.dev, RuntimeOnly: g.runtime, ForceResolve: g.resolve, Net: g.client(),
		CacheDir: g.cacheDir, Offline: g.offline, Policy: pol, VEX: vex,
		Reachability: *reachFlag || pol.Reachability, Provenance: *prov, NoMetadata: *noMeta,
		Now: now, Version: Version,
	}
	rep, doc, err := core.Scan(context.Background(), opts)
	if err != nil {
		var sc core.SelfCheckError
		if errors.As(err, &sc) {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitSelfCheck
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return buildExit(err)
	}
	rep.Policy = polInfo
	created := nowOr(now)
	// the root is named as by the sbom command (npm "@scope/name", Maven
	// "group:artifact"), not by the last segment of its purl
	cdx, err := doc.CycloneDX(doc.RootName, doc.RootVersion)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: CycloneDX SBOM:", err)
		return exitIncomplete
	}
	spdx, err := doc.SPDX(doc.RootName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: SPDX SBOM:", err)
		return exitIncomplete
	}
	extra := map[string][]byte{"sbom.cdx.json": cdx, "sbom.spdx.json": spdx}
	if v := autoVEX(rep, created); v != nil {
		extra["reachability.openvex.json"] = v
	}
	if err := rep.Evidence(*out, extra, created); err != nil {
		fmt.Fprintln(os.Stderr, "error writing evidence:", err)
		return exitIncomplete
	}
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if err := appendFile(p, rep.Markdown()); err != nil {
			// the reports are written and the decision stands; only the job
			// summary of GitHub Actions is missing
			fmt.Fprintln(os.Stderr, "warning: GITHUB_STEP_SUMMARY:", err)
		}
	}
	if !*quiet {
		fmt.Print(rep.Markdown())
		fmt.Printf("\nreports written to %s (exit code %d)\n", *out, rep.Decision.ExitCode)
	}
	for _, w := range unlockedWarnings(rep.Project.Inputs, rep.Components, "") {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	return rep.Decision.ExitCode
}

// appendFile appends text to the file at path, creating it if needed.
func appendFile(path, text string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// buildExit is the exit code of a dependency graph that could not be built:
// a directory without any supported project file is a usage error (a wrong
// directory, as one that does not exist), anything else exit code 2.
func buildExit(err error) int {
	if errors.Is(err, core.ErrNoProject) {
		return exitUsage
	}
	return exitIncomplete
}

// policyInfo records which policy a scan applied: the file (relative to the
// project directory when it was found there) and its SHA-256, or the
// built-in policy; a file that extends the built-in policy also names the
// SHA-256 of the built-in policy.
func policyInfo(dir, file string, discovered bool, pol *policy.Policy) (report.PolicyInfo, error) {
	builtin := sha256.Sum256([]byte(policy.Default))
	if file == "" {
		return report.PolicyInfo{Source: "built-in", SHA256: hex.EncodeToString(builtin[:])}, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return report.PolicyInfo{}, err
	}
	h := sha256.Sum256(b)
	src := file
	if discovered {
		if rel, err := filepath.Rel(dir, file); err == nil {
			src = filepath.ToSlash(rel)
		}
	}
	info := report.PolicyInfo{Source: src, SHA256: hex.EncodeToString(h[:]), Discovered: discovered}
	if pol != nil && pol.Extends == policy.Builtin {
		info.Extends = "built-in sha256:" + hex.EncodeToString(builtin[:])
	}
	return info, nil
}

// autoVEX turns "not reachable" results into an OpenVEX document so that the
// analysis can be reviewed and reused (justification
// vulnerable_code_not_in_execute_path).
func autoVEX(r *report.Report, created time.Time) []byte {
	var stmts []map[string]any
	for _, f := range r.Findings {
		if f.Vuln == nil || f.Kind != model.KindVulnerability || f.Vuln.Reachable != "no" {
			continue
		}
		stmts = append(stmts, map[string]any{
			"vulnerability": map[string]any{"name": f.ID, "aliases": f.Vuln.Aliases},
			"products":      []map[string]string{{"@id": f.Component}},
			"status":        "not_affected", "justification": "vulnerable_code_not_in_execute_path",
			"impact_statement": "package is not imported by the application or by any reachable dependency (ssca package-level reachability)",
		})
	}
	if len(stmts) == 0 {
		return nil
	}
	b, _ := json.MarshalIndent(map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://ssca.local/vex/" + r.Snapshot,
		"author": "ssca " + r.Version + " (automated, requires review)", "timestamp": created.UTC().Format(time.RFC3339),
		"version": 1, "statements": stmts,
	}, "", "  ")
	return b
}
