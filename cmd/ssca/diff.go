// diff: comparison of two SBOMs (M1).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/report"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

func cmdDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	g := addNet(fs)
	mode := fs.String("mode", string(sbom.DeclaredVsObserved), "declared-vs-observed | release-vs-release | vendor-vs-generated")
	asJSON := fs.Bool("json", false, "print JSON")
	nowFlag := fs.String("now", "", "release-vs-release: time (RFC 3339) against which the age of an added package\nis judged (default: the timestamp of the second SBOM, else the time of the run)")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	now, ok := parseNow(*nowFlag)
	if !ok {
		return exitUsage
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: ssca diff [--mode M] [--json] [--offline] [--now T] baseline.json compared.json")
		return exitUsage
	}
	switch sbom.Mode(*mode) {
	case sbom.ReleaseVsRelease:
	case sbom.DeclaredVsObserved, sbom.VendorVsGenerated:
		// only release-vs-release reads release histories: in the other
		// modes these flags would be silently ignored
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		for _, f := range []string{"now", "offline", "cache"} {
			if set[f] {
				fmt.Fprintf(os.Stderr, "error: --%s applies only to --mode release-vs-release, which reads the release history of added packages\n", f)
				return exitUsage
			}
		}
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
	ages := &packageAges{g: g, ref: diffTime(now, b)}
	var young func(string) bool
	if sbom.Mode(*mode) == sbom.ReleaseVsRelease {
		young = ages.young
	}
	res := sbom.Diff(a, b, sbom.Mode(*mode), vuln.Compare, young)
	if !selfCheck(ages.net) {
		return exitSelfCheck
	}
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
			UnknownAge []string            `json:"unknown_age,omitempty"`
		}{res, inc, ages.unknown}, "", "  ")
		fmt.Println(string(out))
	} else {
		printDiff(os.Stdout, fs.Arg(0), fs.Arg(1), a, b, res, ages)
	}
	return diffExit(a, b, res, ages.unknown)
}

// diffTime is the time against which the age of a package added in
// release-vs-release mode is judged: --now, else the creation time of the
// compared SBOM (a diff of two old releases judges the packages as they were
// at that release), else the time of the run.
func diffTime(now time.Time, b *sbom.Doc) time.Time {
	if !now.IsZero() {
		return now
	}
	if t, err := time.Parse(time.RFC3339, b.Timestamp); err == nil {
		return t
	}
	return time.Now()
}

// packageAges finds out, for release-vs-release, whether an added package is
// young: its first release is less than the cooldown period (7 days, as
// cooldown_days of the policy) before the reference time, as the
// young_new_dependency signal of scan judges a new dependency. The release
// history comes from deps.dev or the registry (the cache, with --offline the
// data snapshot), fetched only for added packages.
type packageAges struct {
	g       *global
	ref     time.Time
	net     *netx.Client
	col     *risk.Collector
	nYoung  int      // number of young packages
	unknown []string // added packages whose age could not be found, with the reason
}

func (p *packageAges) young(key string) bool {
	eco, name, ok := historyName(key)
	if !ok {
		return false
	}
	if p.col == nil {
		p.net = p.g.client()
		p.col = risk.NewCollector(p.net, p.ref)
	}
	m, err := p.col.History(context.Background(), eco, name)
	if err != nil {
		if !errors.Is(err, netx.ErrNotFound) {
			p.unknown = append(p.unknown, key+": "+err.Error())
		}
		return false
	}
	// an age that cannot be judged is not taken for an old package
	const day = "2006-01-02"
	switch {
	case m.FirstReleaseAt.IsZero():
		p.unknown = append(p.unknown, key+": the release history has no release dates")
		return false
	case m.FirstReleaseAt.After(p.ref):
		// the package is in the second SBOM but was first released only
		// after the time it is judged against: a wrong --now or SBOM
		// timestamp, or a name that was deleted and registered again
		p.unknown = append(p.unknown, fmt.Sprintf("%s: first release %s is later than %s, the time the age is judged against",
			key, m.FirstReleaseAt.UTC().Format(day), p.ref.UTC().Format(day)))
		return false
	}
	age := p.ref.Sub(m.FirstReleaseAt).Hours() / 24
	if age < risk.DefaultWeights().CooldownDays {
		p.nYoung++
		return true
	}
	return false
}

// historyName turns a version-less key of sbom.Key into the ecosystem and the
// package name of the registries and deps.dev (Maven "group:artifact");
// packages of other ecosystems have no release history here.
func historyName(key string) (eco, name string, ok bool) {
	typ, rest, _ := strings.Cut(key, "/")
	switch typ {
	case model.NPM, model.PyPI:
		return typ, rest, rest != ""
	case model.Maven:
		group, artifact, found := strings.Cut(rest, "/")
		return typ, group + ":" + artifact, found && group != "" && artifact != ""
	}
	return "", "", false
}

// diffExit is 1 if a change is high or critical; otherwise 2 if one of the
// SBOMs states that it is incomplete (its missing packages may hide or fake
// changes, so the result is not a pass) or if the age of an added package
// is unknown (it may be young), else 0.
func diffExit(a, b *sbom.Doc, res sbom.DiffResult, unknownAge []string) int {
	for _, c := range res.Changes {
		if model.SeverityRank(c.Severity) >= model.SeverityRank(model.SevHigh) {
			return exitViolation
		}
	}
	if len(a.Incomplete) > 0 || len(b.Incomplete) > 0 || len(unknownAge) > 0 {
		return exitIncomplete
	}
	return exitOK
}

// printDiff is the text form of the diff: a header with the similarity and
// the number of changes per severity, then one line per change, the most
// severe first.
func printDiff(w io.Writer, nameA, nameB string, a, b *sbom.Doc, res sbom.DiffResult, ages *packageAges) {
	mark := ""
	if len(a.Incomplete) > 0 || len(b.Incomplete) > 0 || len(ages.unknown) > 0 {
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
	if n := len(ages.unknown); n > 0 {
		pron := "they"
		if n == 1 {
			pron = "it"
		}
		fmt.Fprintf(w, "  note: the age of %s is unknown, so %s may be young:\n", count(n, "added package"), pron)
		for _, u := range report.CompactIncomplete(ages.unknown, 5) {
			fmt.Fprintln(w, "    "+u)
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
	if ages.nYoung > 0 {
		fmt.Fprintf(w, "  (young: the first release of the package is less than %g days before %s)\n", risk.DefaultWeights().CooldownDays, ages.ref.UTC().Format("2006-01-02 15:04 UTC"))
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
