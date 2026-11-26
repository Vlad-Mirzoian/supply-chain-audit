// sbom: CycloneDX and SPDX SBOMs, or the CISA minimum-element check of an existing SBOM (M1).

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/core"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
)

func cmdSBOM(args []string) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	g := addGlobal(fs)
	out := fs.String("out", ".", "output directory")
	validate := fs.String("validate", "", "assess an existing SBOM against the CISA minimum elements instead")
	fs.Bool("enrich", false, "kept for compatibility: the SBOM is enriched by default (see --no-enrich)")
	noEnrich := fs.Bool("no-enrich", false, "write only what the lockfiles and manifests record: no suppliers, licenses or\nregistry hashes (Maven jar SHA-1, SHA-256 of the PyPI files); without them most\nSBOMs miss CISA minimum elements. By default these are taken from the registries\n(with --offline from the data snapshot; what is not there stays empty)")
	asJSON := fs.Bool("json", false, "with --validate: print the assessment as JSON")
	minScore := fs.Float64("min-score", defaultMinScore, "with --validate: lowest acceptable CISA score in percent; below it the exit code is 1")
	nowFlag := fs.String("now", "", "creation time of the SBOMs (RFC 3339) instead of the time of the run: the same\nproject and data snapshot then give byte-identical SBOMs")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if *minScore < 0 || *minScore > 100 {
		fmt.Fprintf(os.Stderr, "error: --min-score %v is not a percentage from 0 to 100\n", *minScore)
		return exitUsage
	}
	if strings.HasPrefix(*validate, "-") {
		fmt.Fprintf(os.Stderr, "error: --validate needs the SBOM file right after it, got %q (other flags go before --validate)\n", *validate)
		return exitUsage
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *validate == "" {
		for _, f := range []string{"min-score", "json"} {
			if set[f] {
				fmt.Fprintf(os.Stderr, "error: --%s applies only to --validate\n", f)
				return exitUsage
			}
		}
	}
	if set["enrich"] && set["no-enrich"] {
		fmt.Fprintln(os.Stderr, "error: --enrich and --no-enrich exclude each other")
		return exitUsage
	}
	if *validate != "" && (set["enrich"] || set["no-enrich"]) {
		fmt.Fprintln(os.Stderr, "error: --enrich and --no-enrich apply only to generating an SBOM, not to --validate")
		return exitUsage
	}
	if *validate != "" {
		// these would be silently ignored: --validate reads a file and
		// builds no graph
		for _, f := range []string{"out", "ecosystem", "runtime-only", "resolve", "now", "offline", "cache"} {
			if set[f] {
				fmt.Fprintf(os.Stderr, "error: --%s applies only to generating an SBOM, not to --validate\n", f)
				return exitUsage
			}
		}
		if fs.NArg() > 0 {
			fmt.Fprintf(os.Stderr, "error: --validate assesses the file %s and takes no project directory (got %s)\n", *validate, strings.Join(fs.Args(), " "))
			return exitUsage
		}
	}
	if *validate != "" {
		d, err := sbom.Read(*validate)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitUsage
		}
		c := d.Assess()
		verdict, code := assessVerdict(d, c, *minScore)
		if *asJSON {
			b, _ := json.MarshalIndent(map[string]any{"format": d.Format, "components": len(d.Components), "edges": len(d.Edges),
				"completeness": c, "incomplete": d.Incomplete, "min_score": *minScore, "verdict": verdict}, "", "  ")
			fmt.Println(string(b))
		} else {
			printAssessment(os.Stdout, *validate, d, c, *minScore, verdict)
		}
		return code
	}
	now, ok := parseNow(*nowFlag)
	if !ok {
		return exitUsage
	}
	dir, ok := projectDir(fs)
	if !ok || !g.checkTarget(dir) {
		return exitUsage
	}
	// one client for the graph and the enrichment: one cache, one count
	// of requests and one self-check of a sealed snapshot
	net := g.client()
	gr, _, err := core.BuildGraph(context.Background(), dir, g.eco, graphOptions(g, net))
	if err == nil && !*noEnrich {
		col := risk.NewCollector(net, nowOr(now))
		col.ArtifactHashes = true
		col.Collect(context.Background(), gr.Components())
	}
	if !selfCheck(net) {
		return exitSelfCheck
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return buildExit(err)
	}
	doc := sbom.FromGraph(gr, Version, nowOr(now))
	cdx, err := doc.CycloneDX(doc.RootName, doc.RootVersion)
	var spdx []byte
	if err == nil {
		spdx, err = doc.SPDX(doc.RootName)
	}
	if err == nil {
		err = os.MkdirAll(*out, 0o755)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(*out, "sbom.cdx.json"), cdx, 0o644)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(*out, "sbom.spdx.json"), spdx, 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitIncomplete
	}
	// the SBOMs are written also for an incomplete graph (they record it),
	// but the exit code is 2 as for graph and scan
	fmt.Printf("%s written to %s: sbom.cdx.json (CycloneDX 1.6), sbom.spdx.json (SPDX 2.3)%s\n",
		count(len(doc.Components), "component"), *out, incompleteMark(gr.Incomplete))
	printIncomplete(os.Stdout, g, gr.Incomplete)
	for _, w := range unlockedWarnings(gr.Inputs, gr.Components(), ", and the SBOM can only record the hashes that the registry publishes") {
		fmt.Println("warning:", w)
	}
	return graphExit(gr)
}

// unlockedWarnings names the ecosystems whose dependencies come from
// manifests without a lockfile (core.Unlocked). Without a lockfile npm
// marks the graph incomplete; PyPI does not (a requirements file is a valid
// input) unless the policy sets thresholds.unpinned_dependencies: fail, so
// for PyPI this warning is otherwise the only hint. Maven has no lockfile
// and is not named. consequence is added for the command (sbom: the SBOM
// records only registry hashes).
func unlockedWarnings(inputs []string, comps []*model.Component, consequence string) []string {
	unpinned := core.Unlocked(inputs, comps)
	advice := map[string]string{
		model.NPM:  "npm install --package-lock-only",
		model.PyPI: "uv lock, poetry lock or pip-compile --generate-hashes",
	}
	label := map[string]string{model.NPM: "npm", model.PyPI: "PyPI"}
	var out []string
	for _, eco := range []string{model.NPM, model.PyPI} {
		if unpinned[eco] > 0 {
			out = append(out, fmt.Sprintf("no lockfile for the %s dependencies: %s not pinned with a hash by the project, and every version "+
				"that the manifests do not pin exactly (transitive ones included) is resolved at this run, so it can differ from what an "+
				"installation gets%s; pin versions and hashes with a lockfile (%s)",
				label[eco], count(unpinned[eco], "package version is", "package versions are"), consequence, advice[eco]))
		}
	}
	return out
}

// defaultMinScore is the lowest CISA score (percent) that sbom --validate
// accepts unless --min-score says otherwise: at most two of the 11 elements
// may be missing altogether (9/11 is 82 %, 8/11 is 73 %).
const defaultMinScore = 80.0

// assessVerdict is the decision of sbom --validate. An incomplete SBOM comes
// first: its score says nothing reliable, so it is exit code 2 and not a
// violation. An SBOM without components has nothing to assess.
func assessVerdict(d *sbom.Doc, c sbom.Completeness, minScore float64) (string, int) {
	switch {
	case len(d.Incomplete) > 0:
		return "INCOMPLETE", exitIncomplete
	case len(d.Components) == 0 || c.Score*100 < minScore:
		return "FAIL", exitViolation
	}
	return "PASS", exitOK
}

// cisaElements lists the minimum elements in the order of the CISA document,
// with the labels of the text output; perComponent elements are shares of
// the components, the others are properties of the document.
var cisaElements = []struct {
	key, label   string
	perComponent bool
}{
	{"component_name", "component name", true},
	{"version", "version", true},
	{"identifier", "identifier (purl)", true},
	{"producer", "producer (supplier)", true},
	{"hash", "hash", true},
	{"license", "license", true},
	{"dependency_relationships", "dependency relationships", false},
	{"sbom_author", "SBOM author", false},
	{"tool", "tool", false},
	{"timestamp", "timestamp", false},
	{"generation_context", "generation context", false},
}

// printAssessment is the text form of sbom --validate.
func printAssessment(w io.Writer, path string, d *sbom.Doc, c sbom.Completeness, minScore float64, verdict string) {
	n := len(d.Components)
	mark := incompleteMark(d.Incomplete)
	if verdict == "FAIL" {
		mark = fmt.Sprintf(" — FAIL (CISA score %s, required %g %%)", pct(c.Score), minScore)
		if n == 0 {
			mark = " — FAIL (no components to assess)"
		}
	}
	fmt.Fprintf(w, "%s: %s SBOM, %s, %s%s\n", path, d.Format, count(n, "component"), count(len(d.Edges), "dependency relationship"), mark)
	fmt.Fprintf(w, "CISA minimum elements: %s (mean of %d elements)\n", pct(c.Score), len(c.Elements))
	for _, e := range cisaElements {
		v, ok := c.Elements[e.key]
		switch {
		case !ok:
			fmt.Fprintf(w, "  %-26s %s\n", e.label, "n/a (no components)")
		case e.perComponent:
			k := int(math.Round(v * float64(n)))
			fmt.Fprintf(w, "  %-26s %5s   %d of %d\n", e.label, pct(v), k, n)
		case v == 1:
			fmt.Fprintf(w, "  %-26s %5s\n", e.label, "yes")
		case e.key == "dependency_relationships" && len(d.Incomplete) > 0:
			fmt.Fprintf(w, "  %-26s %5s   the SBOM states that it is incomplete\n", e.label, "no")
		default:
			fmt.Fprintf(w, "  %-26s %5s\n", e.label, "no")
		}
	}
	// the reasons come from the file: the snapshot of this run (there is
	// none) is not named
	printIncomplete(w, &global{}, d.Incomplete)
}

// pct is a share as a whole percentage; a share that is not exactly 0 or 1
// is never rounded to 0 % or 100 %.
func pct(v float64) string {
	p := math.Round(v * 100)
	if p == 0 && v > 0 {
		p = 1
	}
	if p == 100 && v < 1 {
		p = 99
	}
	return fmt.Sprintf("%d %%", int(p))
}
