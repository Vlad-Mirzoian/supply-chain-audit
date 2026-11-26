package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/sbom"
)

// The text outputs that people read: counts with the right number, diff
// changes from the most severe and without dangling arrows, CI findings
// grouped by file in line order, one line per typosquat name.
func TestTextOutputs(t *testing.T) {
	if got := count(1, "cycle") + ", " + count(4, "cycle") + ", " + count(2, "dependency relationship"); got != "1 cycle, 4 cycles, 2 dependency relationships" {
		t.Errorf("count: %q", got)
	}
	if got := wrap("aaa bbb ccc ddd", 7, "  "); got != "  aaa bbb\n  ccc ddd" {
		t.Errorf("wrap: %q", got)
	}

	var b bytes.Buffer
	a := &sbom.Doc{Components: []sbom.Comp{{PURL: "pkg:npm/a@1.0.0"}, {PURL: "pkg:npm/d@1.0.0"}}}
	c := &sbom.Doc{Components: []sbom.Comp{{PURL: "pkg:npm/a@0.9.0"}}, Incomplete: []string{"x"}}
	res := sbom.Diff(a, c, sbom.ReleaseVsRelease, func(_, x, y string) int { return strings.Compare(x, y) }, nil)
	printDiff(&b, "A", "B", a, c, res)
	out := b.String()
	for _, want := range []string{"release-vs-release: A (2 components) → B (1 component)", "B states that it is incomplete",
		"similarity 0.500 (Jaccard: 1 of 2 packages in both), 2 changes: 1 medium, 1 info", "npm/a  1.0.0 → 0.9.0 (downgrade)"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "VERSION_CHANGED") > strings.Index(out, "REMOVED") || strings.Contains(out, "→ \n") || strings.Contains(out, "1.0.0 →\n") {
		t.Errorf("diff order or arrows:\n%s", out)
	}
	b.Reset()
	printDiff(&b, "A", "A", a, a, sbom.Diff(a, a, sbom.VendorVsGenerated, nil, nil))
	if !strings.Contains(b.String(), "similarity 1.000 (Jaccard: 2 of 2 packages in both), no changes") {
		t.Errorf("equal SBOMs: %s", b.String())
	}

	b.Reset()
	fs := []*model.Finding{
		{File: "w.yml", Line: 10, Severity: model.SevMedium, Title: "Ten", Detail: "detail of ten"},
		{File: "w.yml", Line: 3, Severity: model.SevHigh, Title: "Three"},
		{File: "a/action.yml", Line: 1, Severity: model.SevLow, Title: "One"},
	}
	var none bytes.Buffer
	printCIAudit(&none, nil, nil, nil)
	if !strings.Contains(none.String(), "no CI files found") {
		t.Errorf("ci-audit without CI files: %q", none.String())
	}
	printCIAudit(&b, fs, []string{"a/action.yml", "w.yml"}, []string{"local action missing"})
	out = b.String()
	for _, want := range []string{"2 CI files (workflows and local actions), 3 findings: 1 high, 1 medium, 1 low — INCOMPLETE (1 reason",
		"w.yml (2 findings)\n   3  high      Three\n  10  medium    Ten\n                detail of ten\n", "a/action.yml (1 finding)", "incomplete: local action missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("ci-audit output lacks %q:\n%s", want, out)
		}
	}

	b.Reset()
	suspect := printTyposquat(&b, "npm", 2, "corpus; long description", []string{"lodahs", "react"}, func(n string) []risk.Squat {
		if n == "lodahs" {
			return []risk.Squat{{Target: "lodash", Similarity: 0.92, Class: "edit-distance"}, {Target: "loadjs", Similarity: 0.83, Class: "edit-distance"}}
		}
		return nil
	})
	if want := "corpus: 2 npm names (corpus)\n  lodahs  suspect: lodash (0.92, edit distance), loadjs (0.83, edit distance)\n  react   ok\n1 of 2 names looks like a popular package\n"; !suspect || b.String() != want {
		t.Errorf("typosquat output:\n%s\nwant:\n%s", b.String(), want)
	}
}

// graph shows every cycle as the same concrete path on every run and prints
// the tree with shared subtrees once and cycles marked.
func TestGraphCyclesAndTree(t *testing.T) {
	root := model.NewComponent(model.NPM, "", "app", "1.0.0")
	g := model.NewGraph(root)
	n := map[string]*model.Component{}
	for _, name := range []string{"a", "b", "c", "d"} {
		n[name] = g.AddNode(model.NewComponent(model.NPM, "", name, "1.0.0"))
	}
	n["d"].Scope = model.ScopeDev
	for _, e := range [][2]string{{"a", "b"}, {"b", "c"}, {"c", "a"}, {"c", "b"}} {
		g.AddEdge(model.Edge{From: n[e[0]].PURL, To: n[e[1]].PURL})
	}
	g.AddEdge(model.Edge{From: root.PURL, To: n["a"].PURL})
	g.AddEdge(model.Edge{From: root.PURL, To: n["b"].PURL})
	g.AddEdge(model.Edge{From: root.PURL, To: n["d"].PURL})
	for _, scc := range [][]string{{n["c"].PURL, n["a"].PURL, n["b"].PURL}, {n["b"].PURL, n["c"].PURL, n["a"].PURL}} {
		if got := cycleText(g, scc); got != "a@1.0.0 → b@1.0.0 → c@1.0.0 → a@1.0.0" {
			t.Errorf("cycle %v: %q", scc, got)
		}
	}
	if got := cycleText(g, []string{n["b"].PURL, n["c"].PURL}); got != "b@1.0.0 → c@1.0.0 → b@1.0.0" {
		t.Errorf("two-node cycle: %q", got)
	}
	var b bytes.Buffer
	printTree(&b, g, 0)
	want := `app@1.0.0
├── a@1.0.0
│   └── b@1.0.0
│       └── c@1.0.0
│           ├── a@1.0.0 (cycle)
│           └── b@1.0.0 (cycle)
├── b@1.0.0 (*)
└── d@1.0.0 [dev]
(*) dependencies shown above
`
	if b.String() != want {
		t.Errorf("tree:\n%s\nwant:\n%s", b.String(), want)
	}
	b.Reset()
	printTree(&b, g, 1)
	if !strings.Contains(b.String(), "├── a@1.0.0 …") || !strings.Contains(b.String(), "below depth 1 left out") {
		t.Errorf("tree --depth 1:\n%s", b.String())
	}
}
