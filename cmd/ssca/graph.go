// graph: the dependency graph (M0) as a summary or as JSON.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/core"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// cmdGraph prints the dependency graph (M0 only): a summary, with --tree the
// tree and with --json every component; the JSON output is used in the
// experiments to compare the inventory with package-manager ground truth.
func cmdGraph(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	g := addGlobal(fs)
	asJSON := fs.Bool("json", false, "print components as JSON")
	asTree := fs.Bool("tree", false, "also print the dependency tree")
	maxDepth := fs.Int("depth", 0, "print the tree with only the first N levels (implies --tree; 0: all)")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	if *maxDepth < 0 {
		fmt.Fprintln(os.Stderr, "error: --depth must not be negative")
		return exitUsage
	}
	if *maxDepth > 0 {
		*asTree = true
	}
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	if !g.checkTarget(dir) {
		return exitUsage
	}
	ctx := context.Background()
	net := g.client()
	start := time.Now()
	gr, _, err := core.BuildGraph(ctx, dir, g.eco, common.Options{Net: net, IncludeDev: !g.runtime, MaxRounds: 3, ForceResolve: g.resolve})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitIncomplete
	}
	comps := gr.Components()
	if *asJSON {
		type row struct {
			PURL    string   `json:"purl"`
			Depth   int      `json:"depth"`
			Scope   string   `json:"scope"`
			Source  string   `json:"source"`
			Evicted []string `json:"evicted,omitempty"`
			// scope declared by the lockfile when it differs (M3 reports it)
			LockScope string `json:"lockfile_scope,omitempty"`
			ScopeVia  string `json:"scope_via,omitempty"`
		}
		var rows []row
		for _, c := range comps {
			rows = append(rows, row{c.PURL, c.Depth, string(c.Scope), c.Source, c.Evicted, string(c.LockScope), c.ScopeVia})
		}
		out := map[string]any{"root": gr.Root, "components": rows, "edges": gr.EdgeCount(),
			"cycles": gr.Cycles, "conflicts": gr.Conflicts, "incomplete": gr.Incomplete,
			"seconds": time.Since(start).Seconds(), "requests": net.Requests.Load()}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return graphExit(gr)
	}
	printGraph(os.Stdout, g, gr, time.Since(start), net.Requests.Load(), *asTree, *maxDepth)
	return graphExit(gr)
}

// printGraph prints the summary of the graph: sizes, depths and scopes in
// three lines, then the cycles and conflicts by name, then the reasons of an
// incomplete graph. With tree the dependency tree follows.
func printGraph(w io.Writer, g *global, gr *model.Graph, took time.Duration, requests int64, tree bool, maxDepth int) {
	comps := gr.Components()
	timing := fmt.Sprintf("%.1f s", took.Seconds())
	if requests > 0 {
		timing += ", " + count(int(requests), "request")
	}
	fmt.Fprintf(w, "%s: %s, %s, %s, %s (%s)%s\n", gr.Root, count(len(comps), "component"), count(gr.EdgeCount(), "edge"),
		count(len(gr.Cycles), "cycle"), count(len(gr.Conflicts), "conflict"), timing, incompleteMark(gr.Incomplete))
	depth := map[int]int{}
	maxD := 0
	for _, c := range comps {
		depth[c.Depth]++
		maxD = max(maxD, c.Depth)
	}
	if len(comps) > 0 {
		var hist []string
		for d := 0; d <= maxD; d++ {
			if depth[d] > 0 {
				hist = append(hist, fmt.Sprintf("%d: %d", d, depth[d]))
			}
		}
		fmt.Fprintf(w, "  depth: %d direct, %d transitive, max %d (by depth %s)\n",
			depth[1], len(comps)-depth[1], maxD, strings.Join(hist, ", "))
		scopes := map[model.Scope]int{}
		for _, c := range comps {
			scopes[c.Scope]++
		}
		var sc []string
		for _, s := range []model.Scope{model.ScopeRuntime, model.ScopeOptional, model.ScopeProvided, model.ScopeExtra, model.ScopeDev, model.ScopeTest} {
			if scopes[s] > 0 {
				sc = append(sc, fmt.Sprintf("%s %d", s, scopes[s]))
			}
		}
		fmt.Fprintf(w, "  scope: %s\n", strings.Join(sc, ", "))
	}
	const show = 10
	for i, c := range gr.Cycles {
		if i == show {
			fmt.Fprintf(w, "  ... and %s more (--json lists all)\n", count(len(gr.Cycles)-show, "cycle"))
			break
		}
		fmt.Fprintln(w, "  cycle:", cycleText(gr, c))
	}
	for i, c := range gr.Conflicts {
		if i == show {
			fmt.Fprintf(w, "  ... and %s more (--json lists all)\n", count(len(gr.Conflicts)-show, "conflict"))
			break
		}
		line := fmt.Sprintf("%s %s", c.Name, c.Range)
		if c.Parent != "" {
			line += " (required by " + nodeLabel(gr, c.Parent) + ")"
		}
		if c.Note != "" {
			line += ": " + c.Note
		}
		fmt.Fprintln(w, "  conflict:", line)
	}
	printIncomplete(w, g, gr.Incomplete)
	if tree {
		fmt.Fprintln(w)
		printTree(w, gr, maxDepth)
	}
}

// nodeLabel is name@version of a node, or its id if it is not in the graph.
func nodeLabel(gr *model.Graph, id string) string {
	if c := gr.Nodes[id]; c != nil && c.Version != "" {
		return c.FullName() + "@" + c.Version
	}
	return id
}

// cycleText shows a strongly connected component as one concrete cycle
// through its first node (the shortest one), e.g. "a@1 → b@2 → a@1"; a
// component with more nodes than the cycle says how many it has.
func cycleText(gr *model.Graph, scc []string) string {
	in := map[string]bool{}
	for _, id := range scc {
		in[id] = true
	}
	// the members of an SCC come in no fixed order: start at the smallest
	// one and visit the edges in order, so that the same cycle is shown on
	// every run
	start := slices.Min(scc)
	prev := map[string]string{}
	queue := []string{start}
	found := ""
	for len(queue) > 0 && found == "" {
		cur := queue[0]
		queue = queue[1:]
		es := slices.Clone(gr.Out[cur])
		slices.SortFunc(es, func(a, b model.Edge) int { return strings.Compare(a.To, b.To) })
		for _, e := range es {
			if e.To == start {
				found = cur
				break
			}
			if _, seen := prev[e.To]; in[e.To] && !seen && e.To != start {
				prev[e.To] = cur
				queue = append(queue, e.To)
			}
		}
	}
	var path []string
	if found != "" {
		for x := found; x != start; x = prev[x] {
			path = append(path, x)
		}
	}
	labels := []string{nodeLabel(gr, start)}
	for i := len(path) - 1; i >= 0; i-- {
		labels = append(labels, nodeLabel(gr, path[i]))
	}
	labels = append(labels, nodeLabel(gr, start))
	out := strings.Join(labels, " → ")
	if len(scc) > len(path)+1 {
		out += fmt.Sprintf(" (part of a group of %d packages that depend on each other)", len(scc))
	}
	return out
}

// printTree prints the dependency tree from the root, as npm ls and mvn
// dependency:tree do: children in name order, the subtree of a package only
// at its first occurrence (later ones end with "(*)"), an edge back into the
// current path marked as a cycle, and development and test packages with
// their scope. maxDepth > 0 limits the depth.
func printTree(w io.Writer, gr *model.Graph, maxDepth int) {
	fmt.Fprintln(w, nodeLabel(gr, gr.Root))
	expanded := map[string]bool{gr.Root: true}
	var shownAbove, cut bool
	onPath := map[string]bool{gr.Root: true}
	var walk func(id, prefix string, depth int)
	walk = func(id, prefix string, depth int) {
		es := slices.Clone(gr.Out[id])
		slices.SortFunc(es, func(a, b model.Edge) int { return strings.Compare(nodeLabel(gr, a.To), nodeLabel(gr, b.To)) })
		for i, e := range es {
			branch, next := "├── ", "│   "
			if i == len(es)-1 {
				branch, next = "└── ", "    "
			}
			label := nodeLabel(gr, e.To)
			if c := gr.Nodes[e.To]; c != nil && c.Scope != "" && c.Scope != model.ScopeRuntime {
				label += " [" + string(c.Scope) + "]"
			}
			switch {
			case onPath[e.To]:
				label += " (cycle)"
			case expanded[e.To] && len(gr.Out[e.To]) > 0:
				label += " (*)"
				shownAbove = true
			case maxDepth > 0 && depth >= maxDepth && len(gr.Out[e.To]) > 0:
				label += " …"
				cut = true
			}
			fmt.Fprintln(w, prefix+branch+label)
			if onPath[e.To] || expanded[e.To] || (maxDepth > 0 && depth >= maxDepth) {
				continue
			}
			expanded[e.To] = true
			onPath[e.To] = true
			walk(e.To, prefix+next, depth+1)
			onPath[e.To] = false
		}
	}
	walk(gr.Root, "", 1)
	var legend []string
	if shownAbove {
		legend = append(legend, "(*) dependencies shown above")
	}
	if cut {
		legend = append(legend, fmt.Sprintf("… dependencies below depth %d left out", maxDepth))
	}
	if len(legend) > 0 {
		fmt.Fprintln(w, strings.Join(legend, "; "))
	}
}

// graphExit is exit code 2 for an incomplete graph, as for scan: a graph
// with holes must not look like a complete inventory to a script.
func graphExit(gr *model.Graph) int {
	if len(gr.Incomplete) > 0 {
		return exitIncomplete
	}
	return exitOK
}
