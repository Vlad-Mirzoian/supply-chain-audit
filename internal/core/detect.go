// Package core is the orchestrator: it detects the project type, builds the
// graph (M0) and runs the analysis modules in the order of Fig. 3.5.
package core

import (
	"context"
	"fmt"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/maven"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/graph"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Plugins lists the registered ecosystem plugins.
var Plugins = []common.Plugin{npm.Plugin{}, pypi.Plugin{}, maven.Plugin{}}

// BuildGraph runs M0 for every ecosystem detected in dir (or only for the one
// named by eco) and finds cycles with Tarjan's algorithm. It returns the names
// of the ecosystems that were read. A directory with several ecosystems (an
// npm front end next to a Python back end) gives one graph: the direct
// dependencies of every ecosystem hang from the root of the first one, so that
// no part of the project is silently left out of the audit.
func BuildGraph(ctx context.Context, dir, eco string, opt common.Options) (*model.Graph, []string, error) {
	var g *model.Graph
	var ecos []string
	for _, p := range Plugins {
		if eco != "" && p.Name() != eco {
			continue
		}
		if eco == "" && len(p.Detect(dir)) == 0 {
			continue
		}
		pg, err := p.Load(ctx, dir, opt)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p.Name(), err)
		}
		ecos = append(ecos, p.Name())
		if g == nil {
			g = pg
			continue
		}
		Merge(g, pg)
	}
	if g == nil {
		return nil, nil, fmt.Errorf("no supported project files in %s", dir)
	}
	if len(ecos) > 1 {
		g.ComputeDepths()
	}
	sccs := graph.Tarjan(g)
	g.Cycles = graph.Cycles(g, sccs)
	return g, ecos, nil
}

// Merge adds the graph of another ecosystem to g: its components, its edges
// (those of its root are moved to the root of g) and its diagnostics.
func Merge(g, other *model.Graph) {
	for id, c := range other.Nodes {
		if id != other.Root {
			g.AddNode(c)
		}
	}
	from := []string{other.Root}
	for _, c := range other.Components() {
		from = append(from, c.PURL)
	}
	for _, id := range from {
		for _, e := range other.Out[id] {
			if id == other.Root {
				e.From = g.Root
			}
			g.AddEdge(e)
		}
	}
	g.Conflicts = append(g.Conflicts, other.Conflicts...)
	g.Incomplete = append(g.Incomplete, other.Incomplete...)
	g.Notes = append(g.Notes, other.Notes...)
	g.Inputs = append(g.Inputs, other.Inputs...)
	g.Repositories = append(g.Repositories, other.Repositories...)
}
