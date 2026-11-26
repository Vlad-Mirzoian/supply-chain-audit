// Package graph contains the graph algorithms of the suite: Tarjan's
// strongly connected components and the condensation used for risk propagation.
package graph

import (
	"sort"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Tarjan returns the strongly connected components of g in reverse
// topological order (a component appears after every component it reaches...
// precisely: Tarjan emits sinks first). The implementation is iterative so
// that deep npm graphs cannot overflow the goroutine stack.
func Tarjan(g *model.Graph) [][]string {
	ids := make([]string, 0, len(g.Nodes))
	for id := range g.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	index := map[string]int{}
	low := map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var out [][]string
	next := 0

	type frame struct {
		v string
		i int // next edge to visit
	}
	for _, s := range ids {
		if _, seen := index[s]; seen {
			continue
		}
		call := []frame{{v: s}}
		index[s], low[s] = next, next
		next++
		stack = append(stack, s)
		onStack[s] = true
		for len(call) > 0 {
			f := &call[len(call)-1]
			edges := g.Out[f.v]
			if f.i < len(edges) {
				w := edges[f.i].To
				f.i++
				if _, ok := g.Nodes[w]; !ok {
					continue
				}
				if _, seen := index[w]; !seen {
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					call = append(call, frame{v: w})
				} else if onStack[w] && index[w] < low[f.v] {
					low[f.v] = index[w]
				}
				continue
			}
			// all edges of f.v visited
			v := f.v
			call = call[:len(call)-1]
			if len(call) > 0 {
				p := call[len(call)-1].v
				if low[v] < low[p] {
					low[p] = low[v]
				}
			}
			if low[v] == index[v] {
				var comp []string
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp = append(comp, w)
					if w == v {
						break
					}
				}
				sort.Strings(comp)
				out = append(out, comp)
			}
		}
	}
	return out
}

// Cycles returns the SCCs with more than one node (and self-loops).
func Cycles(g *model.Graph, sccs [][]string) [][]string {
	var out [][]string
	for _, c := range sccs {
		if len(c) > 1 {
			out = append(out, c)
			continue
		}
		for _, e := range g.Out[c[0]] {
			if e.To == c[0] {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// Condensation maps each node to its SCC index. Because Tarjan emits SCCs
// sinks-first, iterating SCC indices in increasing order is a valid reverse
// topological order of the condensed DAG.
func Condensation(sccs [][]string) map[string]int {
	m := make(map[string]int)
	for i, c := range sccs {
		for _, v := range c {
			m[v] = i
		}
	}
	return m
}
