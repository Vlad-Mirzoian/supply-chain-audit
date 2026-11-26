package graph

import (
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

func build(edges [][2]string) *model.Graph {
	g := model.NewGraph(model.NewComponent("npm", "", "app", "1.0.0"))
	add := func(n string) string {
		if n == "app" {
			return g.Root
		}
		c := model.NewComponent("npm", "", n, "1.0.0")
		g.AddNode(c)
		return c.PURL
	}
	for _, e := range edges {
		g.AddEdge(model.Edge{From: add(e[0]), To: add(e[1])})
	}
	return g
}

// D and E depend on each other: one cycle.
func TestTarjanFindsCycle(t *testing.T) {
	g := build([][2]string{{"app", "a"}, {"app", "b"}, {"a", "c"}, {"b", "d"}, {"d", "e"}, {"e", "d"}, {"d", "c"}})
	sccs := Tarjan(g)
	cyc := Cycles(g, sccs)
	if len(cyc) != 1 || len(cyc[0]) != 2 {
		t.Fatalf("expected one cycle of two nodes, got %v", cyc)
	}
	// reverse topological order: c must come before d/e, which come before b
	pos := Condensation(sccs)
	c, d, b := "pkg:npm/c@1.0.0", "pkg:npm/d@1.0.0", "pkg:npm/b@1.0.0"
	if !(pos[c] < pos[d] && pos[d] < pos[b]) {
		t.Fatalf("SCC order is not reverse topological: %v", sccs)
	}
}

func TestTarjanDeepChain(t *testing.T) {
	var edges [][2]string
	prev := "app"
	for i := 0; i < 100000; i++ {
		n := "p" + itoa(i)
		edges = append(edges, [2]string{prev, n})
		prev = n
	}
	g := build(edges)
	if got := len(Tarjan(g)); got != 100001 {
		t.Fatalf("expected 100001 SCCs, got %d", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
