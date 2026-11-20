package reach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// In a project with npm and PyPI dependencies each component is judged by the
// imports of its own ecosystem. Before, the ecosystem of the root was used for
// all of them, so every Python package of an npm-rooted project came out as
// unreachable and its vulnerabilities were down-weighted.
func TestMixedEcosystemReachability(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import requests\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.js"), []byte("const express = require('express')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g := model.NewGraph(model.NewComponent(model.NPM, "", "app", "1.0.0"))
	for _, c := range []*model.Component{
		model.NewComponent(model.NPM, "", "express", "4.21.2"),
		model.NewComponent(model.NPM, "", "left-pad", "1.3.0"),
		model.NewComponent(model.PyPI, "", "requests", "2.31.0"),
		model.NewComponent(model.PyPI, "", "flask", "3.0.0"),
		model.NewComponent(model.Maven, "org.example", "lib", "1.0"),
	} {
		g.AddNode(c)
		g.AddEdge(model.Edge{From: g.Root, To: c.PURL})
	}
	// offline client with an empty cache: archives cannot be read, which only
	// affects edges below the direct dependencies
	a := &Analyzer{Net: netx.New(t.TempDir(), true), Dir: dir}
	res := a.Run(context.Background(), g)
	want := map[string]string{
		"pkg:npm/express@4.21.2":        Yes,
		"pkg:npm/left-pad@1.3.0":        No,
		"pkg:pypi/requests@2.31.0":      Yes,
		"pkg:pypi/flask@3.0.0":          No,
		"pkg:maven/org.example/lib@1.0": Unknown,
	}
	for purl, w := range want {
		if res[purl] != w {
			t.Errorf("%s: %q, want %q", purl, res[purl], w)
		}
	}
}
