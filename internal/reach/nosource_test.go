package reach

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func graph(cs ...*model.Component) *model.Graph {
	g := model.NewGraph(model.NewComponent(model.NPM, "", "app", "1.0.0"))
	for _, c := range cs {
		g.AddNode(c)
		g.AddEdge(model.Edge{From: g.Root, To: c.PURL})
	}
	return g
}

// Without source files of the application nothing is known about its
// imports: every verdict is Unknown, never No. A directory that holds only
// manifests (or only tests and configuration) must not make vulnerabilities
// unreachable.
func TestNoSourceIsUnknown(t *testing.T) {
	cases := map[string]map[string]string{
		"manifests only": {"requirements.txt": "flask==3.0.0\n", "package.json": `{"dependencies":{"express":"4"}}`},
		"tests only":     {"tests/test_app.py": "import flask\n", "test/app.test.js": "require('express')\n"},
		"config only":    {"settings.yaml": "apps: [flask, express]\n"},
		"empty":          {},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for f, b := range files {
				write(t, dir, f, b)
			}
			g := graph(model.NewComponent(model.NPM, "", "express", "4.21.2"), model.NewComponent(model.PyPI, "", "flask", "3.0.0"))
			a := &Analyzer{Net: netx.New(t.TempDir(), true), Dir: dir}
			res := a.Run(context.Background(), g)
			for purl, s := range res {
				if s != Unknown {
					t.Errorf("%s: %q, want unknown", purl, s)
				}
			}
			if len(a.NoSource) != 2 || a.NoSource[0] != model.NPM || a.NoSource[1] != model.PyPI {
				t.Errorf("NoSource = %v", a.NoSource)
			}
		})
	}
}

// Source files of one ecosystem do not stand in for another: with JavaScript
// but no Python code, npm packages are analysed and PyPI packages are Unknown.
func TestNoSourceOneEcosystem(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "index.js", "const express = require('express')\n")
	write(t, dir, "requirements.txt", "flask==3.0.0\n")
	g := graph(model.NewComponent(model.NPM, "", "express", "4.21.2"), model.NewComponent(model.NPM, "", "left-pad", "1.3.0"),
		model.NewComponent(model.PyPI, "", "flask", "3.0.0"))
	a := &Analyzer{Net: netx.New(t.TempDir(), true), Dir: dir}
	res := a.Run(context.Background(), g)
	want := map[string]string{"pkg:npm/express@4.21.2": Yes, "pkg:npm/left-pad@1.3.0": No, "pkg:pypi/flask@3.0.0": Unknown}
	for purl, w := range want {
		if res[purl] != w {
			t.Errorf("%s: %q, want %q", purl, res[purl], w)
		}
	}
	if len(a.NoSource) != 1 || a.NoSource[0] != model.PyPI {
		t.Errorf("NoSource = %v", a.NoSource)
	}
}

func TestAppImportsCountsSourceOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "conf.json", `{"plugin": "express"}`)
	write(t, dir, "node_modules/x/index.js", "require('express')\n")
	if im := AppImports(dir, model.NPM); im.ok || im.files != 0 {
		t.Errorf("config and node_modules counted as source: ok=%v files=%d", im.ok, im.files)
	}
	write(t, dir, "src/a.ts", "import x from 'lodash'\n")
	if im := AppImports(dir, model.NPM); !im.ok || im.files != 1 || !im.names["lodash"] || !im.names["express"] {
		t.Errorf("ok=%v files=%d names=%v", im.ok, im.files, im.names)
	}
}
