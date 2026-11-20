package npm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// "devOptional" packages (a dev dependency that is also an optional
// dependency of a production package) are installed in production: they are
// optional, not dev, and stay in the graph without --include-dev.
func TestLockV3DevOptional(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"devDependencies":{"d":"^1"}}`)
	write("package-lock.json", `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"devDependencies":{"d":"^1"}},
"node_modules/a":{"version":"1.0.0","optionalDependencies":{"fsx":"^1"}},
"node_modules/d":{"version":"1.0.0","dev":true,"dependencies":{"fsx":"^1"}},
"node_modules/fsx":{"version":"1.0.0","devOptional":true}}}`)
	m, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := parsePackageLock(filepath.Join(dir, "package-lock.json"), m, false)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Nodes["pkg:npm/fsx@1.0.0"]
	if c == nil || c.Scope != model.ScopeOptional {
		t.Fatalf("fsx: %+v, want scope optional", c)
	}
	if g.Nodes["pkg:npm/d@1.0.0"] != nil {
		t.Error("dev dependency d in the production graph")
	}
}

// Every lockfile format must record where a package that does not come from
// the registry is downloaded from (git, a URL, a local path), so that M3 does
// not take it for the registry release of the same name and version; yarn v1
// lockfiles without an integrity field carry a sha1 in the URL fragment.
func TestLockfileSources(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	node := func(g *model.Graph, name string) *model.Component {
		t.Helper()
		for _, c := range g.Nodes {
			if c.FullName() == name {
				return c
			}
		}
		t.Fatalf("%s missing; nodes %v", name, g.Nodes)
		return nil
	}
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"github:x/b"}}`)

	write("package-lock.json", `{"name":"app","lockfileVersion":1,"dependencies":{
"a":{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz","integrity":"sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="},
"b":{"version":"git+https://github.com/x/b.git#0123456789abcdef0123456789abcdef01234567","from":"github:x/b"}}}`)
	m, _ := readManifest(dir)
	g, err := parsePackageLock(filepath.Join(dir, "package-lock.json"), m, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := node(g, "b"); !strings.HasPrefix(c.Resolved, "git+https://") {
		t.Errorf("npm v1 git dependency: resolved %q", c.Resolved)
	}

	write("yarn.lock", `# yarn lockfile v1

a@^1:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#0123456789abcdef0123456789abcdef01234567"
`)
	g, err = parseYarnLock(filepath.Join(dir, "yarn.lock"), m, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := node(g, "a"); len(c.Integrity) != 1 || c.Integrity[0] != "sha1-ASNFZ4mrze8BI0VniavN7wEjRWc=" {
		t.Errorf("yarn v1 sha1 fragment: integrity %v", c.Integrity)
	}

	write("yarn.lock", `__metadata:
  version: 8

"a@npm:^1":
  version: 1.0.0
  resolution: "a@npm:1.0.0"

"@s/p@patch:@s/p@npm%3A1.0.0#./.yarn/patches/p.patch":
  version: 1.0.0
  resolution: "@s/p@patch:@s/p@npm%3A1.0.0#./.yarn/patches/p.patch::version=1.0.0"

"b@https://evil.example/b-1.0.0.tgz":
  version: 1.0.0
  resolution: "b@https://evil.example/b-1.0.0.tgz"
`)
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"https://evil.example/b-1.0.0.tgz","@s/p":"patch:@s/p@npm%3A1.0.0#./.yarn/patches/p.patch"}}`)
	m, _ = readManifest(dir)
	g, err = parseYarnLock(filepath.Join(dir, "yarn.lock"), m, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := node(g, "a"); c.Resolved != "" {
		t.Errorf("berry registry package: resolved %q", c.Resolved)
	}
	if c := node(g, "@s/p"); c.Resolved != "" {
		t.Errorf("berry patched registry package: resolved %q", c.Resolved)
	}
	if c := node(g, "b"); c.Resolved != "https://evil.example/b-1.0.0.tgz" {
		t.Errorf("berry URL package: resolved %q", c.Resolved)
	}

	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"github:x/b"}}`)
	write("pnpm-lock.yaml", `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1
        version: 1.0.0
      b:
        specifier: github:x/b
        version: https://codeload.github.com/x/b/tar.gz/0123456
packages:
  a@1.0.0:
    resolution: {integrity: sha512-AAAA}
  b@https://codeload.github.com/x/b/tar.gz/0123456:
    resolution: {type: git, repo: https://github.com/x/b.git, commit: 0123456}
    version: 1.0.0
snapshots:
  a@1.0.0: {}
  b@https://codeload.github.com/x/b/tar.gz/0123456: {}
`)
	m, _ = readManifest(dir)
	g, err = parsePnpmLock(filepath.Join(dir, "pnpm-lock.yaml"), m, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := node(g, "b"); c.Resolved != "git+https://github.com/x/b.git#0123456" {
		t.Errorf("pnpm git dependency: resolved %q", c.Resolved)
	}
}

// Copies of one name and version at several lockfile paths must be merged
// independently of map order: before, the copy read first won, so the hash
// and download URL that M3 checked changed from run to run (NodeGoat: 758,
// 759 or 761 components with a hash), and a nested copy from another source
// could be hidden behind a registry copy.
func TestDuplicateEntriesMergeDeterministically(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"^1","qs":"^6"}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"^1","qs":"^6"}},
"node_modules/qs":{"version":"6.13.0","resolved":"https://registry.npmjs.org/qs/-/qs-6.13.0.tgz","integrity":"sha512-QQ==","license":"MIT/X11"},
"node_modules/a":{"version":"1.0.0","dependencies":{"qs":"^6"}},
"node_modules/a/node_modules/qs":{"version":"6.13.0","inBundle":true,"license":"MIT OR X11"},
"node_modules/b":{"version":"1.0.0","dependencies":{"qs":"^6"}},
"node_modules/b/node_modules/qs":{"version":"6.13.0","resolved":"https://evil.example/qs.tgz","integrity":"sha1-AA=="}}}`), 0o644)
	m, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		g, err := parsePackageLock(filepath.Join(dir, "package-lock.json"), m, false)
		if err != nil {
			t.Fatal(err)
		}
		c := g.Nodes["pkg:npm/qs@6.13.0"]
		if c == nil || c.Resolved != "https://evil.example/qs.tgz" || strings.Join(c.Integrity, " ") != "sha1-AA== sha512-QQ==" || strings.Join(c.Licenses, " ") != "MIT OR X11" {
			t.Fatalf("run %d: %+v", i, c)
		}
	}
}

// The full graph holds development dependencies with their scope in every
// lockfile format. yarn and pnpm record no dev flag per package: the scope
// comes from the walk from the project's dependency lists, and a package that
// a runtime dependency also needs is runtime. Without includeDev the graph is
// the runtime graph.
func TestDevScopesAllFormats(t *testing.T) {
	manifestJSON := `{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"devDependencies":{"t":"^1","s":"^1"}}`
	lockfiles := map[string]map[string]string{
		"v3": {"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"devDependencies":{"t":"^1","s":"^1"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"s":"^1"}},
"node_modules/s":{"version":"1.0.0"},
"node_modules/t":{"version":"1.0.0","dev":true,"dependencies":{"u":"^1","s":"^1"}},
"node_modules/u":{"version":"1.0.0","dev":true}}}`},
		"v1": {"package-lock.json": `{"name":"app","lockfileVersion":1,"dependencies":{
"a":{"version":"1.0.0","requires":{"s":"^1"}},
"s":{"version":"1.0.0"},
"t":{"version":"1.0.0","dev":true,"requires":{"u":"^1","s":"^1"}},
"u":{"version":"1.0.0","dev":true}}}`},
		"yarn": {"yarn.lock": `# yarn lockfile v1

a@^1:
  version "1.0.0"
  dependencies:
    s "^1"

s@^1:
  version "1.0.0"

t@^1:
  version "1.0.0"
  dependencies:
    u "^1"
    s "^1"

u@^1:
  version "1.0.0"
`},
		"berry": {"yarn.lock": `__metadata:
  version: 8

"a@npm:^1":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    s: "npm:^1"

"s@npm:^1":
  version: 1.0.0
  resolution: "s@npm:1.0.0"

"t@npm:^1":
  version: 1.0.0
  resolution: "t@npm:1.0.0"
  dependencies:
    u: "npm:^1"
    s: "npm:^1"

"u@npm:^1":
  version: 1.0.0
  resolution: "u@npm:1.0.0"
`},
		"pnpm": {"pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
    devDependencies:
      t: {specifier: ^1, version: 1.0.0}
      s: {specifier: ^1, version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-AAA=}}
  s@1.0.0: {resolution: {integrity: sha512-SSS=}}
  t@1.0.0: {resolution: {integrity: sha512-TTT=}}
  u@1.0.0: {resolution: {integrity: sha512-UUU=}}
snapshots:
  a@1.0.0:
    dependencies: {s: 1.0.0}
  s@1.0.0: {}
  t@1.0.0:
    dependencies: {u: 1.0.0, s: 1.0.0}
  u@1.0.0: {}
`},
	}
	for name, files := range lockfiles {
		dir := t.TempDir()
		files["package.json"] = manifestJSON
		for f, body := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for _, dev := range []bool{true, false} {
			g, err := Plugin{}.Load(t.Context(), dir, common.Options{IncludeDev: dev})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var got []string
			for _, c := range g.Components() {
				got = append(got, fmt.Sprintf("%s:%s/%d", c.Name, c.Scope, c.Depth))
			}
			want := "[a:runtime/1 s:runtime/2 t:dev/1 u:dev/2]"
			if !dev {
				want = "[a:runtime/1 s:runtime/2]"
			}
			if fmt.Sprint(got) != want {
				t.Errorf("%s (includeDev %v): %v, want %s", name, dev, got, want)
			}
		}
	}
}

// In a monorepo one workspace member may list a package as a development
// dependency and another as a runtime dependency; the package is runtime
// whatever the order of the members.
func TestWorkspaceRuntimeWinsOverDev(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"mono","version":"1.0.0","private":true,"workspaces":["packages/*"]}`)
	write("packages/a/package.json", `{"name":"a","version":"1.0.0","devDependencies":{"vite":"^6"}}`)
	write("packages/b/package.json", `{"name":"b","version":"1.0.0","dependencies":{"vite":"^6"}}`)
	write("yarn.lock", "# yarn lockfile v1\n\nvite@^6:\n  version \"6.4.5\"\n  dependencies:\n    esbuild \"^0.25\"\n\nesbuild@^0.25:\n  version \"0.25.12\"\n")
	g, err := Plugin{}.Load(t.Context(), dir, common.Options{IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"vite@6.4.5", "esbuild@0.25.12"} {
		if c := g.Nodes["pkg:npm/"+n]; c == nil || c.Scope != model.ScopeRuntime {
			t.Errorf("%s: %+v, want runtime", n, c)
		}
	}
}

// A package-lock.json that marks a package as a development dependency
// although a production package needs it (hand-edited "dev": true) must not
// hide the package from the production view: it takes the derived scope, in
// the default mode and with --runtime-only, and the lockfile scope is kept
// for M3. Optional dependencies give the optional scope; peer dependencies
// are not evidence (npm itself flags the peer of a production package as
// "dev" in some versions); a correct lockfile has no difference.
func TestLockScopeMismatch(t *testing.T) {
	cases := []struct {
		name, lock string
	}{
		{"v3", `{"name":"app","lockfileVersion":3,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4"},"devDependencies":{"mocha":"^10","ts":"^5"}},
"node_modules/express":{"version":"4.0.0","dependencies":{"qs":"^6"},"optionalDependencies":{"opt":"^1"},"peerDependencies":{"ts":"*"}},
"node_modules/qs":{"version":"6.0.0","dev":true,"dependencies":{"side":"^1"}},
"node_modules/side":{"version":"1.0.0","dev":true},
"node_modules/opt":{"version":"1.0.0","dev":true},
"node_modules/ts":{"version":"5.0.0","dev":true},
"node_modules/mocha":{"version":"10.0.0","dev":true,"dependencies":{"side":"^1"}}}}`},
		{"v1", `{"name":"app","lockfileVersion":1,"dependencies":{
"express":{"version":"4.0.0","requires":{"qs":"^6"}},
"qs":{"version":"6.0.0","dev":true,"requires":{"side":"^1"}},
"side":{"version":"1.0.0","dev":true},
"mocha":{"version":"10.0.0","dev":true,"requires":{"side":"^1"}}}}`},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app","version":"1.0.0","dependencies":{"express":"^4"},"devDependencies":{"mocha":"^10","ts":"^5"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(tc.lock), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := readManifest(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, includeDev := range []bool{true, false} {
			g, err := parsePackageLock(filepath.Join(dir, "package-lock.json"), m, includeDev)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string][3]string{ // scope, lockfile scope, via
				"pkg:npm/qs@6.0.0":   {"runtime", "dev", "express@4.0.0"},
				"pkg:npm/side@1.0.0": {"runtime", "dev", "qs@6.0.0"},
			}
			if tc.name == "v3" {
				want["pkg:npm/opt@1.0.0"] = [3]string{"optional", "dev", "express@4.0.0"}
			}
			for purl, w := range want {
				c := g.Nodes[purl]
				if c == nil || string(c.Scope) != w[0] || string(c.LockScope) != w[1] || c.ScopeVia != w[2] {
					t.Errorf("%s includeDev=%v %s: %+v, want %v", tc.name, includeDev, purl, c, w)
				}
			}
			// the "dev" flag of a peer of a production package is kept
			if ts := g.Nodes["pkg:npm/ts@5.0.0"]; tc.name == "v3" && includeDev && (ts == nil || ts.Scope != model.ScopeDev || ts.LockScope != "") {
				t.Errorf("peer ts: %+v, want the lockfile scope dev without a difference", ts)
			}
			mocha := g.Nodes["pkg:npm/mocha@10.0.0"]
			if includeDev && (mocha == nil || mocha.Scope != model.ScopeDev || mocha.LockScope != "") {
				t.Errorf("%s: mocha %+v, want a correct dev dependency", tc.name, mocha)
			}
			if !includeDev && mocha != nil {
				t.Errorf("%s: mocha in the runtime graph", tc.name)
			}
			hasEdge := false
			for _, e := range g.Out["pkg:npm/express@4.0.0"] {
				hasEdge = hasEdge || e.To == "pkg:npm/qs@6.0.0"
			}
			if !hasEdge {
				t.Errorf("%s includeDev=%v: edge express -> qs missing", tc.name, includeDev)
			}
		}
	}
}
