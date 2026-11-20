package npm

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// project writes the files of a test project and loads its graph with the
// lockfile parser that the plugin would choose.
func project(t *testing.T, files map[string]string, includeDev bool) (*model.Graph, error) {
	t.Helper()
	dir := t.TempDir()
	for name, s := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case files["package-lock.json"] != "":
		return parsePackageLock(filepath.Join(dir, "package-lock.json"), m, includeDev)
	case files["pnpm-lock.yaml"] != "":
		return parsePnpmLock(filepath.Join(dir, "pnpm-lock.yaml"), m, includeDev)
	default:
		return parseYarnLock(filepath.Join(dir, "yarn.lock"), m, includeDev)
	}
}

// Scoped names contain a slash, like the instance paths of a v1 lockfile:
// a scoped package, the packages nested inside it and a scoped package
// nested inside another one must all be in the graph.
func TestLockV1ScopedPackages(t *testing.T) {
	g, err := project(t, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"@babel/traverse":"7.23.0","lodash":"4.17.20"},"devDependencies":{"@types/node":"20.0.0"}}`,
		"package-lock.json": `{"name":"app","lockfileVersion":1,"requires":true,"dependencies":{
"@babel/traverse":{"version":"7.23.0","requires":{"debug":"^4.1.0","@babel/types":"^7.23.0"},"dependencies":{
  "debug":{"version":"4.3.4","requires":{"ms":"2.1.2"}},
  "@babel/types":{"version":"7.23.0"}}},
"@types/node":{"version":"20.0.0","dev":true},
"debug":{"version":"2.6.9","requires":{"ms":"2.0.0"}},
"lodash":{"version":"4.17.20"},
"ms":{"version":"2.1.2"}}}`,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]model.Scope{
		"pkg:npm/%40babel/traverse@7.23.0": model.ScopeRuntime, "pkg:npm/%40babel/types@7.23.0": model.ScopeRuntime,
		"pkg:npm/debug@4.3.4": model.ScopeRuntime, "pkg:npm/ms@2.1.2": model.ScopeRuntime,
		"pkg:npm/lodash@4.17.20": model.ScopeRuntime, "pkg:npm/%40types/node@20.0.0": model.ScopeDev,
	}
	for purl, s := range want {
		if c := g.Nodes[purl]; c == nil || c.Scope != s {
			t.Errorf("%s: %+v, want scope %s", purl, c, s)
		}
	}
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
	var to []string
	for _, e := range g.Out["pkg:npm/%40babel/traverse@7.23.0"] {
		to = append(to, e.To)
	}
	if strings.Join(to, " ") != "pkg:npm/%40babel/types@7.23.0 pkg:npm/debug@4.3.4" && strings.Join(to, " ") != "pkg:npm/debug@4.3.4 pkg:npm/%40babel/types@7.23.0" {
		t.Errorf("@babel/traverse edges %v, want the nested debug@4.3.4 and @babel/types", to)
	}
}

// A lockfile that lacks an entry for a required dependency (declared in
// package.json or by a locked package) is out of sync: the analysis is
// incomplete. Missing optional and peer dependencies are allowed.
func TestLockfileOutOfSync(t *testing.T) {
	const pj = `{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"optionalDependencies":{"o":"^1"},"devDependencies":{"d":"^1"}}`
	cases := []struct {
		name  string
		files map[string]string
		dev   bool
		want  string // expected part of the incomplete note, "" = in sync
		err   string // expected parse error
	}{
		{"v3 in sync", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1"},"optionalDependencies":{"o":"^1"},"devDependencies":{"d":"^1"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"b":"^1"},"optionalDependencies":{"fsx":"^1"},"peerDependencies":{"react":"*"}},
"node_modules/b":{"version":"1.0.0"},
"node_modules/d":{"version":"1.0.0","dev":true}}}`}, true, "", ""},
		{"v3 direct missing", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1"}},"node_modules/d":{"version":"1.0.0","dev":true}}}`}, true, "a@^1 (required by package.json)", ""},
		{"v3 removed from root entry", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{},"node_modules/d":{"version":"1.0.0","dev":true}}}`}, true, "a@^1 (required by package.json)", ""},
		{"v3 transitive missing", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1"},"devDependencies":{"d":"^1"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"b":"^1"}},
"node_modules/d":{"version":"1.0.0","dev":true}}}`}, true, "b@^1 (required by a@1.0.0)", ""},
		{"v3 dev missing, runtime only", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1"}},"node_modules/a":{"version":"1.0.0"}}}`}, false, "", ""},
		{"v3 dev missing", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1"}},"node_modules/a":{"version":"1.0.0"}}}`}, true, "d@^1 (required by package.json)", ""},
		{"v1 direct missing", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":1,"dependencies":{
"d":{"version":"1.0.0","dev":true}}}`}, true, "a@^1 (required by package.json)", ""},
		{"v1 transitive missing", map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":1,"dependencies":{
"a":{"version":"1.0.0","requires":{"b":"^1"}},"d":{"version":"1.0.0","dev":true}}}`}, true, "b@^1 (required by a@1.0.0)", ""},
		{"yarn in sync", map[string]string{"package.json": pj, "yarn.lock": "# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n  dependencies:\n    b \"^1\"\n  optionalDependencies:\n    fsx \"^1\"\n\nb@^1:\n  version \"1.0.0\"\n\nd@^1:\n  version \"1.0.0\"\n"}, true, "", ""},
		{"yarn missing", map[string]string{"package.json": pj, "yarn.lock": "# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n  dependencies:\n    b \"^1\"\n\nd@^1:\n  version \"1.0.0\"\n"}, true, "b@^1 (required by a@1.0.0)", ""},
		{"yarn not a lockfile", map[string]string{"package.json": pj, "yarn.lock": "garbage: [\n  {{{\n"}, true, "", "not a yarn lockfile entry"},
		{"yarn entry without version", map[string]string{"package.json": pj, "yarn.lock": "a@^1:\n  resolved \"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz\"\n"}, true, "", "has no version"},
		{"pnpm in sync", map[string]string{"package.json": pj, "pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
    devDependencies:
      d: {specifier: ^1, version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-AA==}}
  b@1.0.0: {resolution: {integrity: sha512-BB==}}
  d@1.0.0: {resolution: {integrity: sha512-DD==}}
snapshots:
  a@1.0.0:
    dependencies: {b: 1.0.0}
    optionalDependencies: {fsx: 1.0.0}
  b@1.0.0: {}
  d@1.0.0: {}
`}, true, "", ""},
		{"pnpm not in importer", map[string]string{"package.json": pj, "pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      d: {specifier: ^1, version: 1.0.0}
packages:
  d@1.0.0: {resolution: {integrity: sha512-DD==}}
snapshots:
  d@1.0.0: {}
`}, true, "a@^1 (required by package.json)", ""},
		{"pnpm transitive missing", map[string]string{"package.json": pj, "pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
    devDependencies:
      d: {specifier: ^1, version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-AA==}}
  d@1.0.0: {resolution: {integrity: sha512-DD==}}
snapshots:
  a@1.0.0:
    dependencies: {b: 1.0.0}
  d@1.0.0: {}
`}, true, "b@1.0.0 (required by a@1.0.0)", ""},
	}
	for _, tc := range cases {
		g, err := project(t, tc.files, tc.dev)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: error %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		got := strings.Join(g.Incomplete, "; ")
		switch {
		case tc.want == "" && got != "":
			t.Errorf("%s: incomplete %q, want none", tc.name, got)
		case tc.want != "" && !(strings.Contains(got, "out of sync") && strings.Contains(got, tc.want)):
			t.Errorf("%s: incomplete %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Node.js looks for a dependency in the node_modules folder of every parent
// folder; a workspace nested in another one (apps/desktop/native) finds the
// packages installed in apps/desktop/node_modules.
func TestNestedWorkspaceResolution(t *testing.T) {
	g, err := project(t, map[string]string{
		"package.json": `{"name":"mono","version":"1.0.0","workspaces":["apps/desktop","apps/desktop/native"]}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"workspaces":["apps/desktop","apps/desktop/native"]},
"apps/desktop":{"name":"desktop","version":"1.0.0","dependencies":{"x":"^2"}},
"apps/desktop/native":{"name":"native","version":"0.1.0","dependencies":{"x":"^2"}},
"apps/desktop/node_modules/x":{"version":"2.0.0"},
"node_modules/x":{"version":"1.0.0"},
"node_modules/desktop":{"resolved":"apps/desktop","link":true},
"node_modules/native":{"resolved":"apps/desktop/native","link":true}}}`,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	// both workspaces resolve x to apps/desktop/node_modules; the hoisted
	// x@1.0.0 is required by nothing (npm ci installs it: extraneous)
	if x2, x1 := g.Nodes["pkg:npm/x@2.0.0"], g.Nodes["pkg:npm/x@1.0.0"]; x2 == nil || x2.Extraneous || x1 == nil || !x1.Extraneous {
		t.Errorf("nodes %v, want x@2.0.0 (apps/desktop/node_modules) and x@1.0.0 extraneous", keys(g))
	}
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
}

// yarn "resolutions" replace the range of a dependency, and yarn 4 catalogs
// take it from .yarnrc.yml; the lockfile records the replacement.
// Three details of yarn 4 lockfiles seen in joplin: a resolution that
// replaces every version of a package by a patched one, whose lockfile key
// carries the locator of the workspace; a range with a trailing space; a
// resolution that replaces a dependency by a local link; and (storybook) a
// resolution key with the protocol ("ue@npm:^14.6.8").
func TestYarnResolutionToPatch(t *testing.T) {
	lock := `__metadata:
  version: 8

"a@npm:^1":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    nanoid: "npm:^3.3.11"
    p-limit: "npm:^3.1.0 "
    sharp: "npm:^0.34.5"
  linkType: hard

"p-limit@npm:^3.0.2, p-limit@npm:^3.1.0, p-limit@npm:^3.1.0 ":
  version: 3.1.0
  resolution: "p-limit@npm:3.1.0"
  linkType: hard

"sharp@link:./.yarn/empty-package/::locator=app%40workspace%3A.":
  version: 0.0.0-use.local
  resolution: "sharp@link:./.yarn/empty-package/::locator=app%40workspace%3A."
  languageName: node
  linkType: soft

"nanoid@npm:3.3.7":
  version: 3.3.7
  resolution: "nanoid@npm:3.3.7"
  linkType: hard

"ue@npm:14.6.8":
  version: 14.6.8
  resolution: "ue@npm:14.6.8"
  linkType: hard

"ue@patch:ue@npm%3A14.6.8#~/.yarn/patches/ue-npm-14.6.8-5f12b4535c.patch":
  version: 14.6.8
  resolution: "ue@patch:ue@npm%3A14.6.8#~/.yarn/patches/ue-npm-14.6.8-5f12b4535c.patch::version=14.6.8&hash=2"
  linkType: hard

"nanoid@patch:nanoid@npm%3A3.3.7#./.yarn/patches/nanoid-npm-3.3.7-98824ba130.patch::locator=app%40workspace%3A.":
  version: 3.3.7
  resolution: "nanoid@patch:nanoid@npm%3A3.3.7#./.yarn/patches/nanoid-npm-3.3.7-98824ba130.patch::version=3.3.7&hash=1&locator=app%40workspace%3A."
  linkType: hard
`
	pj := `{"name":"app","version":"1.0.0","dependencies":{"a":"^1","nanoid":"3.3.11","ue":"^14.6.8"},
"resolutions":{"nanoid":"patch:nanoid@npm%3A3.3.7#./.yarn/patches/nanoid-npm-3.3.7-98824ba130.patch","a/sharp":"link:./.yarn/empty-package/",
"ue@npm:^14.6.8":"patch:ue@npm%3A14.6.8#~/.yarn/patches/ue-npm-14.6.8-5f12b4535c.patch"}}`
	g, err := project(t, map[string]string{"package.json": pj, "yarn.lock": lock}, true)
	if err != nil {
		t.Fatal(err)
	}
	if g.Nodes["pkg:npm/nanoid@3.3.7"] == nil || g.Nodes["pkg:npm/a@1.0.0"] == nil || g.Nodes["pkg:npm/p-limit@3.1.0"] == nil || g.Nodes["pkg:npm/ue@14.6.8"] == nil {
		t.Errorf("nodes %v", keys(g))
	}
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
}

func TestYarnResolutionsAndCatalogs(t *testing.T) {
	lock := `__metadata:
  version: 8

"a@npm:^1":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    core: "npm:^7.0.0"
    old: "npm:^1.0.0"
  linkType: hard

"core@npm:7.29.7":
  version: 7.29.7
  resolution: "core@npm:7.29.7"
  linkType: hard

"old@npm:2.0.0":
  version: 2.0.0
  resolution: "old@npm:2.0.0"
  linkType: hard

"vitest@npm:^4.0.18":
  version: 4.0.18
  resolution: "vitest@npm:4.0.18"
  linkType: hard

"tool@npm:^3":
  version: 3.1.0
  resolution: "tool@npm:3.1.0"
  linkType: hard

"tool@npm:^2":
  version: 2.5.0
  resolution: "tool@npm:2.5.0"
  linkType: hard
`
	pj := `{"name":"app","version":"1.0.0","dependencies":{"a":"^1"},"devDependencies":{"vitest":"catalog:","tool":"catalog:build"},
"resolutions":{"core":"7.29.7","old@^1.0.0":"2.0.0"}}`
	g, err := project(t, map[string]string{"package.json": pj, "yarn.lock": lock,
		".yarnrc.yml": "catalogs:\n  build:\n    tool: ^3\n"}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"pkg:npm/core@7.29.7", "pkg:npm/old@2.0.0", "pkg:npm/vitest@4.0.18", "pkg:npm/tool@3.1.0"} {
		if g.Nodes[p] == nil {
			t.Errorf("%s missing; nodes %v", p, keys(g))
		}
	}
	if len(g.Incomplete) != 0 {
		t.Errorf("incomplete: %v", g.Incomplete)
	}
	// a catalog that cannot be read and several candidates: not analysed
	g, err = project(t, map[string]string{"package.json": pj, "yarn.lock": lock}, true)
	if err != nil {
		t.Fatal(err)
	}
	if g.Nodes["pkg:npm/vitest@4.0.18"] == nil || !strings.Contains(strings.Join(g.Incomplete, ";"), "tool@catalog:build") {
		t.Errorf("without .yarnrc.yml: nodes %v, incomplete %v", keys(g), g.Incomplete)
	}
}

func keys(g *model.Graph) []string {
	var out []string
	for k := range g.Nodes {
		out = append(out, k)
	}
	return out
}

// npm builds the project node from package.json and only compares it with the
// root entry of package-lock.json. A root entry that is missing or does not
// list a dependency of package.json must not drop that dependency (it was
// 0 components and a clean result before), a dependency listed only in the
// root entry does not become a dependency of the project (its entry x is
// required by nothing; npm ci installs it anyway, so it is kept as an
// extraneous entry in every case), and an entry without a version cannot be
// identified, so the analysis is incomplete.
func TestRootEntryFromPackageJSON(t *testing.T) {
	const pj = `{"name":"app","version":"1.0.0","dependencies":{"a":"^1","b":"^1"}}`
	const pkgs = `"node_modules/a":{"version":"1.0.0","dependencies":{"c":"^1"}},
"node_modules/b":{"version":"1.0.0"},"node_modules/c":{"version":"1.0.0"},"node_modules/x":{"version":"1.0.0"}`
	cases := []struct {
		name, root, want, note string
	}{
		{"no root entry", ``, "a@1.0.0 b@1.0.0 c@1.0.0 x@1.0.0", "has no entry for the project"},
		{"root entry without b", `"":{"dependencies":{"a":"^1"}},`, "a@1.0.0 b@1.0.0 c@1.0.0 x@1.0.0", "+b"},
		{"root entry with x", `"":{"dependencies":{"a":"^1","b":"^1","x":"^1"}},`, "a@1.0.0 b@1.0.0 c@1.0.0 x@1.0.0", "-x"},
		{"same", `"":{"dependencies":{"a":"^1","b":"^1"}},`, "a@1.0.0 b@1.0.0 c@1.0.0 x@1.0.0", ""},
	}
	for _, tc := range cases {
		g, err := project(t, map[string]string{"package.json": pj,
			"package-lock.json": `{"lockfileVersion":3,"packages":{` + tc.root + pkgs + `}}`}, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var names []string
		for _, c := range g.Components() {
			names = append(names, c.Name+"@"+c.Version)
		}
		sort.Strings(names)
		if got := strings.Join(names, " "); got != tc.want || len(g.Incomplete) != 0 {
			t.Errorf("%s: components %q incomplete %v, want %q and complete", tc.name, got, g.Incomplete, tc.want)
		}
		notes := strings.Join(g.Notes, " | ")
		if tc.note != "" && !strings.Contains(notes, tc.note) || tc.note == "" && strings.Contains(notes, "package.json") {
			t.Errorf("%s: notes %q, want %q", tc.name, notes, tc.note)
		}
	}
	g, err := project(t, map[string]string{"package.json": pj, "package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"dependencies":{"a":"^1","b":"^1"}},"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"resolved":"https://registry.npmjs.org/b/-/b-1.0.0.tgz"}}}`}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Incomplete) != 1 || !strings.Contains(g.Incomplete[0], "1 entry without a version was not analysed: node_modules/b") {
		t.Errorf("incomplete %v, want the entry without a version", g.Incomplete)
	}
}

// A direct dependency locked outside the range of package.json, a pnpm
// specifier that differs from package.json and a link entry that points to
// nothing the lockfile describes make the analysis incomplete (npm ci and
// pnpm --frozen-lockfile refuse such lockfiles); tags, aliases, git
// references and links to workspaces of the same name are accepted.
func TestLockfileRangesAndLinks(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // expected part of the incomplete note, "" = none
	}{
		{"v3 in range, tag, alias, git, workspace", map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"a":"^1.2.0","t":"latest","al":"npm:real@^2","g":"github:u/r#v1","w":"*"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{
"":{"workspaces":["packages/*"],"dependencies":{"a":"^1.2.0","t":"latest","al":"npm:real@^2","g":"github:u/r#v1","w":"*"}},
"packages/w":{"name":"w","version":"0.1.0"},
"node_modules/w":{"resolved":"packages/w","link":true},
"node_modules/a":{"version":"1.4.0"},
"node_modules/t":{"version":"3.0.0"},
"node_modules/al":{"name":"real","version":"2.1.0"},
"node_modules/g":{"version":"1.0.0","resolved":"git+ssh://git@github.com/u/r.git#abc"}}}`}, ""},
		{"v3 out of range", map[string]string{
			"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"^4.17.21"}},"node_modules/lodash":{"version":"4.17.15"}}}`},
			"lodash@4.17.15 (package.json: ^4.17.21)"},
		{"v1 out of range", map[string]string{
			"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
			"package-lock.json": `{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.15"}}}`},
			"lodash@4.17.15 (package.json: ^4.17.21)"},
		{"link without target", map[string]string{
			"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"resolved":"../../evil","link":true}}}`},
			"node_modules/lodash -> ../../evil"},
		{"link to another package", map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"lodash":"*"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"*"}},
"packages/evil":{"name":"evil","version":"1.0.0"},"node_modules/lodash":{"resolved":"packages/evil","link":true}}}`},
			"node_modules/lodash -> packages/evil (package evil)"},
		{"pnpm specifier differs", map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","dependencies":{"a":"^1.2.0"}}`,
			"pnpm-lock.yaml": `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1.0.0, version: 1.0.0}
packages:
  a@1.0.0: {resolution: {integrity: sha512-AA==}}
snapshots:
  a@1.0.0: {}
`}, "a (lockfile: ^1.0.0, package.json: ^1.2.0)"},
		{"pnpm override", map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","dependencies":{"a":"*","@s/b":"^1.0.0"}}`,
			"pnpm-lock.yaml": `lockfileVersion: '9.0'
overrides:
  a: ^2.0.0
  x@1>@s/b@<2: ^2.0.0
importers:
  .:
    dependencies:
      a: {specifier: ^2.0.0, version: 2.0.0}
      '@s/b': {specifier: ^2.0.0, version: 2.0.0}
packages:
  a@2.0.0: {resolution: {integrity: sha512-AA==}}
  '@s/b@2.0.0': {resolution: {integrity: sha512-BB==}}
snapshots:
  a@2.0.0: {}
  '@s/b@2.0.0': {}
`}, ""},
	}
	for _, tc := range cases {
		g, err := project(t, tc.files, true)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		got := strings.Join(g.Incomplete, "; ")
		switch {
		case tc.want == "" && got != "":
			t.Errorf("%s: incomplete %q, want none", tc.name, got)
		case tc.want != "" && !strings.Contains(got, tc.want):
			t.Errorf("%s: incomplete %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestOverrideTarget(t *testing.T) {
	for sel, want := range map[string]string{"a": "a", "@s/a": "@s/a", "a@<2": "a", "@s/a@>=1 <2": "@s/a",
		"parent>a": "a", "mssql@12.7.0>tedious": "tedious", "p@1>@s/a@^3": "@s/a"} {
		if got := overrideTarget(sel); got != want {
			t.Errorf("overrideTarget(%q) = %q, want %q", sel, got, want)
		}
	}
}
