package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadDir(t *testing.T, dir string) *model.Graph {
	t.Helper()
	g, err := Plugin{}.Load(context.Background(), dir, common.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// purls lists "purl@depth" of all components.
func purls(g *model.Graph) string {
	var out []string
	for _, c := range g.Components() {
		out = append(out, strings.TrimPrefix(c.PURL, "pkg:pypi/")+"/"+string(rune('0'+c.Depth)))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// uv.lock: two versions of one package selected by markers are both kept; a
// package from git or a URL is not reported as the PyPI release of the same
// name, its dependencies stay in the graph, and the analysis is incomplete.
func TestUVMultiVersionAndExternalSources(t *testing.T) {
	dir := writeProject(t, map[string]string{"uv.lock": `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "numpy", version = "1.24.4", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < '3.9'" },
    { name = "numpy", version = "2.0.2", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= '3.9'" },
    { name = "mylib" },
    { name = "psycopg-c", version = "3.3.4", source = { url = "https://example.com/psycopg_c-3.3.4-linux.whl" } },
    { name = "torch" },
]

[[package]]
name = "torch"
version = "2.14.0"
source = { registry = "https://download.pytorch.org/whl/cpu" }

[[package]]
name = "numpy"
version = "1.24.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "numpy"
version = "2.0.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mylib"
version = "0.3.0"
source = { git = "https://github.com/x/mylib?rev=abc#abc" }
dependencies = [{ name = "six" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "psycopg-c"
version = "3.3.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "psycopg-c"
version = "3.3.4"
source = { url = "https://example.com/psycopg_c-3.3.4-linux.whl" }
`})
	g := loadDir(t, dir)
	// psycopg-c is a direct dependency by name, so the index release is
	// linked as well (all entries of a name are kept, as for markers)
	if got, want := purls(g), "numpy@1.24.4/1 numpy@2.0.2/1 psycopg-c@3.3.4/1 six@1.16.0/1 torch@2.14.0/1"; got != want {
		t.Errorf("components %s, want %s", got, want)
	}
	// a package of another index keeps its index, so that its files are not
	// compared with the PyPI files of the same version
	if r := g.Nodes["pkg:pypi/torch@2.14.0"].Resolved; r != "https://download.pytorch.org/whl/cpu" {
		t.Errorf("torch resolved %q", r)
	}
	if g.Nodes["pkg:pypi/six@1.16.0"].Resolved != "" || len(g.Notes) != 1 {
		t.Errorf("PyPI package with an index, or notes %v", g.Notes)
	}
	inc := strings.Join(g.Incomplete, "\n")
	for _, w := range []string{"mylib 0.3.0 (git https://github.com/x/mylib", "psycopg-c 3.3.4 (url https://example.com/"} {
		if !strings.Contains(inc, w) {
			t.Errorf("incomplete does not mention %q: %v", w, g.Incomplete)
		}
	}
}

// poetry.lock: both versions of a package are kept and the constraint of a
// dependency selects among them; a git package is reported as not analysed.
func TestPoetryMultiVersionAndGit(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"pyproject.toml": `[tool.poetry]
name = "app"
version = "0.1.0"
[tool.poetry.dependencies]
python = ">=3.8"
numpy = [{version = "1.24.4", python = "<3.9"}, {version = "2.0.2", python = ">=3.9"}]
mylib = {git = "https://github.com/x/mylib.git"}
`,
		"poetry.lock": `[[package]]
name = "numpy"
version = "1.24.4"
files = []

[[package]]
name = "numpy"
version = "2.0.2"
files = []

[[package]]
name = "mylib"
version = "0.3.0"
files = []
[package.dependencies]
numpy = ">=2"
[package.source]
type = "git"
url = "https://github.com/x/mylib.git"
resolved_reference = "abc"
`})
	g := loadDir(t, dir)
	if got, want := purls(g), "numpy@1.24.4/1 numpy@2.0.2/1"; got != want {
		t.Errorf("components %s, want %s", got, want)
	}
	if len(g.Incomplete) != 1 || !strings.Contains(g.Incomplete[0], "mylib 0.3.0 (git https://github.com/x/mylib.git@abc)") {
		t.Errorf("incomplete %v", g.Incomplete)
	}
}

// Pipfile.lock entries without a version (git, path) are reported.
func TestPipfileUnversioned(t *testing.T) {
	dir := writeProject(t, map[string]string{"Pipfile.lock": `{"default": {
		"six": {"version": "==1.16.0"},
		"mylib": {"git": "https://github.com/x/mylib.git", "ref": "abc"}}}`})
	g := loadDir(t, dir)
	if len(g.Incomplete) != 1 || !strings.Contains(g.Incomplete[0], "mylib") {
		t.Errorf("incomplete %v", g.Incomplete)
	}
}

// Malformed requirement lines and direct references of pyproject.toml are
// reported instead of being read as other requirements.
func TestMalformedAndDirectReferences(t *testing.T) {
	dir := writeProject(t, map[string]string{"requirements.txt": "requests==2.32.3\nfoo ===== 1\npkg[extra; python_version < \"3\"\n"})
	_, skipped, err := readRequirements(filepath.Join(dir, "requirements.txt"), map[string]bool{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped %q, want the two malformed lines", skipped)
	}
	pp := filepath.Join(writeProject(t, map[string]string{"pyproject.toml": `[project]
name = "app"
dependencies = ["requests>=2", "mylib @ git+https://github.com/x/mylib", "bad ===== 1"]
[tool.poetry.dependencies]
python = "^3.10"
flask = "^3.0"
local = {path = "../local"}
pinned = {version = "1.2.3", extras = ["x"]}
multi = [{version = "1", python = "<3.9"}, {version = "2", python = ">=3.9"}]
`}), "pyproject.toml")
	lines, skipped, err := pyprojectDeps(pp)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range lines {
		got = append(got, l.Name+l.Spec)
	}
	if g := strings.Join(got, " "); g != "requests>=2 flask>=3.0,<4 pinned==1.2.3" {
		t.Errorf("requirements %s", g)
	}
	if len(skipped) != 4 {
		t.Errorf("skipped %q, want mylib, bad, local and multi", skipped)
	}
}

// scopes lists "name:scope/depth" of all components.
func scopes(g *model.Graph) string {
	var out []string
	for _, c := range g.Components() {
		out = append(out, fmt.Sprintf("%s:%s/%d", c.Name, c.Scope, c.Depth))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// uv.lock: the packages of an extra belong to the package that requested it.
// urllib3 is a runtime package, but only the development tool selenium asks
// for urllib3[socks], so PySocks is a development package (uv export
// --no-dev leaves it out); an extra requested by a runtime package
// (httpx[http2] by app-lib) keeps its packages in runtime.
func TestUVExtraScopeOfRequester(t *testing.T) {
	dir := writeProject(t, map[string]string{"uv.lock": `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "urllib3" }, { name = "app-lib" }]
[package.dev-dependencies]
dev = [{ name = "selenium" }]

[[package]]
name = "app-lib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "httpx", extra = ["http2"] }]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
[package.optional-dependencies]
http2 = [{ name = "h2" }]

[[package]]
name = "h2"
version = "4.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
[package.optional-dependencies]
socks = [{ name = "pysocks" }]

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "selenium"
version = "4.16.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3", extra = ["socks"] }]
`})
	if got, want := scopes(loadScoped(t, dir, true)), "app-lib:runtime/1 h2:runtime/2 httpx:runtime/2 pysocks:dev/2 selenium:dev/1 urllib3:runtime/1"; got != want {
		t.Errorf("full graph: %s, want %s", got, want)
	}
	if got, want := scopes(loadScoped(t, dir, false)), "app-lib:runtime/1 h2:runtime/2 httpx:runtime/2 urllib3:runtime/1"; got != want {
		t.Errorf("runtime graph: %s, want %s", got, want)
	}
}

func loadScoped(t *testing.T, dir string, dev bool) *model.Graph {
	t.Helper()
	g, err := Plugin{}.Load(context.Background(), dir, common.Options{IncludeDev: dev})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// Development groups (uv dependency groups, poetry groups, the develop section
// of Pipfile.lock) and the project's extras are in the full graph with their
// scope; a package that a runtime dependency also needs stays runtime; the
// runtime graph leaves them out.
func TestPythonDevScopes(t *testing.T) {
	uv := writeProject(t, map[string]string{"uv.lock": `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.optional-dependencies]
socks = [{ name = "pysocks" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }, { name = "urllib3" }]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.4.0"
source = { registry = "https://pypi.org/simple" }
`})
	if got, want := scopes(loadScoped(t, uv, true)), "pluggy:dev/2 pysocks:extra/1 pytest:dev/1 requests:runtime/1 urllib3:runtime/2"; got != want {
		t.Errorf("uv full graph: %s, want %s", got, want)
	}
	if got, want := scopes(loadScoped(t, uv, false)), "requests:runtime/1 urllib3:runtime/2"; got != want {
		t.Errorf("uv runtime graph: %s, want %s", got, want)
	}

	poetry := writeProject(t, map[string]string{"pyproject.toml": `[tool.poetry.dependencies]
python = "^3.10"
flask = "^2.0"
[tool.poetry.group.test.dependencies]
pytest = "^7.0"
`, "poetry.lock": `[[package]]
name = "flask"
version = "2.0.1"
[package.dependencies]
jinja2 = ">=3.0"

[[package]]
name = "jinja2"
version = "3.0.1"

[[package]]
name = "pytest"
version = "7.0.0"
category = "dev"
[package.dependencies]
jinja2 = "*"
`})
	if got, want := scopes(loadScoped(t, poetry, true)), "flask:runtime/1 jinja2:runtime/2 pytest:dev/1"; got != want {
		t.Errorf("poetry full graph: %s, want %s", got, want)
	}

	// Pipfile.lock without a Pipfile: develop entries are not direct runtime
	// dependencies
	pipenv := writeProject(t, map[string]string{"Pipfile.lock": `{"default": {"six": {"version": "==1.16.0"}},
		"develop": {"black": {"version": "==24.1.0"}}}`})
	if got, want := scopes(loadScoped(t, pipenv, true)), "black:dev/1 six:runtime/1"; got != want {
		t.Errorf("Pipfile.lock full graph: %s, want %s", got, want)
	}
	if got, want := scopes(loadScoped(t, pipenv, false)), "six:runtime/1"; got != want {
		t.Errorf("Pipfile.lock runtime graph: %s, want %s", got, want)
	}
}

// Pipfile.lock is flat and valid for several environments: its edges come from
// the registry, a requirement counts if its target is locked (also for another
// Python version), extras of the entry and of a parent's requirement are
// activated, and an extra that nobody asked for adds no edge.
func TestPipfileEdges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requires := map[string][]string{
			"a": {`b ; extra == "x"`, `c ; python_version < "3.0"`, `d ; extra == "nope"`, `a[z] ; extra == "x"`},
			"c": {"e[y]"},
			"e": {`f ; extra == "y"`},
		}
		name := strings.Split(strings.TrimPrefix(r.URL.Path, "/pypi/"), "/")[0]
		fmt.Fprintf(w, `{"info": {"name": %q, "version": "1.0", "requires_dist": %s}}`, name, mustJSON(requires[name]))
	}))
	defer srv.Close()
	old := Index
	Index = srv.URL
	defer func() { Index = old }()
	entries := []string{}
	for _, n := range []string{"b", "c", "d", "e", "f"} {
		entries = append(entries, fmt.Sprintf(`%q: {"version": "==1.0"}`, n))
	}
	dir := writeProject(t, map[string]string{
		"Pipfile":      "[packages]\na = \"*\"\nd = \"*\"\n",
		"Pipfile.lock": `{"default": {"a": {"version": "==1.0", "extras": ["x"]}, ` + strings.Join(entries, ", ") + `}, "develop": {}}`,
	})
	g, err := Plugin{}.Load(context.Background(), dir, common.Options{Net: netx.New("", false), IncludeDev: true})
	if err != nil {
		t.Fatal(err)
	}
	var edges []string
	for from, es := range g.Out {
		if from == g.Root {
			continue
		}
		for _, e := range es {
			edges = append(edges, g.Nodes[from].Name+">"+g.Nodes[e.To].Name)
		}
	}
	sort.Strings(edges)
	if got, want := strings.Join(edges, " "), "a>b a>c c>e e>f"; got != want {
		t.Errorf("edges %q, want %q", got, want)
	}
	if n := len(g.Components()); n != 6 || len(g.Incomplete) != 0 {
		t.Errorf("%d components, incomplete %v", n, g.Incomplete)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A dependency declared in pyproject.toml or the Pipfile that the lockfile
// does not lock makes the analysis incomplete, as for npm (the graph was
// complete and silently smaller before). uv compares against the
// requirements it recorded for the project, so a dependency that uv dropped
// for all supported Python versions is not reported; the project itself and
// workspace members are not dependencies; development groups count only when
// development dependencies are analysed.
func TestPythonLockfileOutOfSync(t *testing.T) {
	uvLock := func(recorded string) string {
		return `version = 1
[[package]]
name = "app"
version = "1.0.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
` + recorded + `
[[package]]
name = "lib"
version = "0.1.0"
source = { editable = "packages/lib" }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
`
	}
	const meta = `[package.metadata]
requires-dist = [{ name = "requests" }, { name = "lib", editable = "packages/lib" }, { name = "tomli", marker = "python_full_version < '3.8'" }]
[package.metadata.requires-dev]
dev = [{ name = "pytest" }]`
	pyproject := func(deps, dev string) string {
		return "[project]\nname = \"app\"\nversion = \"1.0.0\"\ndependencies = [" + deps + "]\n[dependency-groups]\ndev = [" + dev + "]\n"
	}
	cases := []struct {
		name  string
		files map[string]string
		dev   bool
		want  string // part of the incomplete note, "" = in sync
	}{
		{"uv recorded, in sync", map[string]string{"uv.lock": uvLock(meta), "pyproject.toml": pyproject(`"requests", "lib", "tomli; python_version < '3.8'"`, `"pytest", "app[test]"`)}, true, ""},
		{"uv recorded, flask added", map[string]string{"uv.lock": uvLock(meta), "pyproject.toml": pyproject(`"requests", "flask"`, `"pytest"`)}, false, "uv.lock is out of sync with pyproject.toml: 1 declared dependency has no lockfile entry: flask"},
		{"uv recorded, dev group added", map[string]string{"uv.lock": uvLock(meta), "pyproject.toml": pyproject(`"requests"`, `"pytest", "ruff"`)}, true, "no lockfile entry: ruff"},
		{"uv recorded, dev group added, runtime only", map[string]string{"uv.lock": uvLock(meta), "pyproject.toml": pyproject(`"requests"`, `"pytest", "ruff"`)}, false, ""},
		{"uv without metadata", map[string]string{"uv.lock": uvLock(""), "pyproject.toml": pyproject(`"requests", "lib", "flask"`, ``)}, false, "no lockfile entry: flask"},
		{"poetry", map[string]string{"poetry.lock": "[[package]]\nname = \"flask\"\nversion = \"2.0.1\"\n",
			"pyproject.toml": "[tool.poetry]\nname = \"app\"\n[tool.poetry.dependencies]\npython = \"^3.10\"\nFlask = \"^2.0\"\nDjango = \"^4.0\"\n"}, false,
			"poetry.lock is out of sync with pyproject.toml: 1 declared dependency has no lockfile entry: django"},
		{"pipfile", map[string]string{"Pipfile.lock": `{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}`,
			"Pipfile": "[packages]\nrequests = \"*\"\ndjango = \"*\"\n[dev-packages]\npytest = \"*\"\nruff = \"*\"\n"}, true,
			"Pipfile.lock is out of sync with Pipfile: 1 declared dependency has no lockfile entry: django"},
		{"pipfile dev", map[string]string{"Pipfile.lock": `{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}`,
			"Pipfile": "[packages]\nrequests = \"*\"\n[dev-packages]\npytest = \"*\"\nruff = \"*\"\n"}, true,
			"Pipfile.lock is out of sync with Pipfile [dev-packages]: 1 declared dependency has no lockfile entry: ruff"},
	}
	for _, tc := range cases {
		g := loadScoped(t, writeProject(t, tc.files), tc.dev)
		got := strings.Join(g.Incomplete, " | ")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: incomplete %q, want %q", tc.name, got, tc.want)
		}
	}
}
