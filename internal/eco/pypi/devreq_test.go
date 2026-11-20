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
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Development and test requirement files are part of the default graph:
// their packages take the dev or test scope, a package that runtime code
// needs keeps its runtime version and scope, runtime files included with -r
// are not read twice, and "-e ." (the project itself) is not reported as an
// unanalysed requirement. With --runtime-only the files are not read.
func TestDevRequirementFiles(t *testing.T) {
	pkgs := map[string]map[string][]string{ // name -> version -> requires_dist
		"flask":        {"3.0.0": {"werkzeug>=3"}},
		"werkzeug":     {"3.0.1": nil, "3.1.0": nil},
		"black":        {"24.1.0": {"click>=8"}},
		"click":        {"8.1.7": nil},
		"pytest":       {"8.0.0": {"pluggy>=1"}},
		"pluggy":       {"1.4.0": nil, "1.5.0": nil},
		"pytest-flask": {"1.3.0": {"flask", "werkzeug>=0.7", "pytest>=5"}},
		"mkdocs":       {"1.6.0": {"click>=7"}},
		"coverage":     {"7.4.0": nil},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case len(parts) == 2 && parts[0] == "simple":
			vs := pkgs[parts[1]]
			if vs == nil {
				http.NotFound(w, r)
				return
			}
			p := SimpleProject{Name: parts[1]}
			for v := range vs {
				p.Versions = append(p.Versions, v)
				p.Files = append(p.Files, SimpleFile{Filename: strings.ReplaceAll(parts[1], "-", "_") + "-" + v + "-py3-none-any.whl"})
			}
			sort.Strings(p.Versions)
			json.NewEncoder(w).Encode(p)
		case len(parts) == 4 && parts[0] == "pypi":
			req, ok := pkgs[parts[1]][parts[2]]
			if !ok {
				http.NotFound(w, r)
				return
			}
			var vi VersionInfo
			vi.Info.Name, vi.Info.Version, vi.Info.RequiresDist = parts[1], parts[2], req
			json.NewEncoder(w).Encode(vi)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := Index
	Index = srv.URL
	defer func() { Index = old }()

	dir := t.TempDir()
	write := func(name, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", "flask==3.0.0\nwerkzeug==3.0.1\n")
	write("requirements-dev.txt", "-r requirements.txt\n-e .\nblack==24.1.0\n")
	write("requirements-test.txt", "-r requirements.txt\npytest\npytest-flask==1.3.0\ncoverage==7.4.0\n")
	write("docs/requirements.txt", "mkdocs==1.6.0\n")

	load := func(includeDev bool) map[string]string {
		t.Helper()
		g, err := Plugin{}.Load(context.Background(), dir, common.Options{Net: netx.New("", false), IncludeDev: includeDev, MaxRounds: 3})
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Incomplete) != 0 {
			t.Errorf("includeDev=%v: incomplete %v", includeDev, g.Incomplete)
		}
		got := map[string]string{}
		for _, c := range g.Components() {
			got[c.Name+"@"+c.Version] = fmt.Sprintf("%s/%d", c.Scope, c.Depth)
		}
		return got
	}
	want := map[string]string{
		"flask@3.0.0": "runtime/1", "werkzeug@3.0.1": "runtime/1",
		"black@24.1.0": "dev/1", "click@8.1.7": "dev/2", "mkdocs@1.6.0": "dev/1",
		"pytest@8.0.0": "test/1", "pluggy@1.5.0": "test/2", "pytest-flask@1.3.0": "test/1", "coverage@7.4.0": "test/1",
	}
	if got := load(true); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("default graph\n got %v\nwant %v", got, want)
	}
	if got := load(false); fmt.Sprint(got) != fmt.Sprint(map[string]string{"flask@3.0.0": "runtime/1", "werkzeug@3.0.1": "runtime/1"}) {
		t.Errorf("runtime-only graph %v", got)
	}
	// a dev file that pins a runtime package to another version cannot be
	// installed next to the runtime requirements: the analysis is incomplete
	write("requirements-dev.txt", "werkzeug==3.1.0\n")
	g, err := Plugin{}.Load(context.Background(), dir, common.Options{Net: netx.New("", false), IncludeDev: true, MaxRounds: 3})
	if err != nil || len(g.Incomplete) == 0 {
		t.Errorf("conflicting dev pin: err %v, incomplete %v", err, g.Incomplete)
	}
	for _, s := range []string{"-e .", "-e .[test]", "--editable=.", "."} {
		if !selfReference(s) {
			t.Errorf("%q is the project itself", s)
		}
	}
	if selfReference("-e ../other") || selfReference("-e git+https://x/y.git") {
		t.Error("other editable requirements are dependencies")
	}
}
