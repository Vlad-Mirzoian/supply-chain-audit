package risk

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// fakePyPI serves deps.dev and the PyPI Simple and JSON APIs for one
// package with two releases (prev, cur) and for its dependencies.
type fakeRelease struct {
	version, uploaded, author, authorEmail string
	requires                               []string
}

func fakePyPI(t *testing.T, name string, prev, cur fakeRelease, deps map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(v any) { json.NewEncoder(w).Encode(v) }
		p := r.URL.Path
		switch {
		case p == "/dd/systems/pypi/packages/"+name:
			write(map[string]any{"versions": []map[string]any{
				{"versionKey": map[string]string{"version": prev.version}, "publishedAt": prev.uploaded},
				{"versionKey": map[string]string{"version": cur.version}, "publishedAt": cur.uploaded},
			}})
		case p == "/simple/"+name+"/":
			write(map[string]any{"name": name, "files": []map[string]string{
				{"filename": name + "-" + prev.version + "-py3-none-any.whl", "upload-time": prev.uploaded},
				{"filename": name + "-" + cur.version + "-py3-none-any.whl", "upload-time": cur.uploaded},
			}})
		case strings.HasPrefix(p, "/simple/"):
			dep := strings.Trim(strings.TrimPrefix(p, "/simple/"), "/")
			first, ok := deps[dep]
			if !ok {
				http.NotFound(w, r)
				return
			}
			write(map[string]any{"name": dep, "files": []map[string]string{
				{"filename": dep + "-1.0.0-py3-none-any.whl", "upload-time": first},
			}})
		case p == "/pypi/"+name+"/"+prev.version+"/json" || p == "/pypi/"+name+"/"+cur.version+"/json":
			rel := prev
			if strings.Contains(p, "/"+cur.version+"/") {
				rel = cur
			}
			write(map[string]any{"info": map[string]any{"name": name, "version": rel.version,
				"author": rel.author, "author_email": rel.authorEmail, "requires_dist": rel.requires}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	oldDD, oldIndex := DepsDev, pypi.Index
	DepsDev, pypi.Index = srv.URL+"/dd", srv.URL
	t.Cleanup(func() { DepsDev, pypi.Index = oldDD, oldIndex })
}

func signalNames(c *model.Component) []string {
	sig, _ := Signals(c, nil, DefaultWeights(), Internal{}, time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC))
	var out []string
	for _, s := range sig {
		out = append(out, s.Name)
	}
	return out
}

// The django-redis case of corpus (a): the same maintainer written as
// "Name <e-mail>" instead of "e-mail", and a new dependency that has existed
// for years, must raise neither publisher_changed nor young_new_dependency.
func TestPyPIMetaSamePeopleOldDependency(t *testing.T) {
	fakePyPI(t, "django-redis",
		fakeRelease{"6.0.0", "2025-06-01T10:00:00Z", "", "niwi@niwi.nz", []string{"redis>=4"}},
		fakeRelease{"7.0.0", "2026-10-01T10:00:00Z", "", "Andrei Antoukh <niwi@niwi.nz>", []string{"redis>=4", "typing-extensions>=4"}},
		map[string]string{"typing-extensions": "2017-01-01T00:00:00Z"})
	c := model.NewComponent(model.PyPI, "", "django-redis", "7.0.0")
	m := NewCollector(netx.New("", false), time.Now()).collectOne(context.Background(), c)
	c.Meta = m
	if len(m.NewDependencies) != 1 || m.NewDependencies[0] != "typing-extensions" {
		t.Fatalf("new dependencies %v", m.NewDependencies)
	}
	if m.NewDepMinAgeDays < 3000 {
		t.Errorf("age of typing-extensions = %.1f days, want > 3000", m.NewDepMinAgeDays)
	}
	for _, s := range signalNames(c) {
		if s == "publisher_changed" || s == "young_new_dependency" {
			t.Errorf("false signal %s (publisher %q, previous %q)", s, m.Publisher, m.PreviousPublisher)
		}
	}
}

// A release by other people that pulls in a package created the day before
// must still raise both signals; a new dependency whose age is unknown must
// not count as 0 days old.
func TestPyPIMetaNewPeopleYoungDependency(t *testing.T) {
	fakePyPI(t, "requestz",
		fakeRelease{"2.0.0", "2026-01-01T10:00:00Z", "Jane Doe", "jane@example.org", nil},
		fakeRelease{"2.0.1", "2026-10-27T10:00:00Z", "", "attacker@evil.example", []string{"crypto-shim", "unknown-dep"}},
		map[string]string{"crypto-shim": "2026-10-26T10:00:00Z"})
	c := model.NewComponent(model.PyPI, "", "requestz", "2.0.1")
	m := NewCollector(netx.New("", false), time.Now()).collectOne(context.Background(), c)
	c.Meta = m
	if math.Abs(m.NewDepMinAgeDays-1) > 0.01 {
		t.Errorf("age of the youngest new dependency = %.2f days, want 1", m.NewDepMinAgeDays)
	}
	got := strings.Join(signalNames(c), " ")
	for _, want := range []string{"publisher_changed", "young_new_dependency"} {
		if !strings.Contains(got, want) {
			t.Errorf("signal %s missing (got %s)", want, got)
		}
	}
}

func TestNewDepAgeUnknown(t *testing.T) {
	m := &model.PackageMeta{PublishedAt: time.Now(), NewDependencies: []string{"x"}, NewDepMinAgeDays: -1}
	newDepAge(m, func(string) []time.Time { return nil })
	if m.NewDepMinAgeDays != -1 {
		t.Errorf("unknown age recorded as %.1f", m.NewDepMinAgeDays)
	}
}

func TestPyPIPeople(t *testing.T) {
	a := pypiPeople("Ilya Etingof", "Ilya Etingof <etingof@gmail.com>", "", "Christian Heimes <christian@python.org>")
	b := pypiPeople("", "etingof@gmail.com", "Christian  Heimes", "CHRISTIAN@python.org")
	if !anyIn(a, b) {
		t.Errorf("no common person in %v and %v", a, b)
	}
	want := "christian heimes, christian@python.org, etingof@gmail.com, ilya etingof"
	if got := strings.Join(a, ", "); got != want {
		t.Errorf("pypiPeople = %q, want %q", got, want)
	}
	if got := pypiPeople("=?utf-8?q?Timoth=C3=A9e_Mazzucotelli?= <dev@pawamoy.fr>"); strings.Join(got, ", ") != "dev@pawamoy.fr, timothée mazzucotelli" {
		t.Errorf("RFC 2047 name not decoded: %q", got)
	}
}

func TestPersonName(t *testing.T) {
	for in, want := range map[string]string{
		"Ann Lee <ann@x.org> (https://x.org)": "Ann Lee",
		"  Bob   B ":                          "Bob B",
		"ann@x.org":                           "",
		"<ann@x.org>":                         "",
		"=?utf-8?q?J=C3=BCrgen?=":             "Jürgen",
		"":                                    "",
	} {
		if got := personName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// A hijacked npm release published minutes ago is not yet in deps.dev, and
// neither is the dependency it injects: the publication time and the age of
// the new dependency come from the registry's own record, so the release
// still gets its age (cooldown) and the young-dependency signal.
func TestNPMMetaRegistryTimesBeforeDepsDev(t *testing.T) {
	now := time.Date(2026, 11, 10, 20, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(v any) { json.NewEncoder(w).Encode(v) }
		switch p := r.URL.Path; p {
		case "/dd/systems/npm/packages/httpkit-client": // knows only the previous release
			write(map[string]any{"versions": []map[string]any{
				{"versionKey": map[string]string{"version": "2.6.0"}, "publishedAt": "2026-09-01T10:00:00Z"}}})
		case "/npm/httpkit-client":
			write(map[string]any{"name": "httpkit-client", "time": map[string]string{
				"created": "2025-01-01T00:00:00Z", "2.6.0": "2026-09-01T10:00:00Z", "2.6.1": "2026-11-10T19:40:00.123Z"}})
		case "/npm/httpkit-client/2.6.0":
			write(map[string]any{"name": "httpkit-client", "version": "2.6.0", "_npmUser": map[string]string{"name": "maint-a"},
				"dependencies": map[string]string{"follow-redirects": "^1.15.0"}})
		case "/npm/httpkit-client/2.6.1":
			write(map[string]any{"name": "httpkit-client", "version": "2.6.1", "_npmUser": map[string]string{"name": "maint-a"},
				"dependencies": map[string]string{"follow-redirects": "^1.15.0", "crypto-shim-js": "^4.2.1"}})
		case "/npm/crypto-shim-js": // published the day before, unknown to deps.dev
			write(map[string]any{"name": "crypto-shim-js", "time": map[string]string{
				"created": "2026-11-09T18:00:00Z", "4.2.1": "2026-11-09T18:00:00Z"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	oldDD, oldReg := DepsDev, npm.Registry
	DepsDev, npm.Registry = srv.URL+"/dd", srv.URL+"/npm"
	t.Cleanup(func() { DepsDev, npm.Registry = oldDD, oldReg })
	c := model.NewComponent(model.NPM, "", "httpkit-client", "2.6.1")
	m := NewCollector(netx.New("", false), now).collectOne(context.Background(), c)
	c.Meta = m
	if want := time.Date(2026, 11, 10, 19, 40, 0, 123e6, time.UTC); !m.PublishedAt.Equal(want) {
		t.Fatalf("published %v, want %v from the registry", m.PublishedAt, want)
	}
	if math.Abs(m.NewDepMinAgeDays-(25.0+40.0/60)/24) > 0.01 {
		t.Errorf("age of crypto-shim-js = %.3f days, want about 1.07", m.NewDepMinAgeDays)
	}
	sig, _ := Signals(c, nil, DefaultWeights(), Internal{}, now)
	got := map[string]bool{}
	for _, s := range sig {
		got[s.Name] = true
	}
	for _, want := range []string{"cooldown", "young_new_dependency"} {
		if !got[want] {
			t.Errorf("signal %s missing (got %v)", want, got)
		}
	}
}

// When deps.dev cannot be read, the release history and the previous
// version come from the registry, so a hijacked release is still compared
// with its predecessor (new publisher, new install script); the failure is
// recorded, while a source that does not know a package is not a failure.
func TestDepsDevUnavailableHistoryFromRegistry(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(v any) { json.NewEncoder(w).Encode(v) }
		switch p := r.URL.Path; {
		case strings.HasPrefix(p, "/dd/"):
			http.Error(w, "forbidden", http.StatusForbidden) // not "not found": an outage
		case p == "/npm/colorkit":
			write(map[string]any{"name": "colorkit", "time": map[string]string{"created": "2019-01-01T00:00:00Z",
				"1.4.0": "2019-01-01T00:00:00Z", "1.5.0": "2024-03-01T00:00:00Z", "2.0.0-beta.1": "2026-11-01T00:00:00Z", "1.5.1": "2026-11-11T11:00:00Z"}})
		case p == "/npm/colorkit/1.5.0":
			write(map[string]any{"name": "colorkit", "version": "1.5.0", "_npmUser": map[string]string{"name": "owner"}})
		case p == "/npm/colorkit/1.5.1":
			write(map[string]any{"name": "colorkit", "version": "1.5.1", "_npmUser": map[string]string{"name": "stranger"},
				"scripts": map[string]string{"postinstall": "node setup.js"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	oldDD, oldReg := DepsDev, npm.Registry
	DepsDev, npm.Registry = srv.URL+"/dd", srv.URL+"/npm"
	t.Cleanup(func() { DepsDev, npm.Registry = oldDD, oldReg })
	c := model.NewComponent(model.NPM, "", "colorkit", "1.5.1")
	m := NewCollector(netx.New("", false), now).collectOne(context.Background(), c)
	c.Meta = m
	if m.PreviousVersion != "1.5.0" || m.Releases != 4 || !m.PublishedAt.Equal(time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC)) {
		t.Fatalf("previous %q, releases %d, published %v: want 1.5.0, 4 and the registry time", m.PreviousVersion, m.Releases, m.PublishedAt)
	}
	if len(m.Unavailable) != 1 || !strings.HasPrefix(m.Unavailable[0], "deps.dev: ") {
		t.Errorf("unavailable %v, want one deps.dev entry", m.Unavailable)
	}
	got := strings.Join(signalNames(c), " ")
	for _, want := range []string{"publisher_changed", "install_script_added"} {
		if !strings.Contains(got, want) {
			t.Errorf("signal %s missing (got %s)", want, got)
		}
	}
	// deps.dev answering "not found" is no failure
	fakePyPI(t, "newpkg", fakeRelease{"0.9.0", "2026-10-01T10:00:00Z", "", "a@b.org", nil},
		fakeRelease{"1.0.0", "2026-11-01T10:00:00Z", "", "a@b.org", nil}, nil)
	p := model.NewComponent(model.PyPI, "", "other", "1.0.0")
	if pm := NewCollector(netx.New("", false), now).collectOne(context.Background(), p); len(pm.Unavailable) != 0 {
		t.Errorf("unavailable %v for packages that the sources do not know", pm.Unavailable)
	}
}

// For an SBOM the collector records the SHA-256 of every file of the PyPI
// release from the Simple API page it reads anyway (no further request); a
// scan, which does not ask for artifact hashes, records none.
func TestPyPIArtifactHashes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/pkg/":
			json.NewEncoder(w).Encode(map[string]any{"name": "pkg", "files": []map[string]any{
				{"filename": "pkg-1.0-py3-none-any.whl", "hashes": map[string]string{"sha256": "AA11"}, "upload-time": "2026-01-01T00:00:00Z"},
				{"filename": "pkg-1.0.tar.gz", "hashes": map[string]string{"sha256": "bb22"}, "upload-time": "2026-01-01T00:00:00Z"},
				{"filename": "pkg-0.9-py3-none-any.whl", "hashes": map[string]string{"sha256": "cc33"}, "upload-time": "2025-01-01T00:00:00Z"},
			}})
		case "/pypi/pkg/1.0/json", "/pypi/pkg/0.9/json":
			json.NewEncoder(w).Encode(map[string]any{"info": map[string]any{"name": "pkg"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldDD, oldIndex := DepsDev, pypi.Index
	DepsDev, pypi.Index = srv.URL+"/dd", srv.URL
	defer func() { DepsDev, pypi.Index = oldDD, oldIndex }()
	for _, sbom := range []bool{false, true} {
		c := model.NewComponent(model.PyPI, "", "pkg", "1.0")
		col := NewCollector(netx.New("", false), time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC))
		col.ArtifactHashes = sbom
		col.Collect(context.Background(), []*model.Component{c})
		want := []string(nil)
		if sbom {
			want = []string{"aa11", "bb22"} // both files of 1.0, not the one of 0.9
		}
		if !slices.Equal(c.Meta.RepoSHA256, want) {
			t.Errorf("artifact hashes %v: %v, want %v", sbom, c.Meta.RepoSHA256, want)
		}
	}
}

// History gives the release history of a package by name as Collect does:
// from deps.dev, or from the PyPI Simple API when deps.dev does not know the
// package (yet); a package that no source knows is netx.ErrNotFound.
func TestHistoryByName(t *testing.T) {
	fakePyPI(t, "django-redis",
		fakeRelease{"6.0.0", "2025-06-01T10:00:00Z", "", "", nil},
		fakeRelease{"7.0.0", "2026-10-01T10:00:00Z", "", "", nil},
		map[string]string{"brand-new": "2026-11-24T08:00:00Z"})
	col := NewCollector(netx.New("", false), time.Now())
	ctx := context.Background()
	m, err := col.History(ctx, model.PyPI, "django-redis")
	if err != nil || m.Releases != 2 || m.FirstReleaseAt.Format("2006-01-02") != "2025-06-01" || m.LatestReleaseAt.Format("2006-01-02") != "2026-10-01" {
		t.Errorf("deps.dev history: %v, %+v", err, m)
	}
	m, err = col.History(ctx, model.PyPI, "brand-new")
	if err != nil || m.Releases != 1 || m.FirstReleaseAt.Format(time.RFC3339) != "2026-11-24T08:00:00Z" {
		t.Errorf("history from the Simple API: %v, %+v", err, m)
	}
	if _, err := col.History(ctx, model.PyPI, "no-such-package"); !errors.Is(err, netx.ErrNotFound) {
		t.Errorf("unknown package: %v, want ErrNotFound", err)
	}
	if _, err := col.History(ctx, model.Maven, "org.x:lib"); !errors.Is(err, netx.ErrNotFound) {
		t.Errorf("Maven without deps.dev record: %v, want ErrNotFound", err)
	}
}
