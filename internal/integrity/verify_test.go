package integrity

import (
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// trustedRoot copies the Sigstore trusted root of the test data into dir (it
// used to read the data snapshot outside the repository, so that the tests
// were skipped wherever the snapshot was missing, CI included).
func trustedRoot(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sigstore", "trusted_root-2026-11-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sigstore-trusted_root.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The PEP 740 check must always pick the same file (the first wheel of the
// index), and an attestation that cannot be downloaded must make the analysis
// incomplete instead of being reported as a failed verification. Before, the
// file was chosen in map order, so offline runs reported "provenance does not
// verify" for a random subset of packages.
func TestPyPIProvenanceDeterministicAndUnavailable(t *testing.T) {
	missing := map[string]bool{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/demo/" {
			files := []map[string]any{}
			for _, f := range []string{"demo-1.0.tar.gz", "demo-1.0-py3-none-any.whl", "demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "demo-0.9-py3-none-any.whl"} {
				files = append(files, map[string]any{"filename": f, "hashes": map[string]string{"sha256": f}, "provenance": srv.URL + "/prov/" + f})
			}
			json.NewEncoder(w).Encode(map[string]any{"name": "demo", "files": files})
			return
		}
		if missing[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unexpected request "+r.URL.Path, http.StatusTeapot)
	}))
	defer srv.Close()
	old := pypi.Index
	pypi.Index = srv.URL
	defer func() { pypi.Index = old }()

	cache := t.TempDir()
	trustedRoot(t, cache)
	if _, err := (&pypi.Client{Net: netx.New(cache, false)}).Simple(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	c := model.NewComponent(model.PyPI, "", "demo", "1.0")
	c.Meta = &model.PackageMeta{HasProvenance: true}

	// offline: the index is in the snapshot, the attestation is not
	for i := 0; i < 10; i++ {
		v := &Verifier{Net: netx.New(cache, true), Trust: &Trust{CacheDir: cache, Offline: true}, Provenance: true}
		fs, r, _ := v.checkOne(context.Background(), c)
		if r == nil || !r.Unavailable || !strings.Contains(r.Error, "demo-1.0-py3-none-any.whl") {
			t.Fatalf("run %d: result %+v, want the first wheel and unavailable", i, r)
		}
		if len(fs) != 0 {
			t.Fatalf("run %d: missing data reported as findings: %+v", i, fs[0])
		}
	}
	// online: the registry says the announced attestation does not exist
	// (not served: a warning, not a failed verification)
	missing["/prov/demo-1.0-py3-none-any.whl"] = true
	v := &Verifier{Net: netx.New(t.TempDir(), false), Trust: &Trust{CacheDir: cache, Offline: true}, Provenance: true}
	fs, r, _ := v.checkOne(context.Background(), c)
	if r == nil || r.Unavailable || !r.NotServed || len(fs) != 1 || fs[0].Rule != "provenance-unavailable" {
		t.Fatalf("missing attestation not reported: %+v %+v", r, fs)
	}
}

// An attestation that the npm metadata announces but the registry does not
// serve (seen on 25 November 2026 for trusted-publishing releases: HTTP 404, or
// HTTP 200 with the body "OK") cannot be verified, but it is no evidence of
// tampering: a warning (provenance-unavailable), not provenance-invalid, which
// fails the build. A bundle that is served and does not verify still fails, and
// a required attestation that is not served is still unsigned.
func TestNPMProvenanceNotServed(t *testing.T) {
	cache := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sigstore", "trusted_root-2026-11-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "sigstore-trusted_root.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/pkg@1.0.0":
			http.NotFound(w, r)
		case "/-/npm/v1/attestations/pkg@2.0.0":
			w.Write([]byte("OK\r\n"))
		case "/-/npm/v1/attestations/pkg@3.0.0": // only a publish attestation, no SLSA provenance
			w.Write([]byte(`{"attestations":[{"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1","bundle":{}}]}`))
		case "/-/npm/v1/attestations/pkg@4.0.0": // a provenance bundle that does not verify
			w.Write([]byte(`{"attestations":[{"predicateType":"https://slsa.dev/provenance/v1","bundle":{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}}]}`))
		default:
			http.Error(w, "unexpected request "+r.URL.Path, http.StatusTeapot)
		}
	}))
	defer srv.Close()
	old := npm.Registry
	npm.Registry = srv.URL
	defer func() { npm.Registry = old }()

	sum := sha512.Sum512([]byte("pkg"))
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	check := func(version string, expect map[string]string) ([]string, *Result) {
		v := &Verifier{Net: netx.New(t.TempDir(), false), Trust: &Trust{CacheDir: cache, Offline: true}, Provenance: true, Expect: expect}
		c := model.NewComponent(model.NPM, "", "pkg", version)
		c.Integrity, c.Meta = []string{sri}, &model.PackageMeta{HasProvenance: true}
		fs, r, _ := v.checkOne(context.Background(), c)
		var rules []string
		for _, f := range fs {
			if f.Kind == model.KindProvenance {
				rules = append(rules, f.Rule)
			}
		}
		return rules, r
	}
	for _, version := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		rules, r := check(version, nil)
		if r == nil || r.Unavailable || !r.NotServed || len(rules) != 1 || rules[0] != "provenance-unavailable" {
			t.Errorf("%s: rules %v, result %+v; want provenance-unavailable", version, rules, r)
		}
	}
	if rules, r := check("4.0.0", nil); r == nil || r.NotServed || len(rules) != 1 || rules[0] != "provenance-invalid" {
		t.Errorf("bundle that does not verify: rules %v, result %+v; want provenance-invalid", rules, r)
	}
	if rules, _ := check("1.0.0", map[string]string{"pkg": "github.com/x/pkg"}); strings.Join(rules, ",") != "unsigned-artifact,provenance-unavailable" {
		t.Errorf("required attestation not served: rules %v; want unsigned-artifact and provenance-unavailable", rules)
	}
}

// The npm hash check must compare every algorithm both sides record (a
// lockfile with only a sha1 value was not checked at all), report a download
// from outside the registry or a registry URL of another package, and say for
// every component whether the check was done and why not.
func TestNPMHashAndSource(t *testing.T) {
	tgz := []byte("qs-1.0.0 tarball")
	s512, s1 := sha512.Sum512(tgz), sha1.Sum(tgz)
	sri512 := "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
	sri1 := "sha1-" + base64.StdEncoding.EncodeToString(s1[:])
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/qs/1.0.0" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"name": "qs", "version": "1.0.0", "dist": map[string]string{
			"integrity": sri512, "shasum": hex.EncodeToString(s1[:]), "tarball": srv.URL + "/qs/-/qs-1.0.0.tgz"}})
	}))
	defer srv.Close()
	old := npm.Registry
	npm.Registry = srv.URL
	defer func() { npm.Registry = old }()

	cache := t.TempDir()
	cases := []struct {
		name, version, resolved string
		integrity               []string
		status, finding         string
	}{
		{"sha512", "1.0.0", "", []string{sri512}, HashVerified, ""},
		{"sha1 only", "1.0.0", srv.URL + "/qs/-/qs-1.0.0.tgz", []string{sri1}, HashVerified, ""},
		{"both in one value", "1.0.0", "", []string{sri512 + " " + sri1}, HashVerified, ""},
		{"wrong sha1", "1.0.0", "", []string{"sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="}, HashMismatch, "SSCA-HASH-MISMATCH"},
		{"no hash", "1.0.0", "", nil, HashNoLockfile, ""},
		{"no comparable hash", "1.0.0", "", []string{"sha256-AAAA"}, HashNoReference, ""},
		{"malformed hash", "1.0.0", "", []string{"sha512-not*base64"}, HashMismatch, "SSCA-HASH-MISMATCH"},
		{"yarn registry", "1.0.0", "https://registry.yarnpkg.com/qs/-/qs-1.0.0.tgz#" + hex.EncodeToString(s1[:]), []string{sri1}, HashVerified, ""},
		{"mirror", "1.0.0", "https://npm.mirror.example/api/npm/qs/-/qs-1.0.0.tgz", []string{sri512}, HashVerified, ""},
		{"internal registry", "1.0.0", "https://npm.acme.internal/qs/-/qs-1.0.0.tgz", []string{sri512}, HashOtherSource, ""},
		{"other host", "1.0.0", "https://evil.example/qs-1.0.0.tgz", []string{sri1}, HashOtherSource, "SSCA-LOCKFILE-SOURCE"},
		{"look-alike host", "1.0.0", "https://registry.npmjs.org.evil.example/qs/-/qs-1.0.0.tgz", []string{sri512}, HashOtherSource, "SSCA-LOCKFILE-SOURCE"},
		{"git", "1.0.0", "git+ssh://git@github.com/x/qs.git#0123456", nil, HashOtherSource, "SSCA-LOCKFILE-SOURCE"},
		{"local path", "1.0.0", "file:vendor/qs", nil, HashOtherSource, "SSCA-LOCKFILE-SOURCE"},
		{"registry URL of another package", "1.0.0", srv.URL + "/evil/-/evil-1.0.0.tgz", nil, HashNoLockfile, "SSCA-LOCKFILE-SOURCE"},
		{"unknown version", "9.9.9", "", []string{sri512}, HashNotFound, ""},
	}
	for _, tc := range cases {
		v := &Verifier{Net: netx.New(cache, false), Registries: []string{"https://npm.mirror.example/api/npm"}, Internal: "https://npm.acme.internal/"}
		c := model.NewComponent(model.NPM, "", "qs", tc.version)
		c.Resolved, c.Integrity = tc.resolved, tc.integrity
		fs, _, h := v.checkOne(context.Background(), c)
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
		if h.Status != tc.status || strings.Join(ids, ",") != tc.finding {
			t.Errorf("%s: status %s, findings %v; want %s, %q", tc.name, h.Status, ids, tc.status, tc.finding)
		}
	}
	// registry data missing from the offline snapshot: not checked, reported
	v := &Verifier{Net: netx.New(t.TempDir(), true)}
	c := model.NewComponent(model.NPM, "", "qs", "1.0.0")
	c.Integrity = []string{sri512}
	fs, _, unavailable := v.Check(context.Background(), []*model.Component{c})
	if len(fs) != 0 || c.HashCheck != HashUnavailable || unavailable[c.PURL] == "" {
		t.Errorf("offline without data: findings %v, status %s, unavailable %v", fs, c.HashCheck, unavailable)
	}
}

// The PyPI hash check must say why a component was not checked: another
// index (all 168 sentry packages were skipped without a word), no lockfile
// hash, a package unknown to PyPI, or index data that could not be fetched.
func TestPyPIHashOutcomes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/simple/demo/" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"name": "demo", "files": []map[string]any{
			{"filename": "demo-1.0-py3-none-any.whl", "hashes": map[string]string{"sha256": "aa11"}}}})
	}))
	defer srv.Close()
	old := pypi.Index
	pypi.Index = srv.URL
	defer func() { pypi.Index = old }()

	cache := t.TempDir()
	cases := []struct {
		name, pkg, version, resolved string
		integrity                    []string
		status                       string
	}{
		{"match", "demo", "1.0", "", []string{"sha256:AA11"}, HashVerified},
		{"mismatch", "demo", "1.0", "", []string{"sha256:bb22"}, HashMismatch},
		{"no hash", "demo", "1.0", "", nil, HashNoLockfile},
		{"no file of the version", "demo", "2.0", "", []string{"sha256:aa11"}, HashNoReference},
		{"other index", "demo", "1.0", "https://pypi.example.internal/simple", []string{"sha256:aa11"}, HashOtherSource},
		{"not on PyPI", "private", "1.0", "", []string{"sha256:aa11"}, HashNotFound},
	}
	for _, tc := range cases {
		v := &Verifier{Net: netx.New(cache, false)}
		c := model.NewComponent(model.PyPI, "", tc.pkg, tc.version)
		c.Resolved, c.Integrity = tc.resolved, tc.integrity
		_, _, h := v.checkOne(context.Background(), c)
		if h.Status != tc.status {
			t.Errorf("%s: status %s, want %s", tc.name, h.Status, tc.status)
		}
	}
	v := &Verifier{Net: netx.New(t.TempDir(), true)}
	c := model.NewComponent(model.PyPI, "", "demo", "1.0")
	c.Integrity = []string{"sha256:aa11"}
	if _, _, h := v.checkOne(context.Background(), c); h.Status != HashUnavailable || h.Error == "" {
		t.Errorf("offline without data: %+v", h)
	}
}

// A repository declared by a POM is a source of every dependency (Maven
// searches it before Central): outside Central it is reported unless the
// policy names it as a mirror or as the organisation's registry; plain HTTP
// is reported as critical even for Central.
func TestDeclaredRepositories(t *testing.T) {
	v := &Verifier{Registries: []string{"https://maven.aliyun.com/repository/"}, Internal: "https://nexus.acme.internal/repository/maven-public"}
	repos := []model.Repository{
		{URL: "https://repo.maven.apache.org/maven2/", DeclaredIn: "a:b:1"},
		{URL: "https://repo1.maven.org/maven2", DeclaredIn: "a:b:1"},
		{URL: "https://maven.aliyun.com/repository/public", DeclaredIn: "a:b:1"},
		{URL: "https://nexus.acme.internal/repository/maven-public/", DeclaredIn: "a:b:1"},
		{URL: "http://nexus.acme.internal/repository/maven-public", DeclaredIn: "a:b:1"},
		{URL: "http://repo1.maven.org/maven2", DeclaredIn: "a:parent:2"},
		{URL: "https://jitpack.io", Plugin: true, DeclaredIn: "a:b:1"},
		{URL: "${repo.url}", DeclaredIn: "a:b:1"},
	}
	var got []string
	for _, f := range v.Repositories("pkg:maven/a/b@1", repos) {
		if f.Kind != model.KindIntegrity || f.Component != "pkg:maven/a/b@1" {
			t.Errorf("finding %+v: want an integrity finding of the project", f)
		}
		got = append(got, f.Severity+" "+f.Evidence["url"].(string))
	}
	want := "critical http://nexus.acme.internal/repository/maven-public|critical http://repo1.maven.org/maven2|high https://jitpack.io|high ${repo.url}"
	if strings.Join(got, "|") != want {
		t.Errorf("findings %q, want %q", strings.Join(got, "|"), want)
	}
}

// The pip sources of a requirements file: --index-url replaces PyPI and is
// accepted for PyPI, a policy mirror and the organisation's index;
// --extra-index-url and --find-links add a source next to PyPI and are
// reported unless they are PyPI or a policy mirror, also for the
// organisation's index (dependency confusion); plain HTTP is critical.
func TestPythonPackageSources(t *testing.T) {
	v := &Verifier{Registries: []string{"https://mirrors.example.org/pypi/"}, Internal: "https://pkgs.acme.internal/simple"}
	repos := []model.Repository{
		{URL: "https://pypi.org/simple/", DeclaredIn: "requirements.txt", Kind: "index-url"},
		{URL: "https://mirrors.example.org/pypi/simple", DeclaredIn: "requirements.txt", Kind: "index-url"},
		{URL: "https://pkgs.acme.internal/simple", DeclaredIn: "requirements.txt", Kind: "index-url"},
		{URL: "https://evil.example/simple", DeclaredIn: "requirements.txt", Kind: "index-url"},
		{URL: "http://pypi.org/simple", DeclaredIn: "requirements.txt", Kind: "index-url"},
		{URL: "https://pypi.org/simple", DeclaredIn: "dev.txt", Kind: "extra-index-url"},
		{URL: "https://mirrors.example.org/pypi/simple", DeclaredIn: "dev.txt", Kind: "extra-index-url"},
		{URL: "https://pkgs.acme.internal/simple", DeclaredIn: "dev.txt", Kind: "extra-index-url"},
		{URL: "./wheels", DeclaredIn: "dev.txt", Kind: "find-links"},
	}
	var got []string
	for _, f := range v.Repositories("pkg:pypi/app@1", repos) {
		if f.ID != "SSCA-REPOSITORY-SOURCE" || f.Kind != model.KindIntegrity || f.Component != "pkg:pypi/app@1" {
			t.Errorf("finding %+v: want an integrity finding of the project", f)
		}
		got = append(got, f.Severity+" "+f.Evidence["option"].(string)+" "+f.Evidence["url"].(string))
	}
	want := "high --index-url https://evil.example/simple|critical --index-url http://pypi.org/simple|high --extra-index-url https://pkgs.acme.internal/simple|high --find-links ./wheels"
	if strings.Join(got, "|") != want {
		t.Errorf("findings %q, want %q", strings.Join(got, "|"), want)
	}
}

// A package that the policy requires to have provenance must not be reported
// as unsigned when the data that says whether it has an attestation is
// missing (offline snapshot without it, registry outage): before, axios was
// reported as "no provenance attestation" and the build failed with
// unsigned-artifact although its release is signed. Without metadata the
// attestation endpoint is asked directly: a 404 still means unsigned, any
// other failure leaves the provenance unchecked (incomplete analysis).
func TestRequiredProvenanceWithoutMetadata(t *testing.T) {
	cache := t.TempDir()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sigstore", "trusted_root-2026-11-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "sigstore-trusted_root.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/-/npm/v1/attestations/axios@1.0.0":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			http.NotFound(w, r) // no attestation for any other version
		}
	}))
	defer srv.Close()
	old := npm.Registry
	npm.Registry = srv.URL
	defer func() { npm.Registry = old }()

	sum := sha512.Sum512([]byte("axios"))
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	expect := map[string]string{"axios": "github.com/axios/axios"}
	check := func(offline bool, version string, meta *model.PackageMeta) ([]*model.Finding, *Result) {
		v := &Verifier{Net: netx.New(t.TempDir(), offline), Trust: &Trust{CacheDir: cache, Offline: true},
			Provenance: true, Expect: expect}
		c := model.NewComponent(model.NPM, "", "axios", version)
		c.Integrity, c.Meta = []string{sri}, meta
		fs, r, _ := v.checkOne(context.Background(), c)
		var prov []*model.Finding
		for _, f := range fs {
			if f.Kind == model.KindProvenance {
				prov = append(prov, f)
			}
		}
		return prov, r
	}
	noRegistry := &model.PackageMeta{Unavailable: []string{"npm registry: not in offline snapshot: x"}}

	// offline, registry metadata and attestation missing from the snapshot
	if fs, r := check(true, "1.0.0", noRegistry); len(fs) != 0 || r == nil || !r.Unavailable {
		t.Errorf("offline without metadata: findings %v, result %+v; want unchecked", fs, r)
	}
	// metadata not collected at all, attestation endpoint fails
	if fs, r := check(false, "1.0.0", nil); len(fs) != 0 || r == nil || !r.Unavailable {
		t.Errorf("no metadata, registry error: findings %v, result %+v; want unchecked", fs, r)
	}
	// metadata unavailable, but the registry answers that there is no attestation
	if fs, r := check(false, "1.0.1", noRegistry); len(fs) != 1 || fs[0].Rule != "unsigned-artifact" || r == nil || r.Unavailable {
		t.Errorf("no metadata, attestation 404: findings %v, result %+v; want unsigned-artifact", fs, r)
	}
	// metadata read and without attestation: unsigned, as before
	if fs, r := check(true, "1.0.0", &model.PackageMeta{}); len(fs) != 1 || fs[0].Rule != "unsigned-artifact" || r != nil {
		t.Errorf("metadata without attestation: findings %v, result %+v; want unsigned-artifact", fs, r)
	}
}

// The same for PyPI: when the package index cannot be read, a package with
// required provenance is unchecked, not unsigned.
func TestRequiredPyPIProvenanceIndexUnavailable(t *testing.T) {
	v := &Verifier{Net: netx.New(t.TempDir(), true), Provenance: true, Expect: map[string]string{"demo": "github.com/x/demo"}}
	c := model.NewComponent(model.PyPI, "", "demo", "1.0")
	fs, r, h := v.checkOne(context.Background(), c)
	if len(fs) != 0 || r == nil || !r.Unavailable || h.Status != HashUnavailable {
		t.Errorf("findings %v, result %+v, hash %s; want unchecked provenance", fs, r, h.Status)
	}
	// without a provenance requirement nothing is added
	v.Expect = nil
	if _, r, _ := v.checkOne(context.Background(), c); r != nil {
		t.Errorf("provenance result without requirement: %+v", r)
	}
}
