package maven

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// dep renders a <dependency> element; extra is inserted verbatim.
func dep(g, a, v, extra string) string {
	s := "<dependency><groupId>" + g + "</groupId><artifactId>" + a + "</artifactId>"
	if v != "" {
		s += "<version>" + v + "</version>"
	}
	return s + extra + "</dependency>"
}

func pom(g, a, v, body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>` + g + `</groupId><artifactId>` + a + `</artifactId><version>` + v + `</version>` + body + `</project>`
}

func deps(ds ...string) string { return "<dependencies>" + strings.Join(ds, "") + "</dependencies>" }

// central is a fake Maven repository with the artifacts used by the tests:
// a parent POM, a BOM, libraries with every kind of transitive dependency,
// a relocated artifact and an artifact published in several versions.
func central(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	files := map[string]string{}
	add := func(g, a, v, body string) {
		files[strings.ReplaceAll(g, ".", "/")+"/"+a+"/"+v+"/"+a+"-"+v+".pom"] = pom(g, a, v, body)
	}
	add("org.example", "parent", "1.0", `<packaging>pom</packaging>
<properties><commons.version>3.0</commons.version></properties>
<licenses><license><name>Apache-2.0</name></license></licenses>
<dependencyManagement>`+deps(dep("org.apache.commons", "commons-lang3", "${commons.version}", ""))+`</dependencyManagement>`+
		deps(dep("org.example", "inherited-lib", "1.0", "")))
	add("org.example", "bom", "1.0", `<packaging>pom</packaging>
<properties><log4j2.version>2.17.1</log4j2.version></properties>
<dependencyManagement>`+deps(dep("org.apache.logging.log4j", "log4j-core", "${log4j2.version}", ""))+`</dependencyManagement>`)
	add("org.example", "starter", "1.0", deps(
		dep("org.apache.logging.log4j", "log4j-core", "2.14.1", ""),
		dep("org.example", "common", "2.0", ""),
		dep("com.example", "excluded", "1.0", ""),
		dep("org.example", "test-only", "1.0", "<scope>test</scope>"),
		dep("org.example", "provided-only", "1.0", "<scope>provided</scope>"),
		dep("org.example", "optional-only", "1.0", "<optional>true</optional>"),
	))
	for _, v := range []string{"2.14.1", "2.17.1"} {
		add("org.apache.logging.log4j", "log4j-core", v, deps(dep("org.apache.logging.log4j", "log4j-api", v, "")))
		add("org.apache.logging.log4j", "log4j-api", v, "")
	}
	for _, v := range []string{"3.0", "3.12.0"} {
		add("org.apache.commons", "commons-lang3", v, "")
	}
	for _, a := range []string{"inherited-lib", "excluded-child", "test-only", "provided-only", "optional-only", "profile-dep", "reloc-child", "test-lib"} {
		add("org.example", a, "1.0", "")
	}
	add("com.example", "excluded", "1.0", deps(dep("org.example", "excluded-child", "1.0", "")))
	add("org.example", "common", "1.0", "")
	add("org.example", "common", "2.0", "")
	add("org.example", "wrapper", "1.0", deps(dep("org.example", "starter", "1.0", "")))
	add("org.example", "undef-lib", "1.0", deps(
		dep("org.example", "common", "${undefined.version}", ""),
		dep("org.example", "inherited-lib", "1.0", ""),
	))
	add("org.example", "relocated-old", "1.0", `<distributionManagement><relocation><artifactId>relocated-new</artifactId></relocation></distributionManagement>`)
	add("org.example", "relocated-new", "1.0", deps(dep("org.example", "reloc-child", "1.0", "")))
	for _, v := range []string{"1.0", "1.5", "2.0"} {
		add("org.example", "ranged", v, "")
	}
	files["org/example/ranged/maven-metadata.xml"] = `<metadata><versioning><versions>
<version>2.0</version><version>1.0</version><version>1.5</version></versions></versioning></metadata>`

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]; ok {
			fmt.Fprint(w, b)
			return
		}
		http.NotFound(w, r)
	}))
	old := Central
	Central = srv.URL
	t.Cleanup(func() { Central = old; srv.Close() })
	return srv, &requests
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// project is a single-module project that uses every feature of the effective
// POM that the resolver supports.
const project = `<?xml version="1.0"?>
<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>
<artifactId>app</artifactId><version>${revision}</version>
<properties><revision>2.3.0</revision><commons.version>3.12.0</commons.version></properties>
<dependencyManagement><dependencies>
  <dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement>
<dependencies>
  <dependency><groupId>org.example</groupId><artifactId>starter</artifactId><version>1.0</version>
    <exclusions><exclusion><groupId>com.example</groupId><artifactId>excluded</artifactId></exclusion></exclusions></dependency>
  <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId></dependency>
  <dependency><groupId>org.example</groupId><artifactId>common</artifactId><version>1.0</version></dependency>
  <dependency><groupId>org.example</groupId><artifactId>relocated-old</artifactId><version>1.0</version></dependency>
  <dependency><groupId>org.example</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency>
  <dependency><groupId>org.example</groupId><artifactId>test-lib</artifactId><version>1.0</version><scope>test</scope></dependency>
  <dependency><groupId>org.example</groupId><artifactId>war-dep</artifactId><version>1.0</version><type>war</type></dependency>
</dependencies>
<profiles><profile><id>default</id><activation><activeByDefault>true</activeByDefault></activation>
  <dependencies><dependency><groupId>org.example</groupId><artifactId>profile-dep</artifactId><version>1.0</version></dependency></dependencies>
</profile><profile><id>off</id>
  <dependencies><dependency><groupId>org.example</groupId><artifactId>inactive-dep</artifactId><version>1.0</version></dependency></dependencies>
</profile></profiles>
</project>`

func load(t *testing.T, dir string, dev bool) *model.Graph {
	t.Helper()
	g, err := Plugin{}.Load(context.Background(), dir, common.Options{Net: netx.New(t.TempDir(), false), IncludeDev: dev})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func versions(g *model.Graph) map[string]string {
	out := map[string]string{}
	for _, c := range g.Components() {
		out[c.FullName()] = c.Version
	}
	return out
}

func TestResolveProject(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), project)
	g := load(t, dir, false)
	if g.Root != "pkg:maven/org.example/app@2.3.0" {
		t.Errorf("root %s (groupId inherited from the parent, version from a property)", g.Root)
	}
	want := map[string]string{
		"org.example:starter":                 "1.0",
		"org.example:inherited-lib":           "1.0",    // dependency inherited from the parent
		"org.apache.commons:commons-lang3":    "3.12.0", // inherited management, child property wins
		"org.apache.logging.log4j:log4j-core": "2.17.1", // transitive version managed by the imported BOM
		"org.apache.logging.log4j:log4j-api":  "2.17.1", // follows the managed log4j-core
		"org.example:common":                  "1.0",    // nearest definition wins over starter's 2.0
		"org.example:relocated-old":           "1.0",
		"org.example:reloc-child":             "1.0", // dependencies of the relocation target
		"org.example:ranged":                  "1.5", // highest version inside [1.0,2.0)
		"org.example:profile-dep":             "1.0", // activeByDefault profile
	}
	got := versions(g)
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: got %q, want %q", n, got[n], v)
		}
	}
	for n := range got {
		if _, ok := want[n]; !ok {
			// excluded subtree, test/provided/optional transitive dependencies,
			// the test-scoped direct dependency, the war and the inactive profile
			t.Errorf("unexpected component %s@%s", n, got[n])
		}
	}
	if ev := g.Nodes["pkg:maven/org.example/common@1.0"].Evicted; len(ev) != 1 || ev[0] != "2.0" {
		t.Errorf("evicted versions of common: %v", ev)
	}
	if c := g.Nodes["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"]; c.Depth != 2 || c.Scope != model.ScopeRuntime {
		t.Errorf("log4j-core depth %d scope %s", c.Depth, c.Scope)
	}
	if len(g.Incomplete) != 0 || len(g.Conflicts) != 0 {
		t.Errorf("incomplete %v conflicts %v", g.Incomplete, g.Conflicts)
	}

	gd := load(t, dir, true)
	dev := versions(gd)
	if dev["org.example:test-lib"] != "1.0" {
		t.Errorf("test-scoped direct dependency missing with IncludeDev")
	} else if c := gd.Nodes["pkg:maven/org.example/test-lib@1.0"]; c.Scope != model.ScopeTest || !c.Direct {
		t.Errorf("test-lib scope %s direct %v, want a direct test dependency", c.Scope, c.Direct)
	}
	for n, v := range want { // the runtime part of the full graph is unchanged
		if dev[n] != v {
			t.Errorf("full graph: %s@%s, want %s", n, dev[n], v)
		}
	}
	if _, ok := dev["org.example:test-only"]; ok {
		t.Errorf("test dependency of a dependency is never transitive")
	}
}

func TestEffectivePOM(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), project)
	p, err := ReadLocal(filepath.Join(dir, "pom.xml"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewRepo(netx.New(t.TempDir(), false)).EffectiveLocal(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if e.GroupID != "org.example" || e.Version != "2.3.0" || e.Packaging != "jar" {
		t.Errorf("coordinates %s:%s:%s %s", e.GroupID, e.ArtifactID, e.Version, e.Packaging)
	}
	if len(e.Licenses) != 1 || e.Licenses[0] != "Apache-2.0" {
		t.Errorf("licence not inherited: %v", e.Licenses)
	}
	managed := map[string]string{}
	for _, m := range e.Managed {
		managed[m.GroupID+":"+m.ArtifactID] = m.Version
	}
	if managed["org.apache.logging.log4j:log4j-core"] != "2.17.1" || managed["org.apache.commons:commons-lang3"] != "3.12.0" {
		t.Errorf("managed versions %v", managed)
	}
	if _, ok := managed["org.example:bom"]; ok {
		t.Errorf("the import entry itself must be replaced by the BOM")
	}
	if len(e.Problems) != 0 {
		t.Errorf("problems %v", e.Problems)
	}
}

// A missing parent or BOM is a problem of the analysis, never silently ignored.
func TestMissingParentAndBOM(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project>
<parent><groupId>org.example</groupId><artifactId>gone</artifactId><version>9</version><relativePath/></parent>
<artifactId>app</artifactId>
<dependencyManagement><dependencies>
  <dependency><groupId>org.example</groupId><artifactId>gone-bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>
</dependencies></dependencyManagement>
<dependencies><dependency><groupId>org.example</groupId><artifactId>ranged</artifactId></dependency></dependencies>
</project>`)
	g := load(t, dir, false)
	text := strings.Join(g.Incomplete, "\n")
	for _, want := range []string{"parent", "BOM org.example:gone-bom"} {
		if !strings.Contains(text, want) {
			t.Errorf("incomplete does not mention %q: %v", want, g.Incomplete)
		}
	}
	if len(g.Components()) != 0 {
		t.Errorf("a dependency without a version must not be guessed: %v", versions(g))
	}
}

// Multi-module reactor: modules are resolved one by one, a sibling module is not
// a third-party component, and the local parent (relativePath) supplies
// properties and management.
func TestReactor(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), pom("com.acme", "root", "1.0", `<packaging>pom</packaging>
<modules><module>core</module><module>web</module></modules>
<properties><lang.version>3.0</lang.version></properties>
<dependencyManagement>`+deps(dep("org.apache.commons", "commons-lang3", "${lang.version}", ""))+`</dependencyManagement>`))
	module := func(name, body string) string {
		return `<project><parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0</version></parent>
<artifactId>` + name + `</artifactId>` + body + `</project>`
	}
	writeFile(t, filepath.Join(dir, "core", "pom.xml"), module("core", deps(dep("org.apache.commons", "commons-lang3", "", ""))))
	writeFile(t, filepath.Join(dir, "web", "pom.xml"), module("web", deps(
		dep("com.acme", "core", "${project.version}", ""),
		dep("org.example", "profile-dep", "1.0", ""))))
	g := load(t, dir, false)
	got := versions(g)
	want := map[string]string{"org.apache.commons:commons-lang3": "3.0", "org.example:profile-dep": "1.0"}
	if len(got) != len(want) {
		t.Errorf("components %v, want %v", got, want)
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: got %q, want %q", n, got[n], v)
		}
	}
	if g.Root != "pkg:maven/com.acme/root@1.0" {
		t.Errorf("root %s", g.Root)
	}
}

// A sibling module takes part in the nearest-wins mediation of the module
// that depends on it, as in Maven's reactor: web reaches common 1.0 through
// core (depth 2) and common 2.0 through wrapper -> starter (depth 3), so
// Maven puts only common 1.0 on the classpath of web. The sibling itself is
// not a component, and its dependencies keep their scope.
func TestReactorSiblingMediation(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), pom("com.acme", "root", "1.0", `<packaging>pom</packaging>
<modules><module>core</module><module>web</module></modules>`))
	module := func(name, body string) string {
		return `<project><parent><groupId>com.acme</groupId><artifactId>root</artifactId><version>1.0</version></parent>
<artifactId>` + name + `</artifactId>` + body + `</project>`
	}
	writeFile(t, filepath.Join(dir, "core", "pom.xml"), module("core", deps(
		dep("org.example", "common", "1.0", ""),
		dep("org.example", "provided-only", "1.0", "<scope>provided</scope>"))))
	writeFile(t, filepath.Join(dir, "web", "pom.xml"), module("web", deps(
		dep("com.acme", "core", "${project.version}", ""),
		dep("org.example", "wrapper", "1.0", ""))))
	g := load(t, dir, false)
	var common []string
	for _, c := range g.Components() {
		switch {
		case c.Namespace == "com.acme":
			t.Errorf("reactor module %s reported as a component", c.PURL)
		case c.FullName() == "org.example:common":
			common = append(common, c.Version)
			if c.Scope != model.ScopeRuntime {
				t.Errorf("common: scope %s", c.Scope)
			}
		case c.FullName() == "org.example:provided-only" && c.Scope != model.ScopeProvided:
			t.Errorf("provided-only: scope %s, want provided", c.Scope)
		}
	}
	if len(common) != 1 || common[0] != "1.0" {
		t.Errorf("common versions %v, want [1.0] (nearest through the sibling module)", common)
	}
	for _, es := range g.Out {
		for _, e := range es {
			if g.Nodes[e.From] == nil || g.Nodes[e.To] == nil {
				t.Errorf("dangling edge %s -> %s", e.From, e.To)
			}
		}
	}
}

func TestInterpolate(t *testing.T) {
	p := map[string]string{"a": "${b}", "b": "1.${c}", "c": "2", "self": "${self}"}
	for in, want := range map[string]string{
		"${a}":       "1.2", // nested
		" ${c}.0 ":   "2.0",
		"${unknown}": "${unknown}", // unknown properties are kept for the caller to detect
		"${self}":    "${self}",    // self reference terminates
		"plain":      "plain",
		"${a}-${c}":  "1.2-2",
	} {
		if got := interpolate(in, p); got != want {
			t.Errorf("interpolate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersionRanges(t *testing.T) {
	for _, c := range []struct {
		v, spec string
		want    bool
	}{
		{"1.5", "[1.0,2.0)", true},
		{"2.0", "[1.0,2.0)", false},
		{"1.0", "(1.0,2.0]", false},
		{"2.0", "(1.0,2.0]", true},
		{"0.1", "(,1.0]", true},
		{"3.0", "[2.0,)", true},
		{"1.2", "[1.2]", true},
		{"1.3", "[1.2]", false},
		{"1.6", "(,1.0],[1.5,)", true},
		{"1.2", "(,1.0],[1.5,)", false},
		{"1.0", "1.0", true}, // soft requirement: only the version itself
		{"1.1", "1.0", false},
		{"9", "", true},
	} {
		if got := Satisfies(c.v, c.spec); got != c.want {
			t.Errorf("Satisfies(%q, %q) = %v", c.v, c.spec, got)
		}
	}
	vs := []string{"1.0-SNAPSHOT", "1.0", "1.0-alpha-1", "1.0.1", "1.0-rc1", "1.0-beta"}
	sort.Slice(vs, func(i, j int) bool { return Compare(vs[i], vs[j]) < 0 })
	if want := "1.0-alpha-1 1.0-beta 1.0-rc1 1.0-SNAPSHOT 1.0 1.0.1"; strings.Join(vs, " ") != want {
		t.Errorf("order %v, want %s", vs, want)
	}
	s := &source{}
	for spec, want := range map[string]string{"1.0": "1.0", "[1.2]": "1.2", "[1.0,2.0)": "", "${x}": "${x}"} {
		if got, _ := s.Pinned(spec); got != want {
			t.Errorf("Pinned(%q) = %q, want %q", spec, got, want)
		}
	}
}

// POMs are fetched once per coordinate even when many paths lead to them.
func TestPOMCache(t *testing.T) {
	_, requests := central(t)
	r := NewRepo(netx.New(t.TempDir(), false))
	for i := 0; i < 5; i++ {
		if _, err := r.Effective(context.Background(), "org.example", "starter", "1.0"); err != nil {
			t.Fatal(err)
		}
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("%d requests for one POM", n)
	}
	if _, err := r.Effective(context.Background(), "org.example", "missing", "1.0"); err == nil {
		t.Error("missing POM accepted")
	}
}

// A dependency declared twice in one POM: Maven keeps the last declaration
// (model normaliser). A dependency without a version is rejected by Maven;
// ssca must not resolve it to some version, and a range that cannot be
// resolved leaves the analysis incomplete.
func TestDuplicateMissingVersionAndUnresolvedRange(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), pom("x", "app", "1", deps(
		dep("org.apache.logging.log4j", "log4j-core", "2.14.1", ""),
		dep("org.apache.logging.log4j", "log4j-core", "2.17.1", ""),
		dep("org.example", "common", "", ""),
		dep("org.example", "unknown", "[1.0,2.0)", ""),
	)))
	g := load(t, dir, false)
	if v := versions(g)["org.apache.logging.log4j:log4j-core"]; v != "2.17.1" {
		t.Errorf("duplicate declaration: log4j-core %s, want the last one (2.17.1)", v)
	}
	if _, ok := versions(g)["org.example:common"]; ok {
		t.Error("dependency without a version was resolved")
	}
	inc := strings.Join(g.Incomplete, "\n")
	for _, w := range []string{"org.example:common has no", "org.example:unknown"} {
		if !strings.Contains(inc, w) {
			t.Errorf("incomplete does not mention %q: %v", w, g.Incomplete)
		}
	}
}

// The repositories and plugin repositories that the POMs declare (also in a
// parent, also through a property) are recorded with the POM that declares
// them, for M3. ssca itself does not download over plain HTTP: the module
// that only a plain-HTTP repository has stays unresolved.
func TestDeclaredRepositories(t *testing.T) {
	central(t)
	var plain atomic.Int64
	http1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(http1.Close)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion>
<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1.0</version><relativePath/></parent>
<artifactId>app</artifactId><version>1.0</version>
<properties><repo.url>https://repo.example.org/maven</repo.url></properties>
<repositories>
  <repository><id>plain</id><url>`+http1.URL+`</url></repository>
  <repository><id>prop</id><url>${repo.url}</url></repository>
</repositories>
<pluginRepositories><pluginRepository><id>jitpack</id><url>https://jitpack.io</url></pluginRepository></pluginRepositories>
`+deps(dep("org.example", "only-elsewhere", "1.0", ""))+`</project>`)
	g := load(t, dir, false)
	var got []string
	for _, r := range g.Repositories {
		got = append(got, fmt.Sprintf("%s plugin=%v in=%s", r.URL, r.Plugin, r.DeclaredIn))
	}
	want := []string{
		http1.URL + " plugin=false in=org.example:app:1.0",
		"https://repo.example.org/maven plugin=false in=org.example:app:1.0",
		"https://jitpack.io plugin=true in=org.example:app:1.0",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("repositories:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if n := plain.Load(); n != 0 {
		t.Errorf("%d requests to the plain-HTTP repository, want none", n)
	}
}

// A dependency of the project whose version uses a property that no POM
// defines makes the analysis incomplete (Maven stops: "must be a valid
// version"); in the POM of a dependency, Maven only warns, so such a
// dependency is left out and listed in a note, while the valid ones stay.
func TestUndefinedProperty(t *testing.T) {
	central(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pom.xml"), pom("x", "app", "1", deps(
		dep("org.apache.logging.log4j", "log4j-core", "${missing.prop}", ""),
		dep("org.example", "undef-lib", "1.0", ""),
	)))
	g := load(t, dir, false)
	if _, ok := versions(g)["org.apache.logging.log4j:log4j-core"]; ok {
		t.Error("dependency with an undefined version property was resolved")
	}
	inc := strings.Join(g.Incomplete, "\n")
	if !strings.Contains(inc, "org.apache.logging.log4j:log4j-core:${missing.prop} uses an undefined property") {
		t.Errorf("incomplete %q does not report the undefined property", inc)
	}
	v := versions(g)
	if v["org.example:undef-lib"] != "1.0" || v["org.example:inherited-lib"] != "1.0" {
		t.Errorf("valid dependencies missing: %v", v)
	}
	if _, ok := v["org.example:common"]; ok {
		t.Error("transitive dependency with an undefined property was resolved")
	}
	if strings.Contains(inc, "undef-lib") {
		t.Errorf("a dependency POM with an undefined property made the analysis incomplete: %q", inc)
	}
	notes := strings.Join(g.Notes, "\n")
	if !strings.Contains(notes, "org.example:undef-lib:1.0 declares org.example:common:${undefined.version}") {
		t.Errorf("notes %q do not list the left-out dependency", notes)
	}
}
