// Package pypi is the PyPI ecosystem plugin: requirements files, poetry.lock,
// uv.lock and Pipfile.lock parsers, PEP 440/508 semantics, the PyPI JSON and
// Simple APIs and resolution with bounded re-selection (Algorithm 3.1).
package pypi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	pep440 "github.com/aquasecurity/go-pep440-version"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/resolve"
)

// Index is the base URL of the package index.
var Index = "https://pypi.org"

// Plugin implements common.Plugin for PyPI.
type Plugin struct{}

func (Plugin) Name() string { return model.PyPI }

var reqFiles = []string{"requirements.txt", "requirements/base.txt", "requirements/prod.txt", "requirements/production.txt", "requirements/common.txt"}

// devReqFiles are the usual names of requirement files for development and
// test environments; they are read next to the runtime requirements, and
// their packages take the development or test scope unless runtime code
// needs them too.
var devReqFiles = []struct {
	file  string
	scope model.Scope
}{
	{"requirements-dev.txt", model.ScopeDev}, {"requirements_dev.txt", model.ScopeDev}, {"dev-requirements.txt", model.ScopeDev},
	{"requirements/dev.txt", model.ScopeDev}, {"requirements/development.txt", model.ScopeDev}, {"requirements/local.txt", model.ScopeDev},
	{"requirements-docs.txt", model.ScopeDev}, {"requirements/docs.txt", model.ScopeDev}, {"docs/requirements.txt", model.ScopeDev},
	{"requirements-test.txt", model.ScopeTest}, {"requirements_test.txt", model.ScopeTest}, {"test-requirements.txt", model.ScopeTest},
	{"requirements-tests.txt", model.ScopeTest}, {"requirements/test.txt", model.ScopeTest}, {"requirements/tests.txt", model.ScopeTest},
	{"requirements/testing.txt", model.ScopeTest},
}

func (Plugin) Detect(dir string) []string {
	var out []string
	for _, f := range append([]string{"poetry.lock", "uv.lock", "Pipfile.lock", "pyproject.toml"}, reqFiles...) {
		if common.Exists(dir, f) {
			out = append(out, f)
		}
	}
	return out
}

var normRe = regexp.MustCompile(`[-_.]+`)

// Normalise applies the PEP 503 name normalisation.
func Normalise(n string) string {
	return strings.ToLower(normRe.ReplaceAllString(strings.TrimSpace(n), "-"))
}

// Compare orders PEP 440 versions.
func Compare(a, b string) int {
	va, ea := pep440.Parse(a)
	vb, eb := pep440.Parse(b)
	if ea != nil || eb != nil {
		return strings.Compare(a, b)
	}
	return va.Compare(vb)
}

// Satisfies checks a version against a PEP 440 specifier set.
func Satisfies(v, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		pv, err := pep440.Parse(v)
		return err == nil && !pv.IsPreRelease()
	}
	ss, err := pep440.NewSpecifiers(spec)
	if err != nil {
		return false
	}
	pv, err := pep440.Parse(v)
	if err != nil {
		return false
	}
	return ss.Check(pv)
}

func comp(name, version string) *model.Component {
	return model.NewComponent(model.PyPI, "", Normalise(name), version)
}

// Requirement is a parsed PEP 508 requirement.
type Requirement struct {
	Name   string
	Extras []string
	Spec   string
	Marker string
	Hashes []string
	URL    bool
}

var reqRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(\(?[^;@]*\)?)?\s*(@[^;]*)?\s*(;.*)?$`)

// ParseRequirement parses "name[extra]>=1.0; marker".
func ParseRequirement(s string) (Requirement, bool) {
	m := reqRe.FindStringSubmatch(s)
	if m == nil {
		return Requirement{}, false
	}
	r := Requirement{Name: Normalise(m[1])}
	if m[2] != "" {
		for _, e := range strings.Split(strings.Trim(m[2], "[]"), ",") {
			if e = strings.TrimSpace(e); e != "" {
				r.Extras = append(r.Extras, e)
			}
		}
	}
	r.Spec = strings.ReplaceAll(strings.Trim(strings.TrimSpace(m[3]), "()"), " ", "")
	r.URL = m[4] != ""
	if m[5] != "" {
		r.Marker = strings.TrimSpace(m[5][1:])
	}
	return r, true
}

// validSpec reports whether spec is empty or a PEP 440 specifier set. A
// malformed requirement ("foo ===== 1", "pkg[extra" without "]") must not be
// read as some other requirement or dropped without a message.
func validSpec(spec string) bool {
	if spec == "" || spec == "*" {
		return true
	}
	_, err := pep440.NewSpecifiers(spec)
	return err == nil
}

// ---------------------------------------------------------------- requirements.txt

type reqLine struct {
	Requirement
	via        []string
	constraint bool // from a constraints file (-c): limits versions, adds nothing
}

// readRequirements parses a requirements file and the files it includes.
// skipped lists the requirements that cannot be analysed (editable
// installs, VCS and URL requirements, local paths, unreadable includes).
//
// The options that change where pip downloads from (--index-url,
// --extra-index-url, --find-links) are added to idx for M3: ssca resolves the
// requirements against PyPI, pip would use these sources.
func readRequirements(file string, seen map[string]bool, idx *[]model.Repository) (out []reqLine, skipped []string, err error) {
	if seen[file] {
		return nil, nil, nil
	}
	seen[file] = true
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var cur *reqLine
	inVia := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	var cont string
	for sc.Scan() {
		raw := sc.Text()
		t := strings.TrimSpace(raw)
		// pip-compile "# via" annotations give the parents of a requirement
		if strings.HasPrefix(t, "#") {
			c := strings.TrimSpace(strings.TrimPrefix(t, "#"))
			if cur != nil && strings.HasPrefix(c, "via") {
				inVia = true
				c = strings.TrimSpace(strings.TrimPrefix(c, "via"))
			}
			if cur != nil && inVia && c != "" {
				cur.via = append(cur.via, c)
			}
			continue
		}
		inVia = false
		if strings.HasSuffix(t, "\\") {
			cont += strings.TrimSuffix(t, "\\") + " "
			continue
		}
		t = cont + t
		cont = ""
		if i := strings.Index(t, " #"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		if inc, constraint, ok := includeOf(t); ok {
			sub, skip, err := readRequirements(filepath.Join(filepath.Dir(file), inc), seen, idx)
			if err != nil {
				skipped = append(skipped, t+" (cannot be read)")
				continue
			}
			for _, l := range sub {
				l.constraint = l.constraint || constraint
				out = append(out, l)
			}
			skipped = append(skipped, skip...)
			continue
		}
		if strings.HasPrefix(t, "-e") || strings.HasPrefix(t, "--editable") {
			skipped = append(skipped, t)
			continue
		}
		if strings.HasPrefix(t, "-") {
			if kind, u, ok := indexOption(t); ok && idx != nil {
				*idx = append(*idx, model.Repository{URL: u, DeclaredIn: filepath.Base(file), Kind: kind})
			}
			continue // index and install options
		}
		var hashes []string
		parts := strings.Fields(t)
		var keep []string
		for _, p := range parts {
			if strings.HasPrefix(p, "--hash=") {
				hashes = append(hashes, strings.TrimPrefix(p, "--hash="))
			} else if !strings.HasPrefix(p, "--") {
				keep = append(keep, p)
			}
		}
		line := strings.Join(keep, " ")
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		name, _, _ := strings.Cut(line, ";")
		r, ok := ParseRequirement(line)
		if !ok || r.URL || strings.Contains(line, "://") || strings.ContainsAny(name, `/\`) || !validSpec(r.Spec) {
			skipped = append(skipped, line) // VCS or URL requirement, local path, malformed line
			continue
		}
		r.Hashes = hashes
		out = append(out, reqLine{Requirement: r})
		cur = &out[len(out)-1]
	}
	return out, skipped, sc.Err()
}

// indexOption recognises "--index-url URL", "-i URL", "--extra-index-url URL"
// and "--find-links URL" / "-f URL" (also with "=" or, for the short forms,
// attached).
func indexOption(t string) (kind, u string, ok bool) {
	for _, o := range []struct{ opt, kind string }{
		{"--index-url", "index-url"}, {"--extra-index-url", "extra-index-url"}, {"--find-links", "find-links"},
		{"-i", "index-url"}, {"-f", "find-links"},
	} {
		rest, found := strings.CutPrefix(t, o.opt)
		if !found || strings.HasPrefix(o.opt, "--") && rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '=' {
			continue
		}
		if f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(rest), "=")); len(f) > 0 {
			return o.kind, f[0], true
		}
	}
	return "", "", false
}

// includeOf recognises "-r file", "--requirement=file", "-c file" and
// "--constraint file".
func includeOf(t string) (file string, constraint bool, ok bool) {
	for _, p := range []struct {
		opt        string
		constraint bool
	}{{"--requirement", false}, {"--constraint", true}, {"-r", false}, {"-c", true}} {
		if rest, found := strings.CutPrefix(t, p.opt); found && (rest == "" || rest[0] == ' ' || rest[0] == '=' || p.opt[1] != '-') {
			rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), "="))
			if rest != "" {
				return rest, p.constraint, true
			}
		}
	}
	return "", false, false
}

func pinned(spec string) (string, bool) {
	if strings.HasPrefix(spec, "==") && !strings.ContainsAny(spec, ",*") {
		return strings.TrimPrefix(strings.TrimPrefix(spec, "=="), "="), true
	}
	return "", false
}

// ---------------------------------------------------------------- Load

// projectIdentity returns the name and version declared in pyproject.toml
// ([project] or [tool.poetry]); without them the directory name and 0.0.0.
func projectIdentity(dir string) (string, string) {
	var pp struct {
		Project struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	name, version := common.DirName(dir), "0.0.0"
	if common.Exists(dir, "pyproject.toml") {
		if _, err := toml.DecodeFile(filepath.Join(dir, "pyproject.toml"), &pp); err == nil {
			for _, n := range []string{pp.Project.Name, pp.Tool.Poetry.Name} {
				if n != "" {
					name = n
					break
				}
			}
			for _, v := range []string{pp.Project.Version, pp.Tool.Poetry.Version} {
				if v != "" {
					version = v
					break
				}
			}
		}
	}
	return name, version
}

func (p Plugin) Load(ctx context.Context, dir string, opt common.Options) (*model.Graph, error) {
	name, version := projectIdentity(dir)
	root := model.NewComponent(model.PyPI, "", Normalise(name), version)
	root.Source = "project"
	if !opt.ForceResolve {
		switch {
		case common.Exists(dir, "poetry.lock"):
			return loadPoetry(dir, root, opt)
		case common.Exists(dir, "uv.lock"):
			return loadUV(dir, root, opt)
		case common.Exists(dir, "Pipfile.lock"):
			return loadPipfile(ctx, dir, root, opt)
		}
	}
	var lines, constraints []reqLine
	var skipped []string
	var input string
	runtimeSeen := map[string]bool{} // runtime files, also when a dev file includes them
	var repos []model.Repository
	for _, f := range reqFiles {
		if common.Exists(dir, f) {
			l, skip, err := readRequirements(filepath.Join(dir, f), runtimeSeen, &repos)
			if err != nil {
				return nil, err
			}
			for _, x := range l {
				if x.constraint {
					constraints = append(constraints, x)
				} else {
					lines = append(lines, x)
				}
			}
			skipped, input = skip, f
			break
		}
	}
	if input == "" && common.Exists(dir, "pyproject.toml") {
		l, skip, err := pyprojectDeps(filepath.Join(dir, "pyproject.toml"))
		if err != nil {
			return nil, err
		}
		lines, skipped, input = l, skip, "pyproject.toml"
	}
	if input == "" {
		return nil, fmt.Errorf("no supported Python project file")
	}
	if opt.Net == nil {
		return nil, fmt.Errorf("Python graph resolution needs network access")
	}
	src := newSource(opt.Net)
	src.locked = map[string]string{}
	src.constraints = map[string][]string{}
	for _, c := range constraints {
		if c.Spec != "" {
			src.constraints[c.Name] = append(src.constraints[c.Name], c.Spec)
		}
	}
	// A fully pinned file (pip freeze / pip-compile) fixes the versions:
	// only the edges are taken from registry metadata.
	allPinned := len(lines) > 0
	for _, l := range lines {
		v, ok := pinned(l.Spec)
		if !ok {
			allPinned = false
		}
		src.locked[l.Name] = v
	}
	var deps []resolve.Dep
	viaKnown := false
	for _, l := range lines {
		if len(l.via) > 0 {
			viaKnown = true
		}
	}
	for _, l := range lines {
		if viaKnown && !isDirectVia(l.via) {
			continue
		}
		deps = append(deps, resolve.Dep{Name: l.Name, Range: l.Spec, Marker: l.Marker, Extras: l.Extras, Scope: model.ScopeRuntime})
	}
	src.closed = allPinned
	g, err := resolve.Resolve(ctx, src, root, deps, opt.MaxRounds)
	if err != nil {
		return nil, err
	}
	g.Inputs = []string{input}
	g.Repositories = append(g.Repositories, repos...)
	for _, s := range skipped {
		g.Incomplete = append(g.Incomplete, input+": requirement not analysed: "+s)
	}
	hashes := map[string][]string{}
	for _, l := range lines {
		hashes[l.Name] = l.Hashes
	}
	for _, c := range g.Components() {
		if h := hashes[c.Name]; len(h) > 0 {
			c.Integrity = h
		}
		c.Source = input
		if src.closed {
			if _, ok := src.locked[c.Name]; !ok {
				c.Source = "resolver"
			}
		}
	}
	if opt.IncludeDev {
		if err := addDevRequirements(ctx, dir, g, root, src.constraints, runtimeSeen, opt); err != nil {
			return nil, err
		}
	}
	return g, nil
}

// addDevRequirements resolves the development and test requirement files
// (devReqFiles) and adds their packages to the runtime graph g. They are
// resolved separately, with the versions of the runtime graph fixed, so that
// the production part of the graph is the same as without them (as in a
// production install of the runtime requirements only) and a package shared
// with runtime code keeps its runtime version and scope. Runtime files that
// a dev file includes ("-r requirements.txt") are not read again, and an
// editable install of the project itself ("-e .") is not a dependency.
func addDevRequirements(ctx context.Context, dir string, g *model.Graph, root *model.Component, constraints map[string][]string, runtimeSeen map[string]bool, opt common.Options) error {
	type devLine struct {
		reqLine
		scope model.Scope
		file  string
	}
	var lines []devLine
	var skipped, inputs []string
	cons := map[string][]string{}
	for n, c := range constraints {
		cons[n] = append([]string(nil), c...)
	}
	for _, df := range devReqFiles {
		if !common.Exists(dir, df.file) {
			continue
		}
		seen := map[string]bool{}
		for f := range runtimeSeen {
			seen[f] = true
		}
		l, skip, err := readRequirements(filepath.Join(dir, df.file), seen, &g.Repositories)
		if err != nil {
			return err
		}
		inputs = append(inputs, df.file)
		for _, x := range l {
			if x.constraint {
				if x.Spec != "" {
					cons[x.Name] = append(cons[x.Name], x.Spec)
				}
				continue
			}
			lines = append(lines, devLine{x, df.scope, df.file})
		}
		for _, sk := range skip {
			if !selfReference(sk) {
				skipped = append(skipped, df.file+": requirement not analysed: "+sk)
			}
		}
	}
	if len(inputs) == 0 {
		return nil
	}
	g.Inputs = append(g.Inputs, inputs...)
	g.Incomplete = append(g.Incomplete, skipped...)
	if len(lines) == 0 {
		return nil
	}
	src := newSource(opt.Net)
	src.locked, src.constraints = map[string]string{}, cons
	runtime := map[string]bool{}
	for _, c := range g.Components() {
		src.locked[c.Name] = c.Version
		runtime[c.Name] = true
	}
	allPinned, viaKnown := true, false
	for _, l := range lines {
		v, ok := pinned(l.Spec)
		if !ok {
			allPinned = false
		}
		if !runtime[l.Name] {
			src.locked[l.Name] = v
		}
		viaKnown = viaKnown || len(l.via) > 0
	}
	var deps []resolve.Dep
	hashes, files := map[string][]string{}, map[string]string{}
	for _, l := range lines {
		if len(l.Hashes) > 0 {
			hashes[l.Name] = l.Hashes
		}
		if _, ok := files[l.Name]; !ok {
			files[l.Name] = l.file
		}
		if viaKnown && !isDirectVia(l.via) {
			continue
		}
		deps = append(deps, resolve.Dep{Name: l.Name, Range: l.Spec, Marker: l.Marker, Extras: l.Extras, Scope: l.scope})
	}
	src.closed = allPinned
	devRoot := model.NewComponent(model.PyPI, "", root.Name, root.Version)
	dg, err := resolve.Resolve(ctx, src, devRoot, deps, opt.MaxRounds)
	if err != nil {
		return err
	}
	for id, c := range dg.Nodes {
		if id == dg.Root || g.Nodes[id] != nil {
			continue
		}
		if h := hashes[c.Name]; len(h) > 0 {
			c.Integrity = h
		}
		c.Source = files[c.Name]
		if c.Source == "" || src.closed && !runtime[c.Name] && src.locked[c.Name] == "" {
			c.Source = "resolver"
		}
		g.Nodes[id] = c
	}
	for from, es := range dg.Out {
		for _, e := range es {
			if from == dg.Root {
				e.From = g.Root
			}
			g.AddEdge(e)
		}
	}
	g.Conflicts = append(g.Conflicts, dg.Conflicts...)
	g.Incomplete = append(g.Incomplete, dg.Incomplete...)
	g.Notes = append(g.Notes, dg.Notes...)
	g.ComputeDepths()
	return nil
}

// selfReference reports whether a skipped requirement installs the project
// itself ("-e .", "-e .[test]", "."), which is not a dependency.
func selfReference(req string) bool {
	r := strings.TrimSpace(req)
	for _, p := range []string{"--editable", "-e"} {
		if rest, ok := strings.CutPrefix(r, p); ok {
			r = strings.TrimSpace(strings.TrimPrefix(rest, "="))
			break
		}
	}
	r = strings.TrimPrefix(r, "file:")
	if i := strings.IndexByte(r, '['); i >= 0 {
		r = r[:i]
	}
	return r == "." || r == "./"
}

func isDirectVia(via []string) bool {
	if len(via) == 0 {
		return true
	}
	for _, v := range via {
		if strings.HasPrefix(v, "-r ") || strings.HasPrefix(v, "-c ") || strings.HasSuffix(v, ".in") || strings.Contains(v, "pyproject.toml") || strings.Contains(v, "setup.") {
			return true
		}
	}
	return false
}

func pyprojectDeps(file string) ([]reqLine, []string, error) {
	var pp struct {
		Project struct {
			Dependencies []string `toml:"dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.DecodeFile(file, &pp); err != nil {
		return nil, nil, err
	}
	var out []reqLine
	var skipped []string
	for _, d := range pp.Project.Dependencies {
		r, ok := ParseRequirement(d)
		if !ok || r.URL || !validSpec(r.Spec) {
			skipped = append(skipped, d) // direct reference ("x @ git+https://...") or malformed
			continue
		}
		out = append(out, reqLine{Requirement: r})
	}
	names := make([]string, 0, len(pp.Tool.Poetry.Dependencies))
	for n := range pp.Tool.Poetry.Dependencies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if strings.EqualFold(n, "python") {
			continue
		}
		spec, ok := "", false
		switch v := pp.Tool.Poetry.Dependencies[n].(type) {
		case string:
			spec, ok = poetrySpec(v), true
		case map[string]any:
			// {version = "^1.2", extras = [...]}; git, path and url
			// dependencies have no registry version
			if ver, isStr := v["version"].(string); isStr {
				spec, ok = poetrySpec(ver), true
			}
		}
		// a list of constraints selected by markers is not analysed either
		if !ok || !validSpec(spec) {
			skipped = append(skipped, n+" (tool.poetry.dependencies)")
			continue
		}
		out = append(out, reqLine{Requirement: Requirement{Name: Normalise(n), Spec: spec}})
	}
	return out, skipped, nil
}

// poetrySpec converts caret/tilde constraints to PEP 440.
func poetrySpec(s string) string {
	s = strings.TrimSpace(s)
	if s == "*" || s == "" {
		return ""
	}
	if strings.HasPrefix(s, "^") {
		v := strings.TrimPrefix(s, "^")
		parts := strings.Split(v, ".")
		upper := ""
		for i, p := range parts {
			if p != "0" || i == len(parts)-1 {
				var n int
				fmt.Sscanf(p, "%d", &n)
				up := append(append([]string{}, parts[:i]...), fmt.Sprint(n+1))
				upper = strings.Join(up, ".")
				break
			}
		}
		return ">=" + v + ",<" + upper
	}
	if strings.HasPrefix(s, "~") && !strings.HasPrefix(s, "~=") {
		v := strings.TrimPrefix(s, "~")
		parts := strings.Split(v, ".")
		if len(parts) >= 2 {
			var n int
			fmt.Sscanf(parts[1], "%d", &n)
			return ">=" + v + ",<" + parts[0] + "." + fmt.Sprint(n+1)
		}
	}
	if _, err := pep440.Parse(s); err == nil {
		return "==" + s
	}
	return strings.ReplaceAll(s, " ", "")
}

// ---------------------------------------------------------------- lockfile index

// lockIndex maps a normalised name to its lockfile entries. uv and Poetry
// lockfiles may hold several versions of one package, chosen by environment
// markers (torch 2.14.0 on macOS, 2.14.0+cpu on Linux); all of them are kept,
// as for other lockfile markers, because any of them may be installed.
type lockIndex map[string][]lockEntry

type lockEntry struct {
	id      string
	version string
	source  string // "" for a package index; otherwise a description such as "git https://..."
}

func (ix lockIndex) add(name, version, id, source string) {
	n := Normalise(name)
	for _, e := range ix[n] {
		if e.id == id {
			return
		}
	}
	ix[n] = append(ix[n], lockEntry{id: id, version: version, source: source})
}

// find returns the entries of name that match version and source when these
// are given (uv names them when a package has several entries).
func (ix lockIndex) find(name, version, source string) []string {
	var out []string
	for _, e := range ix[Normalise(name)] {
		if (version == "" || e.version == version) && (source == "" || e.source == source) {
			out = append(out, e.id)
		}
	}
	return out
}

// lockNode adds a lockfile package to the graph. A package that does not
// come from a package index (git, URL, local path) gets an identifier of its
// own and is marked in external, so that it is never confused with the index
// release of the same name and version.
func lockNode(g *model.Graph, ix lockIndex, external map[string]string, input, name, version, source, index string) *model.Component {
	c := comp(name, version)
	c.Source = input
	if index != "" && !IsPyPIIndex(index) {
		// another package index (download.pytorch.org): its files differ
		// from the PyPI files of the same version
		c.Resolved = index
		g.Notes = append(g.Notes, fmt.Sprintf("%s: %s %s is installed from %s; its hashes are not compared with PyPI", input, name, version, index))
	}
	if source != "" {
		c.PURL += "?source=" + url.QueryEscape(source)
		external[c.PURL] = source
	}
	c = g.AddNode(c)
	ix.add(name, version, c.PURL, source)
	return c
}

// IsPyPIIndex reports whether an index URL from a lockfile is PyPI itself.
func IsPyPIIndex(u string) bool {
	u = strings.TrimSuffix(strings.TrimSpace(u), "/")
	return u == "" || u == "https://pypi.org/simple" || u == "https://pypi.org/pypi" || u == strings.TrimSuffix(Index, "/")+"/simple"
}

// spliceExternal removes the packages of non-index sources that are part of
// the selected graph and links their dependencies to their parents. Such a
// package cannot be checked against registry metadata, advisories or
// provenance, so the analysis is marked incomplete, as for a VCS or URL line
// of a requirements file.
func spliceExternal(g *model.Graph, external map[string]string, input string) {
	ids := make([]string, 0, len(external))
	for id := range external {
		if g.Nodes[id] != nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, x := range ids {
		c := g.Nodes[x]
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s: %s %s (%s) is not from a package index and was not analysed", input, c.Name, c.Version, external[x]))
		children := g.Out[x]
		for from, es := range g.Out {
			kept := es[:0]
			var parents []model.Edge
			for _, e := range es {
				if e.To == x {
					parents = append(parents, e)
				} else {
					kept = append(kept, e)
				}
			}
			g.Out[from] = kept
			for _, p := range parents {
				for _, ch := range children {
					if ch.To != x && ch.To != from {
						g.AddEdge(model.Edge{From: from, To: ch.To, Range: ch.Range, Scope: p.Scope})
					}
				}
			}
		}
		delete(g.Nodes, x)
		delete(g.Out, x)
	}
	g.ComputeDepths()
}

// ---------------------------------------------------------------- poetry.lock

type poetryLock struct {
	Package []struct {
		Name         string         `toml:"name"`
		Version      string         `toml:"version"`
		Category     string         `toml:"category"`
		Optional     bool           `toml:"optional"`
		Dependencies map[string]any `toml:"dependencies"`
		Source       struct {
			Type      string `toml:"type"`
			URL       string `toml:"url"`
			Reference string `toml:"resolved_reference"`
		} `toml:"source"`
		Files []struct {
			File string `toml:"file"`
			Hash string `toml:"hash"`
		} `toml:"files"`
	} `toml:"package"`
	Metadata struct {
		Files map[string][]struct {
			File string `toml:"file"`
			Hash string `toml:"hash"`
		} `toml:"files"`
	} `toml:"metadata"`
}

// poetrySource describes a non-index source; "legacy" is a private package
// index and counts as an index.
func poetrySource(typ, u, ref string) string {
	switch typ {
	case "", "legacy":
		return ""
	}
	s := strings.TrimSpace(typ + " " + u)
	if ref != "" {
		s += "@" + ref
	}
	return s
}

// poetryConstraint returns the PEP 440 form of a dependency entry of
// poetry.lock: "^1.2", {version = "^1.2", markers = ...} or a list of them.
func poetryConstraint(v any) string {
	switch x := v.(type) {
	case string:
		return poetrySpec(x)
	case map[string]any:
		if s, ok := x["version"].(string); ok {
			return poetrySpec(s)
		}
	}
	return ""
}

func loadPoetry(dir string, root *model.Component, opt common.Options) (*model.Graph, error) {
	var lf poetryLock
	if _, err := toml.DecodeFile(filepath.Join(dir, "poetry.lock"), &lf); err != nil {
		return nil, fmt.Errorf("poetry.lock: %w", err)
	}
	g := model.NewGraph(root)
	g.Inputs = []string{"poetry.lock"}
	ix, external := lockIndex{}, map[string]string{}
	ids := make([]string, len(lf.Package))
	for i, p := range lf.Package {
		index := ""
		if p.Source.Type == "legacy" {
			index = p.Source.URL
		}
		c := lockNode(g, ix, external, "poetry.lock", p.Name, p.Version, poetrySource(p.Source.Type, p.Source.URL, p.Source.Reference), index)
		files := p.Files
		if len(files) == 0 {
			files = lf.Metadata.Files[p.Name]
		}
		for _, f := range files {
			c.Integrity = append(c.Integrity, f.Hash)
		}
		if p.Category == "dev" {
			c.Scope = model.ScopeDev
		}
		ids[i] = c.PURL
	}
	for i, p := range lf.Package {
		for n, v := range p.Dependencies {
			// with several versions of n, link those the constraint allows
			// (all of them if it cannot be evaluated)
			all := ix.find(n, "", "")
			var match []string
			if spec := poetryConstraint(v); spec != "" {
				for _, id := range all {
					if Satisfies(g.Nodes[id].Version, spec) {
						match = append(match, id)
					}
				}
			}
			if len(match) == 0 {
				match = all
			}
			for _, to := range match {
				g.AddEdge(model.Edge{From: ids[i], To: to})
			}
		}
	}
	direct, devDirect, extras := pyprojectDirect(dir)
	reportUnlocked(g, "poetry.lock", "pyproject.toml", declaredNames(dir, direct, devDirect, extras, opt.IncludeDev),
		func(n string) bool { return len(ix[n]) > 0 })
	linkDirect(g, ix, direct, devDirect, extras, opt.IncludeDev)
	spliceExternal(g, external, "poetry.lock")
	return g, nil
}

// pyprojectDirect returns the names of the direct runtime dependencies, of
// the development dependencies (poetry groups, uv dev-dependencies, PEP 735
// dependency groups) and of the optional dependencies of the project's extras.
func pyprojectDirect(dir string) (map[string]bool, map[string]bool, map[string]bool) {
	direct, dev, extras := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var pp struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]any `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
			UV struct {
				DevDependencies []string `toml:"dev-dependencies"`
			} `toml:"uv"`
		} `toml:"tool"`
	}
	if _, err := toml.DecodeFile(filepath.Join(dir, "pyproject.toml"), &pp); err != nil {
		return direct, dev, extras
	}
	for _, reqs := range pp.Project.OptionalDependencies {
		for _, d := range reqs {
			if r, ok := ParseRequirement(d); ok {
				extras[r.Name] = true
			}
		}
	}
	for _, d := range pp.Project.Dependencies {
		if r, ok := ParseRequirement(d); ok {
			direct[r.Name] = true
		}
	}
	for n := range pp.Tool.Poetry.Dependencies {
		direct[Normalise(n)] = true
	}
	for n := range pp.Tool.Poetry.DevDependencies {
		dev[Normalise(n)] = true
	}
	for _, grp := range pp.Tool.Poetry.Group {
		for n := range grp.Dependencies {
			dev[Normalise(n)] = true
		}
	}
	for _, d := range pp.Tool.UV.DevDependencies {
		if r, ok := ParseRequirement(d); ok {
			dev[r.Name] = true
		}
	}
	for _, grp := range pp.DependencyGroups {
		for _, x := range grp {
			if s, ok := x.(string); ok {
				if r, ok := ParseRequirement(s); ok {
					dev[r.Name] = true
				}
			}
		}
	}
	delete(direct, "python")
	return direct, dev, extras
}

// declaredNames returns the declared dependencies that a lockfile must lock:
// the runtime ones and, when development dependencies are analysed, the
// development groups and the project's extras. The project itself (a group
// that installs "project[test]") is not a dependency.
func declaredNames(dir string, direct, dev, extras map[string]bool, includeDev bool) []string {
	self, _ := projectIdentity(dir)
	self = Normalise(self)
	seen := map[string]bool{}
	add := func(m map[string]bool) {
		for n := range m {
			if n = Normalise(n); n != self && n != "python" {
				seen[n] = true
			}
		}
	}
	add(direct)
	if includeDev {
		add(dev)
		add(extras)
	}
	return sortedKeys(seen)
}

// reportUnlocked records declared dependencies that the lockfile does not
// lock. The locked install modes of uv, Poetry and pipenv refuse such a
// lockfile or lock it again, so ssca cannot know what would be installed:
// the analysis is incomplete, as for an npm lockfile out of sync with
// package.json.
func reportUnlocked(g *model.Graph, lockfile, manifest string, declared []string, locked func(string) bool) {
	var missing []string
	for _, n := range declared {
		if !locked(n) {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return
	}
	what := fmt.Sprintf("%d declared dependencies have", len(missing))
	if len(missing) == 1 {
		what = "1 declared dependency has"
	}
	more := ""
	if len(missing) > 5 {
		more = fmt.Sprintf(", … %d more", len(missing)-5)
		missing = missing[:5]
	}
	g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s is out of sync with %s: %s no lockfile entry: %s%s",
		lockfile, manifest, what, strings.Join(missing, ", "), more))
}

// linkDirect links the direct dependencies to the root and sets the scopes.
// With includeDev the development dependencies (scope dev) and the optional
// dependencies of the project's extras (scope extra: installed only on
// request, so not part of the production view) are linked as well;
// without it they and everything only they need are left out.
func linkDirect(g *model.Graph, ix lockIndex, direct, dev, extras map[string]bool, includeDev bool) {
	if len(direct) == 0 && len(dev) == 0 {
		// no manifest: every package that nothing depends on is direct
		hasParent := map[string]bool{}
		for _, es := range g.Out {
			for _, e := range es {
				hasParent[e.To] = true
			}
		}
		for n, es := range ix {
			for _, e := range es {
				if !hasParent[e.id] {
					direct[n] = true
				}
			}
		}
	}
	for n := range direct {
		for _, id := range ix.find(n, "", "") {
			g.AddEdge(model.Edge{From: g.Root, To: id, Scope: model.ScopeRuntime})
		}
	}
	if includeDev {
		for n := range extras {
			if direct[n] {
				continue
			}
			for _, id := range ix.find(n, "", "") {
				g.AddEdge(model.Edge{From: g.Root, To: id, Scope: model.ScopeExtra})
			}
		}
		for n := range dev {
			if direct[n] || extras[n] {
				continue
			}
			for _, id := range ix.find(n, "", "") {
				g.AddEdge(model.Edge{From: g.Root, To: id, Scope: model.ScopeDev})
			}
		}
	}
	// scope: runtime if reachable from a runtime direct dependency
	g.PropagateScopes()
	g.ComputeDepths()
	var drop []string
	for id, c := range g.Nodes {
		if id == g.Root {
			continue
		}
		if c.Depth <= 0 {
			drop = append(drop, id)
		}
	}
	for _, id := range drop {
		delete(g.Nodes, id)
		delete(g.Out, id)
	}
	if len(drop) > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("%d lockfile entries are not reachable from the selected dependency groups", len(drop)))
	}
}

// ---------------------------------------------------------------- uv.lock

type uvDep struct {
	Name    string         `toml:"name"`
	Version string         `toml:"version"`
	Source  map[string]any `toml:"source"`
	Extra   []string       `toml:"extra"`
}

type uvLock struct {
	Package []struct {
		Name                 string             `toml:"name"`
		Version              string             `toml:"version"`
		Source               map[string]any     `toml:"source"`
		Dependencies         []uvDep            `toml:"dependencies"`
		OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
		DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
		Sdist                *struct {
			Hash string `toml:"hash"`
		} `toml:"sdist"`
		Wheels []struct {
			Hash string `toml:"hash"`
		} `toml:"wheels"`
		// the requirements of a project as uv read them from pyproject.toml
		// when it wrote the lockfile; uv compares them to decide whether the
		// lockfile is up to date
		Metadata *struct {
			RequiresDist []uvDep            `toml:"requires-dist"`
			RequiresDev  map[string][]uvDep `toml:"requires-dev"`
		} `toml:"metadata"`
	} `toml:"package"`
}

// uvSource describes a non-index source of uv.lock ("git https://...",
// "url https://...whl", "path ../x"); a registry source gives "".
func uvSource(src map[string]any) string {
	if len(src) == 0 {
		return ""
	}
	if _, ok := src["registry"]; ok {
		return ""
	}
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%s %v", keys[0], src[keys[0]])
}

func loadUV(dir string, root *model.Component, opt common.Options) (*model.Graph, error) {
	var lf uvLock
	if _, err := toml.DecodeFile(filepath.Join(dir, "uv.lock"), &lf); err != nil {
		return nil, fmt.Errorf("uv.lock: %w", err)
	}
	g := model.NewGraph(root)
	g.Inputs = []string{"uv.lock"}
	ix, external := lockIndex{}, map[string]string{}
	ids := make([]string, len(lf.Package)) // "" for the project and workspace members
	members := map[string]bool{}           // the project and the workspace members
	var recorded map[string]bool           // requirements of the project recorded by uv
	for i, p := range lf.Package {
		ed, editable := p.Source["editable"]
		vi, virtual := p.Source["virtual"]
		if editable || virtual {
			members[Normalise(p.Name)] = true
			if (ed == "." || vi == ".") && p.Metadata != nil {
				recorded = map[string]bool{}
				for _, d := range p.Metadata.RequiresDist {
					recorded[Normalise(d.Name)] = true
				}
				for _, grp := range p.Metadata.RequiresDev {
					for _, d := range grp {
						recorded[Normalise(d.Name)] = true
					}
				}
			}
			continue
		}
		index, _ := p.Source["registry"].(string)
		c := lockNode(g, ix, external, "uv.lock", p.Name, p.Version, uvSource(p.Source), index)
		if p.Sdist != nil {
			c.Integrity = append(c.Integrity, p.Sdist.Hash)
		}
		for _, w := range p.Wheels {
			c.Integrity = append(c.Integrity, w.Hash)
		}
		ids[i] = c.PURL
	}
	targets := func(d uvDep) []string { return ix.find(d.Name, d.Version, uvSource(d.Source)) }
	direct, dev, extras := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, p := range lf.Package {
		if ids[i] == "" {
			for _, d := range p.Dependencies {
				direct[Normalise(d.Name)] = true
			}
			for _, grp := range p.OptionalDependencies {
				for _, d := range grp {
					extras[Normalise(d.Name)] = true
				}
			}
			for _, grp := range p.DevDependencies {
				for _, d := range grp {
					dev[Normalise(d.Name)] = true
				}
			}
			continue
		}
		for _, d := range p.Dependencies {
			for _, to := range targets(d) {
				g.AddEdge(model.Edge{From: ids[i], To: to})
			}
		}
	}
	// a dependency requested with extras ("httpx[http2]") also brings the
	// packages of those extras. They are needed by the package that made the
	// request, so the edges start there: urllib3[socks] requested only by a
	// development tool must not make PySocks a runtime package because
	// urllib3 itself is one. Extras requested by the project are linked from
	// the requested package (the project's scope is set by linkDirect).
	byID := map[string]int{}
	for i, id := range ids {
		if id != "" {
			byID[id] = i
		}
	}
	seen := map[string]bool{}
	var addExtras func(requester string, d uvDep)
	addExtras = func(requester string, d uvDep) {
		for _, target := range targets(d) {
			i, ok := byID[target]
			if !ok {
				continue
			}
			from := requester
			if from == "" {
				from = target
			}
			for _, e := range d.Extra {
				key := from + ">" + target + "[" + e + "]"
				if seen[key] {
					continue
				}
				seen[key] = true
				for _, x := range lf.Package[i].OptionalDependencies[e] {
					for _, to := range targets(x) {
						if to != from {
							g.AddEdge(model.Edge{From: from, To: to})
						}
					}
					addExtras(from, x)
				}
			}
		}
	}
	for i, p := range lf.Package {
		deps := p.Dependencies
		if ids[i] == "" && opt.IncludeDev {
			// the project's own extras and dependency groups
			for _, grp := range p.OptionalDependencies {
				deps = append(deps, grp...)
			}
			for _, grp := range p.DevDependencies {
				deps = append(deps, grp...)
			}
		}
		for _, d := range deps {
			if len(d.Extra) > 0 {
				addExtras(ids[i], d)
			}
		}
	}
	// pyproject.toml must agree with the lockfile: with the requirements
	// that uv recorded for the project, or else with the locked packages
	pd, pdev, pextras := pyprojectDirect(dir)
	reportUnlocked(g, "uv.lock", "pyproject.toml", declaredNames(dir, pd, pdev, pextras, opt.IncludeDev), func(n string) bool {
		if recorded != nil {
			return recorded[n] || members[n]
		}
		return len(ix[n]) > 0 || members[n]
	})
	linkDirect(g, ix, direct, dev, extras, opt.IncludeDev)
	spliceExternal(g, external, "uv.lock")
	return g, nil
}

// ---------------------------------------------------------------- Pipfile.lock

func loadPipfile(ctx context.Context, dir string, root *model.Component, opt common.Options) (*model.Graph, error) {
	b, err := os.ReadFile(filepath.Join(dir, "Pipfile.lock"))
	if err != nil {
		return nil, err
	}
	var lf struct {
		Default map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
			Markers string   `json:"markers"`
			Extras  []string `json:"extras"`
		} `json:"default"`
		Develop map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
			Extras  []string `json:"extras"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("Pipfile.lock: %w", err)
	}
	g := model.NewGraph(root)
	g.Inputs = []string{"Pipfile.lock"}
	ids := map[string]string{}
	active := map[string]map[string]bool{} // extras requested for each entry
	activate := func(n string, extras []string) bool {
		k, grew := Normalise(n), false
		if active[k] == nil {
			active[k] = map[string]bool{}
		}
		for _, x := range extras {
			if x = Normalise(x); !active[k][x] {
				active[k][x], grew = true, true
			}
		}
		return grew
	}
	// entries without a version come from git, a path or a URL (pipenv
	// installs every entry of the section)
	unversioned := func(section, n string) {
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("Pipfile.lock: %s (%s) has no index version and was not analysed", n, section))
	}
	for _, n := range sortedKeys(lf.Default) {
		e := lf.Default[n]
		activate(n, e.Extras)
		if e.Version == "" {
			unversioned("default", n)
			continue
		}
		c := comp(n, strings.TrimPrefix(e.Version, "=="))
		c.Integrity, c.Source = e.Hashes, "Pipfile.lock"
		ids[Normalise(n)] = g.AddNode(c).PURL
	}
	if opt.IncludeDev {
		for _, n := range sortedKeys(lf.Develop) {
			e := lf.Develop[n]
			activate(n, e.Extras)
			if _, ok := ids[Normalise(n)]; ok {
				continue
			}
			if e.Version == "" {
				unversioned("develop", n)
				continue
			}
			c := comp(n, strings.TrimPrefix(e.Version, "=="))
			c.Integrity, c.Source, c.Scope = e.Hashes, "Pipfile.lock", model.ScopeDev
			ids[Normalise(n)] = g.AddNode(c).PURL
		}
	}
	// Pipfile.lock is flat: edges are restored from registry metadata. The
	// file is valid for several environments (its entries have markers), so
	// a requirement counts if its target is locked, whatever the Python
	// version or platform of this analysis. An edge to "pkg[extra]" activates
	// the extra, whose requirements are then read again.
	if opt.Net != nil {
		src := newSource(opt.Net)
		queue, failed := sortedKeys(ids), map[string]bool{}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			if failed[n] {
				continue
			}
			id := ids[n]
			deps, err := src.depsAnyEnv(ctx, n, g.Nodes[id].Version, sortedKeys(active[n]))
			if err != nil {
				failed[n] = true
				g.Incomplete = append(g.Incomplete, "edges of "+n+" unavailable")
				continue
			}
			for _, d := range deps {
				k := Normalise(d.Name)
				to, ok := ids[k]
				if !ok {
					continue
				}
				if to != id {
					g.AddEdge(model.Edge{From: id, To: to, Range: d.Range})
				}
				if activate(k, d.Extras) {
					queue = append(queue, k)
				}
			}
		}
	}
	direct, dev := pipfileDirect(dir)
	// the Pipfile must agree with the lockfile: its packages must be locked
	// in the default section, its development packages in either section
	inSection := func(sections ...map[string]bool) func(string) bool {
		return func(n string) bool {
			for _, s := range sections {
				if s[n] {
					return true
				}
			}
			return false
		}
	}
	lockedDefault, lockedDevelop := map[string]bool{}, map[string]bool{}
	for n := range lf.Default {
		lockedDefault[Normalise(n)] = true
	}
	for n := range lf.Develop {
		lockedDevelop[Normalise(n)] = true
	}
	reportUnlocked(g, "Pipfile.lock", "Pipfile", declaredNames(dir, direct, nil, nil, false), inSection(lockedDefault))
	if opt.IncludeDev {
		var devOnly []string
		for _, n := range declaredNames(dir, nil, dev, nil, true) {
			if !direct[n] {
				devOnly = append(devOnly, n)
			}
		}
		reportUnlocked(g, "Pipfile.lock", "Pipfile [dev-packages]", devOnly, inSection(lockedDefault, lockedDevelop))
	}
	if len(direct) == 0 && len(dev) == 0 {
		// no Pipfile: the entries that nothing depends on are direct, those of
		// the develop section development dependencies
		hasParent := map[string]bool{}
		for _, es := range g.Out {
			for _, e := range es {
				hasParent[e.To] = true
			}
		}
		for n, id := range ids {
			switch {
			case hasParent[id]:
			case g.Nodes[id].Scope == model.ScopeDev:
				dev[n] = true
			default:
				direct[n] = true
			}
		}
	}
	ix := lockIndex{}
	for n, id := range ids {
		ix.add(n, g.Nodes[id].Version, id, "")
	}
	linkDirect(g, ix, direct, dev, nil, opt.IncludeDev)
	return g, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func pipfileDirect(dir string) (map[string]bool, map[string]bool) {
	direct, dev := map[string]bool{}, map[string]bool{}
	var pf struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if _, err := toml.DecodeFile(filepath.Join(dir, "Pipfile"), &pf); err == nil {
		for n := range pf.Packages {
			direct[Normalise(n)] = true
		}
		for n := range pf.DevPackages {
			dev[Normalise(n)] = true
		}
	}
	return direct, dev
}

// ---------------------------------------------------------------- index client

// SimpleFile is one file entry of the PEP 691 JSON Simple API.
type SimpleFile struct {
	Filename   string            `json:"filename"`
	URL        string            `json:"url"`
	Hashes     map[string]string `json:"hashes"`
	UploadTime string            `json:"upload-time"`
	Yanked     any               `json:"yanked"`
	Provenance *string           `json:"provenance"`
}

// SimpleProject is the PEP 691 project page.
type SimpleProject struct {
	Name     string       `json:"name"`
	Versions []string     `json:"versions"`
	Files    []SimpleFile `json:"files"`
}

// Client accesses the PyPI JSON and Simple APIs.
type Client struct{ Net *netx.Client }

// Simple returns the project page of the JSON Simple API.
func (c *Client) Simple(ctx context.Context, name string) (*SimpleProject, error) {
	b, err := c.Net.Get(ctx, Index+"/simple/"+Normalise(name)+"/", "application/vnd.pypi.simple.v1+json")
	if err != nil {
		return nil, err
	}
	var p SimpleProject
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("simple %s: %w", name, err)
	}
	return &p, nil
}

// VersionInfo is the JSON API document of one release.
type VersionInfo struct {
	Info struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		RequiresDist []string          `json:"requires_dist"`
		License      string            `json:"license"`
		LicenseExpr  string            `json:"license_expression"`
		Author       string            `json:"author"`
		AuthorEmail  string            `json:"author_email"`
		Maintainer   string            `json:"maintainer"`
		MaintEmail   string            `json:"maintainer_email"`
		ProjectURLs  map[string]string `json:"project_urls"`
		HomePage     string            `json:"home_page"`
		Classifiers  []string          `json:"classifiers"`
	} `json:"info"`
	URLs []struct {
		Filename    string            `json:"filename"`
		PackageType string            `json:"packagetype"`
		Digests     map[string]string `json:"digests"`
		UploadTime  string            `json:"upload_time_iso_8601"`
		URL         string            `json:"url"`
	} `json:"urls"`
}

// Version returns the JSON API document of a release.
func (c *Client) Version(ctx context.Context, name, version string) (*VersionInfo, error) {
	var v VersionInfo
	if err := c.Net.GetJSON(ctx, Index+"/pypi/"+Normalise(name)+"/"+version+"/json", &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// ReleaseTimes returns the first upload time of each version.
func (p *SimpleProject) ReleaseTimes() map[string]time.Time {
	out := map[string]time.Time{}
	for _, f := range p.Files {
		v := VersionFromFilename(p.Name, f.Filename)
		t, err := time.Parse(time.RFC3339, f.UploadTime)
		if v == "" || err != nil {
			continue
		}
		if old, ok := out[v]; !ok || t.Before(old) {
			out[v] = t
		}
	}
	return out
}

// VersionFromFilename extracts the version from a wheel or sdist name.
func VersionFromFilename(project, fn string) string {
	base := fn
	for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2", ".whl", ".egg", ".exe", ".msi", ".rpm", ".dmg"} {
		base = strings.TrimSuffix(base, ext)
	}
	if strings.HasSuffix(fn, ".whl") || strings.HasSuffix(fn, ".egg") {
		parts := strings.Split(base, "-")
		if len(parts) >= 2 {
			return parts[1]
		}
		return ""
	}
	n := len(project)
	if len(base) > n+1 && Normalise(base[:n]) == Normalise(project) {
		return base[n+1:]
	}
	if i := strings.LastIndex(base, "-"); i > 0 {
		return base[i+1:]
	}
	return ""
}

// ---------------------------------------------------------------- resolver source

type source struct {
	cl          *Client
	locked      map[string]string   // fully pinned input: name -> version
	constraints map[string][]string // constraints files: name -> specifiers
	closed      bool
}

func newSource(n *netx.Client) *source { return &source{cl: &Client{Net: n}} }

func (s *source) Rule() resolve.Rule        { return resolve.PyPISingle }
func (s *source) Normalise(n string) string { return Normalise(n) }

func (s *source) Versions(ctx context.Context, name string) ([]string, error) {
	if v, ok := s.locked[name]; ok && v != "" {
		return []string{v}, nil
	}
	p, err := s.cl.Simple(ctx, name)
	if err != nil {
		return nil, err
	}
	yanked := map[string]bool{}
	has := map[string]bool{}
	for _, f := range p.Files {
		v := VersionFromFilename(p.Name, f.Filename)
		if y, ok := f.Yanked.(bool); ok && y {
			yanked[v] = true
		} else if _, ok := f.Yanked.(string); ok {
			yanked[v] = true
		} else {
			has[v] = true
		}
	}
	var vs []string
	for _, v := range p.Versions {
		if _, err := pep440.Parse(v); err == nil && has[v] {
			vs = append(vs, v)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return Compare(vs[i], vs[j]) < 0 })
	return s.constrain(name, vs), nil
}

// constrain keeps the versions allowed by the constraints files.
func (s *source) constrain(name string, vs []string) []string {
	cs := s.constraints[name]
	if len(cs) == 0 {
		return vs
	}
	var kept []string
	for _, v := range vs {
		ok := true
		for _, c := range cs {
			ok = ok && Satisfies(v, c)
		}
		if ok {
			kept = append(kept, v)
		}
	}
	return kept
}

func (s *source) Deps(ctx context.Context, name, version string, extras []string) ([]resolve.Dep, error) {
	return s.deps(ctx, name, version, func(m string) bool { return EvalMarker(m, extras) })
}

// depsAnyEnv is Deps for requirements that hold in any environment (EvalMarkerAnyEnv).
func (s *source) depsAnyEnv(ctx context.Context, name, version string, extras []string) ([]resolve.Dep, error) {
	return s.deps(ctx, name, version, func(m string) bool { return EvalMarkerAnyEnv(m, extras) })
}

func (s *source) deps(ctx context.Context, name, version string, keep func(marker string) bool) ([]resolve.Dep, error) {
	vi, err := s.cl.Version(ctx, name, version)
	if err != nil {
		return nil, err
	}
	var out []resolve.Dep
	for _, rd := range vi.Info.RequiresDist {
		r, ok := ParseRequirement(rd)
		if !ok || r.URL {
			continue
		}
		if !keep(r.Marker) {
			continue
		}
		out = append(out, resolve.Dep{Name: r.Name, Range: r.Spec, Extras: r.Extras, Scope: model.ScopeRuntime})
	}
	return out, nil
}

func (s *source) Satisfies(v, r string) bool { return Satisfies(v, r) }

func (s *source) Pinned(r string) (string, bool) { return pinned(r) }

func (s *source) MarkerApplies(d resolve.Dep) bool {
	return EvalMarker(d.Marker, nil)
}

func (s *source) Component(name, version string) *model.Component { return comp(name, version) }

func (s *source) Transitive(parent model.Scope, d resolve.Dep, depth int) (model.Scope, bool) {
	return parent, true
}

func (s *source) Managed(name string) (string, model.Scope, bool) {
	if v, ok := s.locked[name]; ok && v != "" {
		return "==" + v, "", true
	}
	return "", "", false
}
