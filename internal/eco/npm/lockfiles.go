// Package npm is the npm ecosystem plugin: lockfile parsers, SemVer
// semantics, registry client and resolution without a lockfile.
package npm

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// manifest is the subset of package.json used by the suite.
type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Scripts              map[string]string `json:"scripts"`
	Workspaces           json.RawMessage   `json:"workspaces"`
	Resolutions          map[string]string `json:"resolutions"` // yarn
	members              []*manifest
}

func readManifest(dir string) (*manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	if m.Name == "" {
		m.Name = common.DirName(dir)
	}
	if m.Version == "" {
		m.Version = "0.0.0"
	}
	// workspace members (yarn and npm "workspaces" field)
	var pats []string
	if json.Unmarshal(m.Workspaces, &pats) != nil {
		var obj struct {
			Packages []string `json:"packages"`
		}
		if json.Unmarshal(m.Workspaces, &obj) == nil {
			pats = obj.Packages
		}
	}
	for _, pat := range pats {
		dirs, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, d := range dirs {
			if b, err := os.ReadFile(filepath.Join(d, "package.json")); err == nil {
				var wm manifest
				if json.Unmarshal(b, &wm) == nil {
					m.members = append(m.members, &wm)
				}
			}
		}
	}
	return &m, nil
}

func rootComponent(m *manifest) *model.Component {
	ns, n := model.SplitNPMName(m.Name)
	c := model.NewComponent(model.NPM, ns, n, m.Version)
	c.Source = "package.json"
	return c
}

func npmComponent(name, version string) *model.Component {
	ns, n := model.SplitNPMName(name)
	return model.NewComponent(model.NPM, ns, n, version)
}

// addNode adds a lockfile entry to the graph. The same name and version can
// appear at several paths of a lockfile (nested copies, bundled copies
// without hash or URL); the copies are merged independently of the order in
// which the lockfile is read: all hashes are kept, a download location
// outside the registry wins over the registry, so that M3 checks it, and the
// license is chosen by text order.
func addNode(g *model.Graph, c *model.Component) *model.Component {
	n := g.AddNode(c)
	if n == c {
		return n
	}
	for _, h := range c.Integrity {
		if !slices.Contains(n.Integrity, h) {
			n.Integrity = append(n.Integrity, h)
		}
	}
	slices.Sort(n.Integrity)
	if betterSource(c.Resolved, n.Resolved) {
		n.Resolved = c.Resolved
	}
	// a copy with a wrong lockfile scope marks the merged node
	if c.LockScope != "" && (n.LockScope == "" || c.ScopeVia < n.ScopeVia) {
		n.LockScope, n.ScopeVia = c.LockScope, c.ScopeVia
	}
	// copies may spell the license differently ("MIT/X11", "MIT OR X11")
	if a, b := strings.Join(n.Licenses, "\n"), strings.Join(c.Licenses, "\n"); b != "" && (a == "" || b < a) {
		n.Licenses = c.Licenses
	}
	return n
}

// betterSource orders the download locations of merged copies: a recorded
// location beats none, one outside the registry beats the registry, and the
// text order decides between equals.
func betterSource(a, b string) bool {
	switch {
	case a == "" || a == b:
		return false
	case b == "":
		return true
	case onRegistry(a) != onRegistry(b):
		return !onRegistry(a)
	}
	return a < b
}

// onRegistry reports whether a lockfile URL points to the public registry.
func onRegistry(u string) bool {
	for _, b := range []string{Registry + "/", "https://registry.npmjs.org/", "https://registry.yarnpkg.com/"} {
		if strings.HasPrefix(u, b) {
			return true
		}
	}
	return false
}

// sourceSpec reports whether a lockfile version field names a download
// source instead of a version (npm v1 "git+https://...#sha", "file:../x").
func sourceSpec(v string) bool {
	return strings.Contains(v, ":") && !strings.HasPrefix(v, "npm:")
}

// yarnSHA1 turns the "#<sha1>" fragment of a yarn v1 "resolved" URL into an
// integrity value; yarn v1 lockfiles before 1.10 record no other hash.
func yarnSHA1(resolved string) string {
	_, frag, ok := strings.Cut(resolved, "#")
	b, err := hex.DecodeString(frag)
	if !ok || err != nil || len(b) != 20 {
		return ""
	}
	return "sha1-" + base64.StdEncoding.EncodeToString(b)
}

// berrySource returns the download source of a yarn berry resolution
// ("qs@npm:6.13.0", "x@https://host/x.tgz", "y@git+ssh://..."): "" for the
// registry, including a registry package with a local patch.
func berrySource(resolution string) string {
	i := strings.Index(resolution[min(1, len(resolution)):], "@") + 1 // skip the "@" of a scope
	if i <= 0 {
		return ""
	}
	src := resolution[i+1:]
	if strings.HasPrefix(src, "patch:") { // patch:qs@npm%3A6.13.0#./.yarn/patches/...
		inner, _, _ := strings.Cut(strings.TrimPrefix(src, "patch:"), "#")
		if u, err := url.PathUnescape(inner); err == nil {
			inner = u
		}
		return berrySource(inner)
	}
	if strings.HasPrefix(src, "npm:") {
		return ""
	}
	return src
}

// ---------------------------------------------------------------- package-lock

type lockPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	DevOptional          bool              `json:"devOptional"`
	Peer                 bool              `json:"peer"`
	Link                 bool              `json:"link"`
	License              any               `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	HasInstallScript     bool              `json:"hasInstallScript"`
}

type lockV1Dep struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Integrity    string               `json:"integrity"`
	Dev          bool                 `json:"dev"`
	Optional     bool                 `json:"optional"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]lockV1Dep `json:"dependencies"`
}

type packageLock struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]lockPkg   `json:"packages"`
	Dependencies    map[string]lockV1Dep `json:"dependencies"`
}

// scopeOf maps the flags of a lockfile entry to a scope. "devOptional" marks
// a package that is a development dependency and also an optional dependency
// of a production package: npm installs it in production (unless optional
// packages are omitted), so it is optional, not dev.
func scopeOf(p lockPkg) model.Scope {
	switch {
	case p.Dev:
		return model.ScopeDev
	case p.Optional || p.DevOptional:
		return model.ScopeOptional
	}
	return model.ScopeRuntime
}

// nameFromPath returns the package name of "node_modules/a/node_modules/@s/b".
func nameFromPath(p string) string {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return ""
	}
	return p[i+len("node_modules/"):]
}

// parsePackageLock reads lockfileVersion 2/3 (packages map) or 1 (nested).
func parsePackageLock(file string, m *manifest, includeDev bool) (*model.Graph, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var lf packageLock
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(file), err)
	}
	g := model.NewGraph(rootComponent(m))
	g.Inputs = []string{filepath.Base(file)}
	md := newMissing(filepath.Base(file))
	if len(lf.Packages) > 0 {
		parseLockV2(g, lf.Packages, m, includeDev, md)
	} else {
		parseLockV1(g, lf.Dependencies, m, includeDev, md)
	}
	md.report(g)
	g.ComputeDepths()
	pruneUnreachable(g)
	return g, nil
}

// prodScopes derives which packages of a lockfile are production packages,
// the way npm sets the flags it writes: a package is runtime if a chain of
// dependencies leads to it from a start node, optional if every such chain
// contains an optional dependency, and a development package if no chain
// without devDependencies reaches it. edges(u) lists the dependencies of
// node u with their scope (runtime or optional); development edges are not
// listed. Peer dependencies are not followed: npm versions differ in whether
// a peer of a production package is flagged "dev" (vscode in corpus (a)
// declares tslib as a peer of a runtime package, and npm marked it "dev"),
// so only regular and optional dependencies count as evidence. The result
// maps a node to its scope and to the node from which it was reached.
func prodScopes(starts []string, edges func(u string) []scopedEdge) map[string]reached {
	best := map[string]reached{}
	var q []string
	for _, s := range starts {
		best[s] = reached{scope: model.ScopeRuntime}
		q = append(q, s)
	}
	for len(q) > 0 {
		u := q[0]
		q = q[1:]
		for _, e := range edges(u) {
			s := best[u].scope
			if e.scope == model.ScopeOptional {
				s = model.ScopeOptional
			}
			if old, ok := best[e.to]; !ok || model.ScopeRank(s) < model.ScopeRank(old.scope) {
				best[e.to] = reached{scope: s, via: u}
				q = append(q, e.to)
			}
		}
	}
	return best
}

type scopedEdge struct {
	to    string
	scope model.Scope
}

type reached struct {
	scope model.Scope
	via   string
}

// checkScope compares the scope written in the lockfile with the derived one.
// A package that the lockfile marks as a development dependency although a
// production package needs it takes the derived scope, and the difference is
// recorded for M3: such a lockfile hides a shipped package from the
// production view (by hand-editing or a broken tool).
func checkScope(c *model.Component, flag model.Scope, r reached, ok bool, viaName func(string) string) {
	c.Scope = flag
	if flag.Production() || !ok {
		return
	}
	c.Scope, c.LockScope, c.ScopeVia = r.scope, flag, viaName(r.via)
}

func parseLockV2(g *model.Graph, pk map[string]lockPkg, m *manifest, includeDev bool, md *missingDeps) {
	projectFromManifest(g, pk, m)
	// links: node_modules/x -> workspace folder
	links := map[string]string{}
	for p, e := range pk {
		if e.Link && e.Resolved != "" {
			links[p] = e.Resolved
		}
	}
	// resolve finds the lockfile path that a dependency of the package at
	// path from resolves to (Node.js module resolution: from/node_modules/name,
	// then the parent folders); a link resolves to its workspace folder.
	// The folders are walked up one by one, so that a nested workspace
	// such as apps/a/native finds apps/a/node_modules; inside node_modules the
	// extra candidates (".../node_modules/@s/node_modules/x") never exist.
	resolve := func(from, name string) (string, bool) {
		dir := from
		for {
			cand := "node_modules/" + name
			if dir != "" {
				cand = dir + "/" + cand
			}
			if _, ok := pk[cand]; ok {
				if t, ok := links[cand]; ok {
					return t, true
				}
				return cand, true
			}
			if dir == "" {
				return "", false
			}
			if i := strings.LastIndex(dir, "/"); i >= 0 {
				dir = dir[:i]
			} else {
				dir = ""
			}
		}
	}
	isProject := func(p string) bool {
		e := pk[p]
		return p == "" || !strings.Contains(p, "node_modules/") && !e.Link
	}
	// scopes derived from the dependency lists; the project and the
	// workspace members are the start nodes
	starts := []string{""}
	for p := range pk {
		if p != "" && isProject(p) {
			starts = append(starts, p)
		}
	}
	sort.Strings(starts)
	derived := prodScopes(starts, func(u string) []scopedEdge {
		e := pk[u]
		var out []scopedEdge
		add := func(m map[string]string, s model.Scope) {
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if to, ok := resolve(u, n); ok {
					out = append(out, scopedEdge{to, s})
				}
			}
		}
		add(e.Dependencies, model.ScopeRuntime)
		add(e.OptionalDependencies, model.ScopeOptional)
		return out
	})
	viaName := func(p string) string {
		if isProject(p) {
			return "the project"
		}
		e := pk[p]
		name := nameFromPath(p)
		if e.Name != "" {
			name = e.Name
		}
		return name + "@" + e.Version
	}
	// entries that nothing requires, whatever the selected scopes: npm ci
	// installs them anyway, so they are analysed and reported (extraneous)
	required := map[string]bool{}
	for q := append([]string{}, starts...); len(q) > 0; {
		u := q[0]
		q = q[1:]
		e := pk[u]
		lists := []map[string]string{e.Dependencies, e.OptionalDependencies, e.PeerDependencies}
		if isProject(u) {
			lists = append(lists, e.DevDependencies)
		}
		for _, l := range lists {
			for n := range l {
				if to, ok := resolve(u, n); ok && !required[to] {
					required[to] = true
					q = append(q, to)
				}
			}
		}
	}
	// package.json must agree with the lockfile: a dependency it declares
	// that the lockfile does not resolve is not analysed
	for _, l := range []map[string]string{m.Dependencies, devIf(m.DevDependencies, includeDev)} {
		for _, n := range sortedKeys(l) {
			if _, ok := m.OptionalDependencies[n]; ok {
				continue
			}
			if _, ok := resolve("", n); !ok {
				md.add(n, l[n], "package.json")
			}
		}
	}
	// every direct dependency must be locked inside the range of package.json
	for _, l := range []map[string]string{m.Dependencies, m.OptionalDependencies, devIf(m.DevDependencies, includeDev)} {
		for _, n := range sortedKeys(l) {
			p, ok := resolve("", n)
			if e, entry := pk[p]; ok && entry && !e.Link && strings.Contains(p, "node_modules/") && e.Version != "" {
				md.checkRange(n, l[n], e.Version)
			}
		}
	}
	// a link entry must point to a folder entry of the same lockfile (a
	// workspace or a local package) of the same name; otherwise the
	// dependency is satisfied by code that the lockfile does not describe
	for _, p := range sortedKeys2(pk) {
		e := pk[p]
		if !e.Link {
			continue
		}
		t, ok := pk[e.Resolved]
		switch {
		case e.Resolved == "" || !ok:
			md.badLink(p, e.Resolved, "")
		case t.Name != "" && t.Name != nameFromPath(p):
			md.badLink(p, e.Resolved, t.Name)
		}
	}
	idOf := map[string]string{} // lock path -> purl
	var noVersion []string
	for p, e := range pk {
		if p == "" || e.Link || !strings.Contains(p, "node_modules/") {
			continue
		}
		name := nameFromPath(p)
		if e.Name != "" { // npm alias "npm:real@1.0.0"
			name = e.Name
		}
		if e.Version == "" {
			// npm writes a version for every installed package; an entry
			// without one is damaged or edited and cannot be identified
			if r, ok := derived[p]; includeDev || scopeOf(e).Production() || ok && r.scope.Production() {
				noVersion = append(noVersion, p)
			}
			continue
		}
		c := npmComponent(name, e.Version)
		r, ok := derived[p]
		checkScope(c, scopeOf(e), r, ok, viaName)
		if !includeDev && !c.Scope.Production() {
			continue
		}
		c.Extraneous = !required[p]
		c.Resolved = e.Resolved
		if e.Integrity != "" {
			c.Integrity = []string{e.Integrity}
		}
		c.Source = "package-lock.json"
		c.Licenses = licenseList(e.License)
		node := addNode(g, c)
		if model.ScopeRank(c.Scope) < model.ScopeRank(node.Scope) {
			node.Scope = c.Scope
		}
		idOf[p] = node.PURL
	}
	if len(noVersion) > 0 {
		sort.Strings(noVersion)
		what := fmt.Sprintf("%d entries without a version were", len(noVersion))
		if len(noVersion) == 1 {
			what = "1 entry without a version was"
		}
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s: %s not analysed: %s", md.file, what, strings.Join(noVersion, ", ")))
	}
	addEdges := func(fromPath, fromID string, e lockPkg, isProject bool) {
		type dl struct {
			m        map[string]string
			s        model.Scope
			required bool // must have a lockfile entry
		}
		lists := []dl{{e.Dependencies, model.ScopeRuntime, true}, {e.OptionalDependencies, model.ScopeOptional, false}, {e.PeerDependencies, model.ScopeRuntime, false}}
		if isProject && includeDev {
			lists = append(lists, dl{e.DevDependencies, model.ScopeDev, true})
		}
		for _, l := range lists {
			for name, rng := range l.m {
				p, ok := resolve(fromPath, name)
				if !ok {
					// the project's own list is package.json, checked above
					if _, opt := e.OptionalDependencies[name]; l.required && !opt && fromPath != "" {
						md.add(name, rng, viaName(fromPath))
					}
					continue
				}
				to, ok := idOf[p]
				if !ok || g.Nodes[to] == nil {
					continue
				}
				g.AddEdge(model.Edge{From: fromID, To: to, Range: rng, Scope: l.s})
			}
		}
	}
	for p, e := range pk {
		switch {
		case p == "":
			addEdges("", g.Root, e, true)
		case !strings.Contains(p, "node_modules/") && !e.Link:
			// workspace member: its dependencies count as direct dependencies
			addEdges(p, g.Root, e, true)
		default:
			if id, ok := idOf[p]; ok {
				addEdges(p, id, e, false)
			}
		}
	}
	attachExtraneous(g)
}

// attachExtraneous links the extraneous lockfile entries that no other entry
// requires to the project, with the scope of their lockfile flag: npm ci
// installs them as if the project depended on them. Their own dependencies
// stay below them.
func attachExtraneous(g *model.Graph) {
	hasParent := map[string]bool{}
	for from, es := range g.Out {
		for _, e := range es {
			if from != e.To {
				hasParent[e.To] = true
			}
		}
	}
	var ext []*model.Component
	for _, c := range g.Components() {
		if c.Extraneous {
			ext = append(ext, c)
		}
	}
	for _, c := range ext {
		if !hasParent[c.PURL] {
			g.AddEdge(model.Edge{From: g.Root, To: c.PURL, Scope: c.Scope})
		}
	}
	// extraneous packages that only require each other (a cycle)
	g.ComputeDepths()
	for _, c := range ext {
		if c.Depth < 0 {
			g.AddEdge(model.Edge{From: g.Root, To: c.PURL, Scope: c.Scope})
			g.ComputeDepths()
		}
	}
	if len(ext) > 0 {
		g.Notes = append(g.Notes, fmt.Sprintf("lockfile contains %d entries that no dependency requires; npm ci installs them, so they are analysed and reported (SSCA-LOCKFILE-EXTRANEOUS)", len(ext)))
	}
}

func parseLockV1(g *model.Graph, deps map[string]lockV1Dep, m *manifest, includeDev bool, md *missingDeps) {
	// the nested "dependencies" objects form a tree of package instances;
	// an instance is named by its path ("a/b" = b nested inside a,
	// "a/@s/c" = @s/c nested inside a); since scoped names contain a slash
	// themselves, every instance records the path of its parent
	type scopeNode struct {
		deps   map[string]lockV1Dep
		parent *scopeNode
		paths  map[string]string // name -> instance path
	}
	type instance struct {
		name   string
		d      lockV1Dep
		parent string // "" for the top level
	}
	inst := map[string]instance{}
	reqs := map[string][]scopedEdge{}   // instance -> instances it requires
	unresolved := map[string][]string{} // instance -> required names without an entry
	var build func(sn *scopeNode, parent string)
	build = func(sn *scopeNode, parent string) {
		for name, d := range sn.deps {
			p := name
			if parent != "" {
				p = parent + "/" + name
			}
			sn.paths[name] = p
			inst[p] = instance{name, d, parent}
		}
		for name, d := range sn.deps {
			p := sn.paths[name]
			child := &scopeNode{deps: d.Dependencies, parent: sn, paths: map[string]string{}}
			build(child, p)
			reqNames := make([]string, 0, len(d.Requires))
			for req := range d.Requires {
				reqNames = append(reqNames, req)
			}
			sort.Strings(reqNames)
			for _, req := range reqNames {
				found := false
				for s := child; s != nil; s = s.parent {
					if to, ok := s.paths[req]; ok {
						reqs[p] = append(reqs[p], scopedEdge{to, model.ScopeRuntime})
						found = true
						break
					}
				}
				if !found {
					unresolved[p] = append(unresolved[p], req)
				}
			}
		}
	}
	root := &scopeNode{deps: deps, paths: map[string]string{}}
	build(root, "")
	// scopes derived from the manifest: "" is the project
	derived := prodScopes([]string{""}, func(u string) []scopedEdge {
		if u != "" {
			return reqs[u]
		}
		var out []scopedEdge
		for _, l := range []struct {
			m map[string]string
			s model.Scope
		}{{m.Dependencies, model.ScopeRuntime}, {m.OptionalDependencies, model.ScopeOptional}} {
			names := make([]string, 0, len(l.m))
			for n := range l.m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if p, ok := root.paths[n]; ok {
					out = append(out, scopedEdge{p, l.s})
				}
			}
		}
		return out
	})
	viaName := func(p string) string {
		if p == "" {
			return "the project"
		}
		return inst[p].name + "@" + inst[p].d.Version
	}
	// instances that nothing requires (extraneous), whatever the selected
	// scopes; npm ci installs them anyway
	required := map[string]bool{}
	{
		var q []string
		for _, l := range []map[string]string{m.Dependencies, m.OptionalDependencies, m.DevDependencies} {
			for n := range l {
				if p, ok := root.paths[n]; ok && !required[p] {
					required[p] = true
					q = append(q, p)
				}
			}
		}
		for len(q) > 0 {
			u := q[0]
			q = q[1:]
			for _, e := range reqs[u] {
				if !required[e.to] {
					required[e.to] = true
					q = append(q, e.to)
				}
			}
		}
	}
	ids := map[string]string{} // instance path -> purl
	paths := make([]string, 0, len(inst))
	for p := range inst {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		name, d := inst[p].name, inst[p].d
		c := npmComponent(name, d.Version)
		if strings.HasPrefix(d.Version, "npm:") { // alias
			real := strings.TrimPrefix(d.Version, "npm:")
			at := strings.LastIndex(real, "@")
			c = npmComponent(real[:at], real[at+1:])
		}
		flag := model.ScopeRuntime
		if d.Dev {
			flag = model.ScopeDev
		} else if d.Optional {
			flag = model.ScopeOptional
		}
		r, ok := derived[p]
		checkScope(c, flag, r, ok, viaName)
		if !includeDev && !c.Scope.Production() {
			continue
		}
		// the instances inside a skipped development package are skipped too
		// (paths sort before the paths nested in them, so the parent is done)
		if par := inst[p].parent; par != "" {
			if _, ok := ids[par]; !ok {
				continue
			}
		}
		c.Extraneous = !required[p] && len(m.Dependencies)+len(m.OptionalDependencies)+len(m.DevDependencies) > 0
		c.Resolved, c.Source = d.Resolved, "package-lock.json"
		if c.Resolved == "" && sourceSpec(d.Version) {
			c.Resolved = d.Version
		}
		if d.Integrity != "" {
			c.Integrity = []string{d.Integrity}
		}
		node := addNode(g, c)
		if model.ScopeRank(c.Scope) < model.ScopeRank(node.Scope) {
			node.Scope = c.Scope
		}
		ids[p] = node.PURL
	}
	for _, p := range paths {
		from, ok := ids[p]
		if !ok {
			continue
		}
		// v1 "requires" does not tell optional dependencies apart; npm 6
		// writes them for every platform (flagged "optional"), so a required
		// name without an entry means that the lockfile is out of sync
		for _, req := range unresolved[p] {
			md.add(req, inst[p].d.Requires[req], viaName(p))
		}
		for _, e := range reqs[p] {
			if to, ok := ids[e.to]; ok {
				g.AddEdge(model.Edge{From: from, To: to, Range: inst[p].d.Requires[inst[e.to].name]})
			}
		}
	}
	link := func(deps map[string]string, s model.Scope) {
		for name, rng := range deps {
			if p, ok := root.paths[name]; ok {
				if id, ok := ids[p]; ok {
					g.AddEdge(model.Edge{From: g.Root, To: id, Range: rng, Scope: s})
				}
			}
		}
	}
	link(m.Dependencies, model.ScopeRuntime)
	link(m.OptionalDependencies, model.ScopeOptional)
	if includeDev {
		link(m.DevDependencies, model.ScopeDev)
	}
	attachExtraneous(g)
	for _, l := range []map[string]string{m.Dependencies, devIf(m.DevDependencies, includeDev)} {
		for _, n := range sortedKeys(l) {
			if _, opt := m.OptionalDependencies[n]; opt {
				continue
			}
			if _, ok := root.paths[n]; !ok {
				md.add(n, l[n], "package.json")
			}
		}
	}
	for _, l := range []map[string]string{m.Dependencies, m.OptionalDependencies, devIf(m.DevDependencies, includeDev)} {
		for _, n := range sortedKeys(l) {
			if d, ok := deps[n]; ok && d.Version != "" {
				md.checkRange(n, l[n], d.Version)
			}
		}
	}
}

// projectFromManifest makes the root entry ("") of a package-lock.json
// version 2 or 3 carry the dependency lists of package.json. npm builds the
// project node from package.json and only compares it with the root entry of
// the lockfile (a difference makes it recompute the dev and optional flags);
// a root entry that is missing or lists other dependencies must therefore not
// hide a dependency of package.json or add one that npm does not install.
func projectFromManifest(g *model.Graph, pk map[string]lockPkg, m *manifest) {
	if m == nil {
		return
	}
	old, had := pk[""]
	root := old
	root.Dependencies, root.DevDependencies = m.Dependencies, m.DevDependencies
	root.OptionalDependencies, root.PeerDependencies = m.OptionalDependencies, m.PeerDependencies
	pk[""] = root
	if !had {
		g.Notes = append(g.Notes, "package-lock.json has no entry for the project; the dependencies of package.json were used")
		return
	}
	var diff []string
	for _, l := range [][2]map[string]string{{old.Dependencies, root.Dependencies}, {old.DevDependencies, root.DevDependencies},
		{old.OptionalDependencies, root.OptionalDependencies}, {old.PeerDependencies, root.PeerDependencies}} {
		for _, n := range sortedKeys(l[1]) {
			if _, ok := l[0][n]; !ok {
				diff = append(diff, "+"+n)
			}
		}
		for _, n := range sortedKeys(l[0]) {
			if _, ok := l[1][n]; !ok {
				diff = append(diff, "-"+n)
			}
		}
	}
	if len(diff) > 0 {
		g.Notes = append(g.Notes, "the root entry of package-lock.json lists other dependencies than package.json, which was used (as by npm): "+strings.Join(diff, " "))
	}
}

func devIf(m map[string]string, include bool) map[string]string {
	if include {
		return m
	}
	return nil
}

// pruneUnreachable keeps only nodes reachable from the root. In
// package-lock.json the extraneous entries are attached to the root before
// (attachExtraneous), so what is pruned here are the entries outside the
// selected scopes (development dependencies with --runtime-only) and, in
// yarn.lock, entries that yarn does not install because nothing resolves to
// them.
func pruneUnreachable(g *model.Graph) {
	var stale []string
	for id, c := range g.Nodes {
		if c.Depth < 0 {
			stale = append(stale, id)
		}
	}
	if len(stale) == 0 {
		return
	}
	sort.Strings(stale)
	for _, id := range stale {
		delete(g.Nodes, id)
		delete(g.Out, id)
	}
	g.Notes = append(g.Notes, fmt.Sprintf("lockfile contains %d entries not reachable from the selected dependencies (outside the selected scopes or not installed)", len(stale)))
}

// missingDeps collects dependencies that a lockfile should lock but has no
// entry for. npm ci, yarn --frozen-lockfile and pnpm --frozen-lockfile refuse
// such a lockfile; ssca cannot see what would be installed instead, so the
// analysis is incomplete. Optional dependencies may be missing (lockfiles
// written on one platform can leave out the packages of another one), and
// peer dependencies are not checked.
//
// The same holds for a direct dependency that the lockfile locks outside the
// range of package.json (npm ci: "package.json and package-lock.json are not
// in sync"; pnpm --frozen-lockfile compares the specifiers) and for a link
// entry that points to nothing the lockfile describes.
type missingDeps struct {
	file  string
	seen  map[string]bool
	wrong map[string]bool
	links map[string]bool
}

func newMissing(file string) *missingDeps {
	return &missingDeps{file: file, seen: map[string]bool{}, wrong: map[string]bool{}, links: map[string]bool{}}
}

func (md *missingDeps) add(name, rng, from string) {
	md.seen[name+"@"+rng+" (required by "+from+")"] = true
}

// checkRange records a direct dependency whose locked version is outside the
// SemVer range of package.json. Tags, aliases, git, file, link and workspace
// references, URLs and GitHub shorthands are not ranges and are not checked.
func (md *missingDeps) checkRange(name, rng, locked string) {
	r := strings.TrimSpace(rng)
	if r == "" || r == "*" || strings.EqualFold(r, "x") || strings.ContainsAny(r, ":/#") {
		return
	}
	if _, err := semver.NewConstraint(r); err != nil {
		return
	}
	if !Satisfies(locked, r) {
		md.wrong[fmt.Sprintf("%s@%s (package.json: %s)", name, locked, r)] = true
	}
}

// checkSpecifier records a direct dependency whose specifier in the pnpm
// lockfile differs from package.json.
func (md *missingDeps) checkSpecifier(name, spec, locked string) {
	if locked != "" && strings.TrimSpace(spec) != strings.TrimSpace(locked) {
		md.wrong[fmt.Sprintf("%s (lockfile: %s, package.json: %s)", name, locked, spec)] = true
	}
}

func (md *missingDeps) badLink(path, target, name string) {
	k := path + " -> " + target
	switch {
	case target == "":
		k = path + " (no target)"
	case name != "":
		k += " (package " + name + ")"
	}
	md.links[k] = true
}

func (md *missingDeps) report(g *model.Graph) {
	list := func(m map[string]bool) string {
		l := make([]string, 0, len(m))
		for k := range m {
			l = append(l, k)
		}
		sort.Strings(l)
		more := ""
		if len(l) > 5 {
			more = fmt.Sprintf(", … %d more", len(l)-5)
			l = l[:5]
		}
		return strings.Join(l, ", ") + more
	}
	count := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	if len(md.seen) > 0 {
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s is out of sync: %s no lockfile entry: %s",
			md.file, count(len(md.seen), "required dependency has", "required dependencies have"), list(md.seen)))
	}
	if len(md.wrong) > 0 {
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s is out of sync: %s not locked as package.json requires: %s",
			md.file, count(len(md.wrong), "direct dependency is", "direct dependencies are"), list(md.wrong)))
	}
	if len(md.links) > 0 {
		g.Incomplete = append(g.Incomplete, fmt.Sprintf("%s: %s to a folder that the lockfile does not describe, so the linked code is not analysed: %s",
			md.file, count(len(md.links), "link entry points", "link entries point"), list(md.links)))
	}
}

// sortedKeys2 returns the paths of a package-lock packages map in order.
func sortedKeys2(m map[string]lockPkg) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedKeys returns the keys of a dependency list in order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func licenseList(v any) []string {
	switch x := v.(type) {
	case string:
		if x != "" {
			return []string{x}
		}
	case map[string]any:
		if t, ok := x["type"].(string); ok {
			return []string{t}
		}
	}
	return nil
}

// ---------------------------------------------------------------- yarn.lock

type yarnEntry struct {
	specs     []string
	version   string
	resolved  string
	integrity string
	deps      map[string]string
	optional  map[string]bool // deps that are optional dependencies
}

// parseYarnLock reads yarn v1 lockfiles and yarn berry (v2+) YAML lockfiles.
func parseYarnLock(file string, m *manifest, includeDev bool) (*model.Graph, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var entries []*yarnEntry
	soft := map[string]bool{} // specs of workspaces and links (no package to analyse)
	if strings.Contains(string(b), "__metadata:") {
		entries, err = parseYarnBerry(b, soft)
	} else {
		entries, err = parseYarnV1(string(b))
	}
	if err != nil {
		return nil, err
	}
	members := map[string]bool{}
	for _, wm := range m.members {
		members[wm.Name] = true
	}
	// a dependency on a workspace member or a link has no package entry
	localProto := func(rng string) bool {
		for _, proto := range []string{"workspace:", "link:", "portal:"} {
			if strings.HasPrefix(rng, proto) {
				return true
			}
		}
		return false
	}
	local := func(name, rng string) bool {
		if localProto(rng) || members[name] || soft[name+"@"+rng] {
			return true
		}
		// the resolutions field may replace the dependency by a local
		// package ("parent/x": "link:./empty")
		for _, k := range resolutionKeys(name, rng) {
			if r, ok := m.Resolutions[k]; ok {
				return localProto(r)
			}
		}
		for k, r := range m.Resolutions {
			if strings.HasSuffix(k, "/"+name) && localProto(r) {
				return true
			}
		}
		return false
	}
	md := newMissing("yarn.lock")
	bySpec := map[string]*yarnEntry{}
	for _, e := range entries {
		for _, s := range e.specs {
			bySpec[s] = e
		}
	}
	// the key of a patched package names the workspace that declared the
	// patch ("x@patch:x@npm%3A1.0.0#./p.patch::locator=root%40workspace%3A."),
	// while the resolutions field and package.json write the descriptor
	// without it
	for _, e := range entries {
		for _, s := range e.specs {
			if i := strings.Index(s, "::locator="); i > 0 && bySpec[s[:i]] == nil {
				bySpec[s[:i]] = e
			}
		}
	}
	g := model.NewGraph(rootComponent(m))
	g.Inputs = []string{filepath.Base(file)}
	ids := map[*yarnEntry]string{}
	nameOf := func(spec string) string {
		// alias "codemirror5@npm:codemirror@^5.65": the key name is the alias;
		// a patched package "x@patch:x@npm%3A1.0.0#./p.patch" is named x
		for _, proto := range []string{"@npm:", "@patch:"} {
			if j := strings.Index(spec, proto); j > 0 {
				return spec[:j]
			}
		}
		i := strings.LastIndex(spec, "@")
		if i <= 0 {
			return spec
		}
		return spec[:i]
	}
	node := func(e *yarnEntry) string {
		if id, ok := ids[e]; ok {
			return id
		}
		name := nameOf(e.specs[0])
		if r := e.specs[0][len(name)+1:]; strings.HasPrefix(r, "npm:") && strings.Contains(r[4:], "@") {
			real := r[4:]
			name = real[:strings.LastIndex(real, "@")]
		}
		c := npmComponent(name, e.version)
		c.Resolved, c.Source = e.resolved, "yarn.lock"
		if e.integrity != "" {
			c.Integrity = []string{e.integrity}
		} else if h := yarnSHA1(e.resolved); h != "" {
			c.Integrity = []string{h}
		}
		id := addNode(g, c).PURL
		ids[e] = id
		return id
	}
	lookup := func(name, rng string) *yarnEntry {
		// the keys are trimmed, a range may keep a trailing space ("npm:^3.1.0 ")
		rng = strings.TrimSpace(rng)
		for _, s := range []string{name + "@" + rng, name + "@npm:" + rng} {
			if e, ok := bySpec[s]; ok {
				return e
			}
		}
		return nil
	}
	// the "resolutions" field of package.json replaces the range of a
	// dependency ("x", "x@^1", "**/x", "parent/x"); the lockfile then records
	// the replacement
	catalogs := yarnCatalogs(filepath.Dir(file))
	byName := map[string][]*yarnEntry{}
	for _, e := range entries {
		n := nameOf(e.specs[0])
		if !slices.Contains(byName[n], e) {
			byName[n] = append(byName[n], e)
		}
	}
	find := func(name, rng string) *yarnEntry {
		if e := lookup(name, rng); e != nil {
			return e
		}
		// yarn 4 catalogs: "catalog:" and "catalog:<name>" take the range
		// from .yarnrc.yml; without it, the only entry of that name is used
		if c, ok := strings.CutPrefix(rng, "catalog:"); ok {
			if r, ok := catalogs[c][name]; ok {
				return lookup(name, r)
			}
			if es := byName[name]; len(es) == 1 {
				return es[0]
			}
			return nil
		}
		for _, k := range resolutionKeys(name, rng) {
			if r, ok := m.Resolutions[k]; ok {
				return lookup(name, r)
			}
		}
		for k, r := range m.Resolutions {
			if strings.HasSuffix(k, "/"+name) {
				if e := lookup(name, r); e != nil {
					return e
				}
			}
		}
		return nil
	}
	var q []*yarnEntry
	addRoot := func(deps map[string]string, s model.Scope) {
		for name, rng := range deps {
			if e := find(name, rng); e != nil {
				g.AddEdge(model.Edge{From: g.Root, To: node(e), Range: rng, Scope: s})
				q = append(q, e)
			} else if s != model.ScopeOptional && !local(name, rng) {
				md.add(name, rng, "package.json")
			}
		}
	}
	for _, wm := range append([]*manifest{m}, m.members...) {
		addRoot(wm.Dependencies, model.ScopeRuntime)
		addRoot(wm.OptionalDependencies, model.ScopeOptional)
		if includeDev {
			addRoot(wm.DevDependencies, model.ScopeDev)
		}
	}
	seen := map[*yarnEntry]bool{}
	for len(q) > 0 {
		e := q[0]
		q = q[1:]
		if seen[e] {
			continue
		}
		seen[e] = true
		from := node(e)
		for name, rng := range e.deps {
			if ch := find(name, rng); ch != nil {
				g.AddEdge(model.Edge{From: from, To: node(ch), Range: rng})
				q = append(q, ch)
			} else if !e.optional[name] && !local(name, rng) {
				md.add(name, rng, strings.TrimPrefix(from, "pkg:npm/"))
			}
		}
	}
	md.report(g)
	// yarn.lock records no scopes: a package is runtime if a runtime
	// dependency of the project needs it, otherwise optional or dev
	g.PropagateScopes()
	g.ComputeDepths()
	pruneUnreachable(g)
	return g, nil
}

// resolutionKeys lists the keys of the "resolutions" field that apply to a
// dependency, most specific first; yarn 4 also writes the protocol
// ("x@npm:^1.0.0").
func resolutionKeys(name, rng string) []string {
	bare := strings.TrimPrefix(strings.TrimSpace(rng), "npm:")
	return []string{name + "@" + bare, name + "@npm:" + bare, name + "@" + rng, name, "**/" + name}
}

// yarnCatalogs reads the dependency catalogs of yarn 4 from .yarnrc.yml:
// "catalog" is the default one (key ""), "catalogs" the named ones.
func yarnCatalogs(dir string) map[string]map[string]string {
	out := map[string]map[string]string{}
	b, err := os.ReadFile(filepath.Join(dir, ".yarnrc.yml"))
	if err != nil {
		return out
	}
	var rc struct {
		Catalog  map[string]string            `yaml:"catalog"`
		Catalogs map[string]map[string]string `yaml:"catalogs"`
	}
	if yaml.Unmarshal(b, &rc) != nil {
		return out
	}
	for k, v := range rc.Catalogs {
		out[k] = v
	}
	if rc.Catalog != nil {
		out[""] = rc.Catalog
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ":")
	return strings.Trim(s, `"`)
}

func parseYarnV1(src string) ([]*yarnEntry, error) {
	var out []*yarnEntry
	var cur *yarnEntry
	inDeps, inOpt := false, false
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		t := strings.TrimSpace(line)
		switch {
		case indent == 0:
			// an entry header lists the specs it resolves: a@^1, "b@~2":
			if !strings.HasSuffix(t, ":") || strings.ContainsAny(t, "{}[]") {
				return nil, fmt.Errorf("yarn.lock: line %d: not a yarn lockfile entry: %.60q", n, t)
			}
			if cur != nil && cur.version == "" {
				return nil, fmt.Errorf("yarn.lock: entry %s has no version", strings.Join(cur.specs, ", "))
			}
			cur = &yarnEntry{deps: map[string]string{}, optional: map[string]bool{}}
			for _, s := range strings.Split(strings.TrimSuffix(t, ":"), ",") {
				cur.specs = append(cur.specs, unquote(s))
			}
			out = append(out, cur)
			inDeps = false
		case indent == 2 && cur != nil:
			inDeps, inOpt = false, false
			k, v, _ := strings.Cut(t, " ")
			v = unquote(v)
			switch k {
			case "version":
				cur.version = v
			case "resolved":
				cur.resolved = v
			case "integrity":
				cur.integrity = v
			case "dependencies:", "optionalDependencies:":
				inDeps, inOpt = true, k == "optionalDependencies:"
			}
		case indent >= 4 && cur != nil && inDeps:
			k, v, _ := strings.Cut(t, " ")
			cur.deps[unquote(k)] = unquote(v)
			if inOpt {
				cur.optional[unquote(k)] = true
			}
		case cur == nil:
			return nil, fmt.Errorf("yarn.lock: line %d: indented text before the first entry", n)
		}
	}
	if cur != nil && cur.version == "" {
		return nil, fmt.Errorf("yarn.lock: entry %s has no version", strings.Join(cur.specs, ", "))
	}
	return out, sc.Err()
}

func parseYarnBerry(b []byte, soft map[string]bool) ([]*yarnEntry, error) {
	var raw map[string]struct {
		Version          string            `yaml:"version"`
		Resolution       string            `yaml:"resolution"`
		Dependencies     map[string]string `yaml:"dependencies"`
		DependenciesMeta map[string]struct {
			Optional bool `yaml:"optional"`
		} `yaml:"dependenciesMeta"`
		LinkType string `yaml:"linkType"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("yarn.lock: %w", err)
	}
	var out []*yarnEntry
	for k, v := range raw {
		if k == "__metadata" {
			continue
		}
		if v.LinkType == "soft" {
			for _, s := range strings.Split(k, ",") {
				soft[strings.TrimSpace(s)] = true
			}
			continue
		}
		e := &yarnEntry{version: v.Version, resolved: berrySource(v.Resolution), deps: map[string]string{}, optional: map[string]bool{}}
		for _, s := range strings.Split(k, ",") {
			e.specs = append(e.specs, strings.TrimSpace(s))
		}
		for n, r := range v.Dependencies {
			e.deps[n] = r
			e.optional[n] = v.DependenciesMeta[n].Optional
		}
		out = append(out, e)
	}
	return out, nil
}

// ---------------------------------------------------------------- pnpm-lock.yaml

type pnpmDepRef struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type pnpmImporter struct {
	Dependencies         map[string]yaml.Node `yaml:"dependencies"`
	DevDependencies      map[string]yaml.Node `yaml:"devDependencies"`
	OptionalDependencies map[string]yaml.Node `yaml:"optionalDependencies"`
}

type pnpmPkg struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Repo      string `yaml:"repo"`      // type: git
		Commit    string `yaml:"commit"`    // type: git
		Directory string `yaml:"directory"` // type: directory
	} `yaml:"resolution"`
	Name                 string            `yaml:"name"`
	Version              string            `yaml:"version"`
	Dev                  *bool             `yaml:"dev"`
	Optional             bool              `yaml:"optional"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Overrides       map[string]string       `yaml:"overrides"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	pnpmImporter    `yaml:",inline"`
	Packages        map[string]pnpmPkg `yaml:"packages"`
	Snapshots       map[string]pnpmPkg `yaml:"snapshots"`
}

func depVersion(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var r pnpmDepRef
	_ = n.Decode(&r)
	return r.Version
}

// overrideTarget returns the package that a pnpm override selector names:
// "a", "@s/a", "a@<2", "parent>a", "parent@1>@s/a@^3" -> the last name.
func overrideTarget(sel string) string {
	// a ">" that separates parent and child is followed by a name, one in a
	// version range (">=1", "> 2") by "=", a digit or a space
	for i := len(sel) - 2; i >= 0; i-- {
		if c := sel[i+1]; sel[i] == '>' && c != '=' && c != ' ' && (c < '0' || c > '9') {
			sel = sel[i+1:]
			break
		}
	}
	if i := strings.Index(sel[min(1, len(sel)):], "@"); i >= 0 {
		sel = sel[:i+min(1, len(sel))]
	}
	return strings.TrimSpace(sel)
}

// depSpecifier returns the specifier that pnpm recorded for a dependency of
// an importer (lockfile 6 and later; older lockfiles keep it elsewhere and
// give "").
func depSpecifier(n yaml.Node) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	var r pnpmDepRef
	_ = n.Decode(&r)
	return r.Specifier
}

// stripPeers turns "1.2.3(react@18.2.0)" into "1.2.3".
func stripPeers(v string) string {
	if i := strings.Index(v, "("); i >= 0 {
		return v[:i]
	}
	return v
}

func parsePnpmLock(file string, m *manifest, includeDev bool) (*model.Graph, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	// pnpm 10+ writes two YAML documents: the lockfile of pnpm itself and the
	// project lockfile. All documents are merged; the last one wins.
	lf := pnpmLock{Importers: map[string]pnpmImporter{}, Packages: map[string]pnpmPkg{}, Snapshots: map[string]pnpmPkg{}}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var doc pnpmLock
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("pnpm-lock.yaml: %w", err)
		}
		if doc.LockfileVersion != nil {
			lf.LockfileVersion = doc.LockfileVersion
		}
		for k, v := range doc.Importers {
			lf.Importers[k] = v
		}
		for k, v := range doc.Overrides {
			if lf.Overrides == nil {
				lf.Overrides = map[string]string{}
			}
			lf.Overrides[k] = v
		}
		for k, v := range doc.Packages {
			lf.Packages[k] = v
		}
		for k, v := range doc.Snapshots {
			lf.Snapshots[k] = v
		}
		if len(doc.Dependencies)+len(doc.DevDependencies)+len(doc.OptionalDependencies) > 0 {
			lf.pnpmImporter = doc.pnpmImporter
		}
	}
	major := 5
	if s := fmt.Sprint(lf.LockfileVersion); s != "" {
		fmt.Sscanf(strings.Trim(s, "'"), "%d", &major)
	}
	g := model.NewGraph(rootComponent(m))
	g.Inputs = []string{filepath.Base(file)}

	// key for a dependency reference
	keyOf := func(name, ver string) string {
		if strings.HasPrefix(ver, "link:") || strings.HasPrefix(ver, "file:") {
			return ""
		}
		if strings.HasPrefix(ver, "/") { // already a key (v5/v6 alias)
			return ver
		}
		switch {
		case major >= 9:
			if strings.LastIndex(stripPeers(ver), "@") > 0 { // alias "real@1.0.0"
				return ver
			}
			return name + "@" + ver
		case major == 6:
			return "/" + name + "@" + ver
		default:
			return "/" + name + "/" + ver
		}
	}
	parseKey := func(k string) (string, string) {
		k = strings.TrimPrefix(k, "/")
		k = stripPeers(k)
		if major >= 6 {
			i := strings.LastIndex(k, "@")
			if i > 0 {
				return k[:i], k[i+1:]
			}
		}
		i := strings.LastIndex(k, "/")
		if i > 0 {
			return k[:i], k[i+1:]
		}
		return k, ""
	}
	pkgInfo := func(k string) (pnpmPkg, pnpmPkg) {
		base := k
		if major >= 9 {
			base = stripPeers(k)
		}
		p := lf.Packages[base]
		s, ok := lf.Snapshots[k]
		if !ok {
			s = lf.Packages[k]
		}
		return p, s
	}
	ids := map[string]string{}
	node := func(k string) string {
		if id, ok := ids[k]; ok {
			return id
		}
		p, _ := pkgInfo(k)
		name, ver := parseKey(k)
		if p.Name != "" {
			name = p.Name
		}
		if p.Version != "" {
			ver = p.Version
		}
		c := npmComponent(name, ver)
		c.Source = "pnpm-lock.yaml"
		switch r := p.Resolution; {
		case r.Tarball != "":
			c.Resolved = r.Tarball
		case r.Repo != "":
			c.Resolved = "git+" + r.Repo + "#" + r.Commit
		case r.Directory != "":
			c.Resolved = "file:" + r.Directory
		}
		if p.Resolution.Integrity != "" {
			c.Integrity = []string{p.Resolution.Integrity}
		}
		if p.Dev != nil && *p.Dev {
			c.Scope = model.ScopeDev
		}
		id := addNode(g, c).PURL
		ids[k] = id
		return id
	}
	var q []string
	importers := lf.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": lf.pnpmImporter}
	}
	md := newMissing("pnpm-lock.yaml")
	overridden := map[string]bool{}
	for k := range lf.Overrides {
		overridden[overrideTarget(k)] = true
	}
	// package.json must agree with the project's importer
	if root, ok := importers["."]; ok {
		for _, l := range []map[string]string{m.Dependencies, devIf(m.DevDependencies, includeDev)} {
			for _, n := range sortedKeys(l) {
				ra, a := root.Dependencies[n]
				rb, b := root.DevDependencies[n]
				rc, c := root.OptionalDependencies[n]
				_, opt := m.OptionalDependencies[n]
				if !a && !b && !c && !opt {
					md.add(n, l[n], "package.json")
				}
				for _, x := range []struct {
					n  yaml.Node
					ok bool
				}{{ra, a}, {rb, b}, {rc, c}} {
					// pnpm writes the specifier of an override ("overrides"
					// of package.json or pnpm-workspace.yaml) and records the
					// overrides in the lockfile, which keeps it in sync
					if x.ok && !overridden[n] {
						md.checkSpecifier(n, l[n], depSpecifier(x.n))
					}
				}
			}
		}
	}
	for _, imp := range importers {
		lists := []struct {
			m map[string]yaml.Node
			s model.Scope
		}{{imp.Dependencies, model.ScopeRuntime}, {imp.OptionalDependencies, model.ScopeOptional}}
		if includeDev {
			lists = append(lists, struct {
				m map[string]yaml.Node
				s model.Scope
			}{imp.DevDependencies, model.ScopeDev})
		}
		for _, l := range lists {
			for name, ref := range l.m {
				k := keyOf(name, depVersion(ref))
				if k == "" {
					continue
				}
				if !pnpmKnown(lf, k) {
					if l.s != model.ScopeOptional {
						md.add(name, depVersion(ref), "package.json")
					}
					continue
				}
				id := node(k)
				g.Nodes[id].Scope = minScope(g.Nodes[id].Scope, l.s)
				g.AddEdge(model.Edge{From: g.Root, To: id, Scope: l.s})
				q = append(q, k)
			}
		}
	}
	seen := map[string]bool{}
	for len(q) > 0 {
		k := q[0]
		q = q[1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		_, s := pkgInfo(k)
		for i, deps := range []map[string]string{s.Dependencies, s.OptionalDependencies} {
			for name, ver := range deps {
				ck := keyOf(name, ver)
				if ck == "" {
					continue
				}
				if !pnpmKnown(lf, ck) {
					if i == 0 {
						md.add(name, ver, strings.TrimPrefix(node(k), "pkg:npm/"))
					}
					continue
				}
				g.AddEdge(model.Edge{From: node(k), To: node(ck)})
				q = append(q, ck)
			}
		}
	}
	md.report(g)
	g.PropagateScopes()
	g.ComputeDepths()
	return g, nil
}

func minScope(a, b model.Scope) model.Scope {
	if model.ScopeRank(b) < model.ScopeRank(a) {
		return b
	}
	return a
}

func pnpmKnown(lf pnpmLock, k string) bool {
	if _, ok := lf.Snapshots[k]; ok {
		return true
	}
	if _, ok := lf.Packages[k]; ok {
		return true
	}
	_, ok := lf.Packages[stripPeers(k)]
	return ok
}
