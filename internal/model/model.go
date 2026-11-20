// Package model defines the shared data model of the suite: the component
// graph produced by M0 and the findings written by modules M1–M5.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// HomeURL is the home page of the suite, named in the SARIF reports and in
// the User-Agent of its requests.
const HomeURL = "https://github.com/Vlad-Mirzoian/supply-chain-audit"

// Ecosystem identifiers used throughout the suite (purl types).
const (
	NPM   = "npm"
	PyPI  = "pypi"
	Maven = "maven"
)

// Scope of a dependency, used for the exposure factor c.
type Scope string

const (
	ScopeRuntime  Scope = "runtime"
	ScopeDev      Scope = "dev" // build-time or development dependency
	ScopeTest     Scope = "test"
	ScopeOptional Scope = "optional"
	ScopeProvided Scope = "provided"
	// ScopeExtra marks the packages of the optional features (extras) of a
	// Python project itself: pip, uv and Poetry install them only on request
	// (pip install project[extra]), unlike npm optionalDependencies, which
	// npm installs by default.
	ScopeExtra Scope = "extra"
)

// ScopeRank orders scopes from the strongest (runtime) to the weakest (test).
// A package reached through several paths takes the strongest scope.
func ScopeRank(s Scope) int {
	switch s {
	case ScopeRuntime, "":
		return 0
	case ScopeOptional:
		return 1
	case ScopeProvided:
		return 2
	case ScopeExtra:
		return 3
	case ScopeDev:
		return 4
	case ScopeTest:
		return 5
	}
	return 6
}

// Production reports whether a package of this scope is part of the shipped
// or deployed application (runtime, optional, provided), as opposed to a
// development, build or test dependency or a package that only an extra of
// the project needs.
func (s Scope) Production() bool { return s != ScopeDev && s != ScopeTest && s != ScopeExtra }

// Component is one node of the dependency graph: a concrete package version.
type Component struct {
	PURL      string `json:"purl"`
	Ecosystem string `json:"ecosystem"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Scope     Scope  `json:"scope"`
	// LockScope is set when the lockfile declares a weaker scope than the
	// dependency lists give (package-lock.json "dev": true on a package that
	// a production package needs); ScopeVia names that production package.
	// Scope holds the derived scope; M3 reports the difference.
	LockScope Scope  `json:"lockfile_scope,omitempty"`
	ScopeVia  string `json:"scope_via,omitempty"`
	// Extraneous marks a package-lock.json entry that no dependency of the
	// project requires. npm ci installs every entry of the lockfile, so the
	// package is analysed (attached to the project) and M3 reports it.
	Extraneous bool `json:"extraneous,omitempty"`
	Direct     bool `json:"direct"`
	Depth      int  `json:"depth"`
	// Integrity is the hash declared by the lockfile, e.g. "sha512-..." (npm SRI)
	// or "sha256:..." (PyPI). Empty for Maven, which has no lockfile.
	Integrity []string `json:"integrity,omitempty"`
	Resolved  string   `json:"resolved,omitempty"` // download URL recorded in the lockfile
	// HashCheck is the outcome of the M3 comparison of Integrity with the
	// registry (integrity.Hash* values).
	HashCheck string   `json:"hash_check,omitempty"`
	Licenses  []string `json:"licenses,omitempty"`
	// Source records which method produced the node (lockfile name or "resolver").
	Source string `json:"source"`
	// Evicted lists versions that lost Maven mediation ("nearest wins").
	Evicted []string `json:"evicted,omitempty"`
	// Meta holds registry metadata collected by M4 (may be nil).
	Meta *PackageMeta `json:"meta,omitempty"`
}

// FullName returns the ecosystem-native package name (npm "@scope/name",
// Maven "group:artifact", PyPI "name").
func (c *Component) FullName() string {
	switch c.Ecosystem {
	case NPM:
		if c.Namespace != "" {
			return c.Namespace + "/" + c.Name
		}
	case Maven:
		return c.Namespace + ":" + c.Name
	}
	return c.Name
}

// PackageMeta is registry metadata used by the health and malice indicators.
type PackageMeta struct {
	// Supplier is the producer declared in the package metadata (npm author,
	// PyPI author or maintainer, Maven organization or developer); it is
	// empty when the metadata names nobody. SupplierOrg says that it is an
	// organization (only the Maven <organization> element states that).
	Supplier    string `json:"supplier,omitempty"`
	SupplierOrg bool   `json:"supplier_org,omitempty"`
	// RepoSHA1 is the SHA-1 published by the Maven repository next to the
	// jar (only collected for sbom --enrich).
	RepoSHA1           string    `json:"repo_sha1,omitempty"`
	PublishedAt        time.Time `json:"published_at,omitempty"`
	LatestReleaseAt    time.Time `json:"latest_release_at,omitempty"`
	FirstReleaseAt     time.Time `json:"first_release_at,omitempty"`
	Releases           int       `json:"releases,omitempty"` // published versions with a release time
	PreviousVersion    string    `json:"previous_version,omitempty"`
	Maintainers        int       `json:"maintainers,omitempty"`
	Publisher          string    `json:"publisher,omitempty"`
	PreviousPublisher  string    `json:"previous_publisher,omitempty"`
	PrevMaintainers    []string  `json:"previous_maintainers,omitempty"`
	InstallScripts     []string  `json:"install_scripts,omitempty"`
	PrevInstallScripts []string  `json:"prev_install_scripts,omitempty"`
	HasProvenance      bool      `json:"has_provenance"`
	PrevHasProvenance  bool      `json:"prev_has_provenance"`
	AnyProvenance      bool      `json:"any_provenance"`
	NewDependencies    []string  `json:"new_dependencies,omitempty"`
	NewDepMinAgeDays   float64   `json:"new_dep_min_age_days,omitempty"`
	Repository         string    `json:"repository,omitempty"`
	Scorecard          float64   `json:"scorecard"` // -1 when unknown
	Downloads          int64     `json:"downloads,omitempty"`
	Deprecated         string    `json:"deprecated,omitempty"`
	RegistryIntegrity  string    `json:"registry_integrity,omitempty"`
	Incomplete         []string  `json:"incomplete,omitempty"`
	// Unavailable lists the metadata sources that could not be read for
	// this package ("deps.dev: <error>"): a network or server error, or a
	// response missing from an offline snapshot. A source that does not
	// know the package ("not found") is not listed.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Edge is a dependency link between two components.
type Edge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Range string `json:"range,omitempty"`
	Scope Scope  `json:"scope,omitempty"`
}

// Conflict is an unsatisfiable or mediated version requirement.
type Conflict struct {
	Name   string `json:"name"`
	Range  string `json:"range"`
	Parent string `json:"parent"`
	Note   string `json:"note"`
}

// Graph is the shared component graph (Section 3.4.1).
type Graph struct {
	Root       string                `json:"root"`
	Nodes      map[string]*Component `json:"nodes"`
	Out        map[string][]Edge     `json:"-"`
	Conflicts  []Conflict            `json:"conflicts,omitempty"`
	Cycles     [][]string            `json:"cycles,omitempty"`
	Incomplete []string              `json:"incomplete,omitempty"`
	// Notes record lockfile drift and unresolved optional dependencies, which
	// do not make the analysis incomplete.
	Notes  []string `json:"notes,omitempty"`
	Inputs []string `json:"inputs"` // project files that were read
	// Repositories are the package repositories that the project files
	// declare (Maven <repositories> and <pluginRepositories>); the package
	// manager downloads from them as well as from the public registry.
	Repositories []Repository `json:"repositories,omitempty"`
}

// Repository is a package repository declared by a project file.
type Repository struct {
	URL        string `json:"url"`
	Plugin     bool   `json:"plugin,omitempty"` // build plugins only (Maven <pluginRepositories>)
	DeclaredIn string `json:"declared_in"`      // the POM (g:a:v) or requirements file that declares it
	// Kind is set for a Python package source: "index-url", "extra-index-url"
	// or "find-links" (the pip option of a requirements file)
	Kind string `json:"kind,omitempty"`
}

// NewGraph creates an empty graph with the given root node.
func NewGraph(root *Component) *Graph {
	g := &Graph{Root: root.PURL, Nodes: map[string]*Component{}, Out: map[string][]Edge{}}
	g.Nodes[root.PURL] = root
	return g
}

// AddNode inserts c if it is new and returns the stored node.
func (g *Graph) AddNode(c *Component) *Component {
	if old, ok := g.Nodes[c.PURL]; ok {
		return old
	}
	g.Nodes[c.PURL] = c
	return c
}

// AddEdge inserts an edge unless one between the same nodes exists. A
// repeated edge in a stronger scope upgrades the scope of the existing one: a
// package that one workspace member lists as a development dependency and
// another as a runtime dependency is a runtime dependency of the project.
func (g *Graph) AddEdge(e Edge) {
	for i, x := range g.Out[e.From] {
		if x.To == e.To {
			if ScopeRank(e.Scope) < ScopeRank(x.Scope) {
				g.Out[e.From][i].Scope = e.Scope
			}
			return
		}
	}
	g.Out[e.From] = append(g.Out[e.From], e)
}

// Components returns all nodes except the root in a stable order.
func (g *Graph) Components() []*Component {
	out := make([]*Component, 0, len(g.Nodes))
	for id, c := range g.Nodes {
		if id != g.Root {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PURL < out[j].PURL })
	return out
}

// EdgeCount returns the number of edges.
func (g *Graph) EdgeCount() int {
	n := 0
	for _, es := range g.Out {
		n += len(es)
	}
	return n
}

// ComputeDepths sets Depth and Direct by breadth-first search from the root.
// A package of a production scope is measured along production dependencies
// only, so that a runtime package that is also listed as a development
// dependency keeps the depth it has in the shipped application; development
// and test packages are measured in the whole graph. A node that cannot be
// reached gets depth -1.
func (g *Graph) ComputeDepths() {
	bfs := func(follow func(from string, e Edge) bool) map[string]int {
		d := map[string]int{g.Root: 0}
		q := []string{g.Root}
		for len(q) > 0 {
			u := q[0]
			q = q[1:]
			for _, e := range g.Out[u] {
				if _, seen := d[e.To]; seen || g.Nodes[e.To] == nil || !follow(u, e) {
					continue
				}
				d[e.To] = d[u] + 1
				q = append(q, e.To)
			}
		}
		return d
	}
	all := bfs(func(string, Edge) bool { return true })
	prod := bfs(func(from string, e Edge) bool {
		if from == g.Root && !e.Scope.Production() {
			return false
		}
		return g.Nodes[e.To].Scope.Production()
	})
	for id, c := range g.Nodes {
		c.Depth = -1
		if d, ok := all[id]; ok {
			c.Depth = d
		}
		if d, ok := prod[id]; ok && c.Scope.Production() {
			c.Depth = d
		}
	}
	for _, c := range g.Nodes {
		c.Direct = c.Depth == 1
	}
}

// PropagateScopes sets the scope of every node reachable from the root: the
// direct dependencies take the scope of their edge from the root (runtime when
// the edge has none) and a package takes the strongest scope of its parents,
// so that it is runtime as soon as one path from the root runs through
// runtime dependencies only. Nodes that cannot be reached keep their scope.
// It is used where the lockfile does not record the scope of every package
// (yarn, pnpm, uv, poetry, Pipfile.lock).
func (g *Graph) PropagateScopes() {
	best := map[string]Scope{}
	var q []string
	for _, e := range g.Out[g.Root] {
		s := e.Scope
		if s == "" {
			s = ScopeRuntime
		}
		if old, ok := best[e.To]; !ok || ScopeRank(s) < ScopeRank(old) {
			best[e.To] = s
			q = append(q, e.To)
		}
	}
	for len(q) > 0 {
		u := q[0]
		q = q[1:]
		for _, e := range g.Out[u] {
			if e.To == g.Root {
				continue
			}
			if old, ok := best[e.To]; !ok || ScopeRank(best[u]) < ScopeRank(old) {
				best[e.To] = best[u]
				q = append(q, e.To)
			}
		}
	}
	for id, s := range best {
		if c := g.Nodes[id]; c != nil {
			c.Scope = s
		}
	}
}

// ProductionView returns the part of g that the application ships: the root,
// the components of a production scope (Scope.Production) and the edges among
// them. Nodes are shared with g. Analyses that only concern shipped code, such
// as reachability, run on it.
func (g *Graph) ProductionView() *Graph {
	v := &Graph{Root: g.Root, Nodes: map[string]*Component{}, Out: map[string][]Edge{},
		Conflicts: g.Conflicts, Cycles: g.Cycles, Incomplete: g.Incomplete, Notes: g.Notes, Inputs: g.Inputs}
	for id, c := range g.Nodes {
		if id == g.Root || c.Scope.Production() {
			v.Nodes[id] = c
		}
	}
	for from, es := range g.Out {
		if v.Nodes[from] == nil {
			continue
		}
		for _, e := range es {
			if from == g.Root && !e.Scope.Production() {
				continue // a development edge to a package that is also needed at runtime
			}
			if v.Nodes[e.To] != nil {
				v.Out[from] = append(v.Out[from], e)
			}
		}
	}
	return v
}

// MakePURL builds a package URL for the three supported ecosystems.
func MakePURL(eco, namespace, name, version string) string {
	var b strings.Builder
	b.WriteString("pkg:" + eco + "/")
	if namespace != "" {
		b.WriteString(strings.ReplaceAll(namespace, "@", "%40") + "/")
	}
	b.WriteString(name)
	if version != "" {
		b.WriteString("@" + version)
	}
	return b.String()
}

// NewComponent creates a component with its purl filled in.
func NewComponent(eco, namespace, name, version string) *Component {
	return &Component{
		PURL: MakePURL(eco, namespace, name, version), Ecosystem: eco,
		Namespace: namespace, Name: name, Version: version, Scope: ScopeRuntime,
	}
}

// SplitNPMName splits "@scope/name" into scope and name.
func SplitNPMName(full string) (string, string) {
	if strings.HasPrefix(full, "@") {
		if i := strings.Index(full, "/"); i > 0 {
			return full[:i], full[i+1:]
		}
	}
	return "", full
}

// FindingKind classifies findings by the module that produced them.
type FindingKind string

const (
	KindVulnerability FindingKind = "vulnerability"
	KindMalicious     FindingKind = "malicious"
	KindIntegrity     FindingKind = "integrity"
	KindProvenance    FindingKind = "provenance"
	KindSignal        FindingKind = "signal"
	KindCI            FindingKind = "ci"
	KindConfusion     FindingKind = "dependency-confusion"
)

// Severity levels used in reports and SARIF.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// Vulnerability holds the enriched data of one advisory for one component.
type Vulnerability struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases,omitempty"`
	Summary    string   `json:"summary,omitempty"`
	CVSS       float64  `json:"cvss"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	EPSS       float64  `json:"epss"`
	KEV        bool     `json:"kev"`
	Fixed      []string `json:"fixed,omitempty"`
	// Reachable is "yes", "no" or "unknown" (package-level import reachability).
	Reachable string `json:"reachable"`
	// VEX status applied to this finding, if any.
	VEXStatus        string `json:"vex_status,omitempty"`
	VEXJustification string `json:"vex_justification,omitempty"`
	LocallyConfirmed bool   `json:"locally_confirmed"`
}

// CVEs returns the CVE identifiers among the ID and aliases.
func (v *Vulnerability) CVEs() []string {
	var out []string
	for _, a := range append([]string{v.ID}, v.Aliases...) {
		if strings.HasPrefix(a, "CVE-") {
			out = append(out, a)
		}
	}
	return out
}

// Finding is one result of an analysis module.
type Finding struct {
	ID         string         `json:"id"`
	Kind       FindingKind    `json:"kind"`
	Rule       string         `json:"rule,omitempty"`
	Component  string         `json:"component,omitempty"` // purl
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail,omitempty"`
	File       string         `json:"file,omitempty"`
	Line       int            `json:"line,omitempty"`
	Vuln       *Vulnerability `json:"vuln,omitempty"`
	Suppressed bool           `json:"suppressed,omitempty"`
	Reason     string         `json:"suppression_reason,omitempty"`
	Module     string         `json:"module"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

// Signal is one malicious-package or health indicator with value in [0,1].
type Signal struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Reason string  `json:"reason"`
}

// Score is the composite risk score with its explanation (Section 3.1.4).
type Score struct {
	PURL      string   `json:"purl"`
	Scope     Scope    `json:"scope"`
	C         float64  `json:"c"`
	V         float64  `json:"v"`
	H         float64  `json:"h"`
	M         float64  `json:"m"`
	CRS       float64  `json:"crs"`
	Band      string   `json:"band"`
	Override  string   `json:"override,omitempty"`
	Signals   []Signal `json:"signals,omitempty"`
	Health    []Signal `json:"health,omitempty"`
	Subtree   float64  `json:"subtree_risk"`
	WorstPath []string `json:"worst_path,omitempty"`
}

// BandOf maps a CRS value to its band (Section 3.1.4).
func BandOf(crs float64) string {
	switch {
	case crs >= 75:
		return SevCritical
	case crs >= 50:
		return SevHigh
	case crs >= 25:
		return SevMedium
	}
	return SevLow
}

// SeverityRank orders severities for sorting and thresholds.
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// String helps debugging.
func (c *Component) String() string {
	return fmt.Sprintf("%s (%s, depth %d)", c.PURL, c.Scope, c.Depth)
}
