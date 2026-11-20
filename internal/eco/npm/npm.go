package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/resolve"
)

// Registry is the default public npm registry.
var Registry = "https://registry.npmjs.org"

// DownloadsAPI is the npm downloads API (last-month point counts).
var DownloadsAPI = "https://api.npmjs.org/downloads/point/last-month/"

// Plugin implements common.Plugin for npm.
type Plugin struct{}

func (Plugin) Name() string { return model.NPM }

func (Plugin) Detect(dir string) []string {
	var out []string
	for _, f := range []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if common.Exists(dir, f) {
			out = append(out, f)
		}
	}
	if len(out) > 0 && !common.Exists(dir, "package.json") {
		return nil
	}
	return out
}

func (Plugin) Load(ctx context.Context, dir string, opt common.Options) (*model.Graph, error) {
	m, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	if !opt.ForceResolve {
		for _, lf := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
			if common.Exists(dir, lf) {
				return parsePackageLock(filepath.Join(dir, lf), m, opt.IncludeDev)
			}
		}
		if common.Exists(dir, "pnpm-lock.yaml") {
			return parsePnpmLock(filepath.Join(dir, "pnpm-lock.yaml"), m, opt.IncludeDev)
		}
		if common.Exists(dir, "yarn.lock") {
			return parseYarnLock(filepath.Join(dir, "yarn.lock"), m, opt.IncludeDev)
		}
	}
	var deps []resolve.Dep
	add := func(mm map[string]string, s model.Scope) {
		names := make([]string, 0, len(mm))
		for n := range mm {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			deps = append(deps, resolve.Dep{Name: n, Range: mm[n], Scope: s})
		}
	}
	add(m.Dependencies, model.ScopeRuntime)
	add(m.OptionalDependencies, model.ScopeOptional)
	if opt.IncludeDev {
		add(m.DevDependencies, model.ScopeDev)
	}
	if len(deps) == 0 {
		// nothing to install (e.g. a package.json that only configures
		// development tools): the empty graph is exact
		g := model.NewGraph(rootComponent(m))
		g.Inputs = []string{"package.json"}
		return g, nil
	}
	if opt.Net == nil {
		return nil, fmt.Errorf("no lockfile and no network access for resolution")
	}
	src := &source{reg: NewRegistry(opt.Net)}
	g, err := resolve.Resolve(ctx, src, rootComponent(m), deps, 1)
	if err != nil {
		return nil, err
	}
	g.Inputs = []string{"package.json"}
	g.Incomplete = append(g.Incomplete, "npm graph resolved without a lockfile; hoisting may differ from npm install")
	return g, nil
}

// Compare orders SemVer versions; unparsable versions sort lexically.
func Compare(a, b string) int {
	va, ea := semver.NewVersion(a)
	vb, eb := semver.NewVersion(b)
	if ea != nil || eb != nil {
		return strings.Compare(a, b)
	}
	return va.Compare(vb)
}

var rangeCache sync.Map

// Satisfies reports whether version v is inside the npm range r.
func Satisfies(v, r string) bool {
	r = strings.TrimSpace(r)
	if r == "" || r == "*" || r == "latest" || r == "x" {
		r = "*"
	}
	if strings.HasPrefix(r, "npm:") {
		if i := strings.LastIndex(r, "@"); i > 0 {
			r = r[i+1:]
		}
	}
	var c *semver.Constraints
	if x, ok := rangeCache.Load(r); ok {
		c = x.(*semver.Constraints)
	} else {
		var err error
		c, err = semver.NewConstraint(r)
		if err != nil {
			return false
		}
		rangeCache.Store(r, c)
	}
	sv, err := semver.NewVersion(v)
	if err != nil {
		return false
	}
	if sv.Prerelease() != "" && r == "*" {
		return false
	}
	return c.Check(sv)
}

// ---------------------------------------------------------------- registry

// VersionDoc is the per-version document of the npm registry.
type VersionDoc struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
	Scripts     map[string]string `json:"scripts"`
	HasInstall  bool              `json:"hasInstallScript"`
	Deprecated  any               `json:"deprecated"`
	License     any               `json:"license"`
	Repository  any               `json:"repository"`
	Author      any               `json:"author"`
	NpmUser     *person           `json:"_npmUser"`
	Maintainers []person          `json:"maintainers"`
	Dist        struct {
		Integrity    string `json:"integrity"`
		Shasum       string `json:"shasum"`
		Tarball      string `json:"tarball"`
		Attestations *struct {
			URL        string `json:"url"`
			Provenance struct {
				PredicateType string `json:"predicateType"`
			} `json:"provenance"`
		} `json:"attestations"`
		Signatures []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	} `json:"dist"`
}

type person struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Packument is the abbreviated package document.
type Packument struct {
	Name     string                `json:"name"`
	Versions map[string]VersionDoc `json:"versions"`
	DistTags map[string]string     `json:"dist-tags"`
	Time     map[string]string     `json:"time"`
}

// RegistryClient fetches npm registry metadata.
type RegistryClient struct {
	Net  *netx.Client
	Base string
}

// NewRegistry returns a client for the public registry.
func NewRegistry(n *netx.Client) *RegistryClient { return &RegistryClient{Net: n, Base: Registry} }

func escape(name string) string {
	return strings.Replace(url.PathEscape(name), "%40", "@", 1)
}

// Packument returns the abbreviated (install) package document.
func (r *RegistryClient) Packument(ctx context.Context, name string) (*Packument, error) {
	b, err := r.Net.Get(ctx, r.Base+"/"+escape(name), "application/vnd.npm.install-v1+json")
	if err != nil {
		return nil, err
	}
	var p Packument
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("packument %s: %w", name, err)
	}
	return &p, nil
}

// Version returns the full per-version document.
func (r *RegistryClient) Version(ctx context.Context, name, version string) (*VersionDoc, error) {
	var d VersionDoc
	if err := r.Net.GetJSON(ctx, r.Base+"/"+escape(name)+"/"+url.PathEscape(version), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Times returns the publication time of every version and the "created"
// entry from the full package document; the abbreviated document has no
// times. It is the registry's own record, available as soon as a version is
// published, before indexes such as deps.dev have ingested it.
func (r *RegistryClient) Times(ctx context.Context, name string) (map[string]time.Time, error) {
	var d struct {
		Time map[string]string `json:"time"`
	}
	if err := r.Net.GetJSON(ctx, r.Base+"/"+escape(name), &d); err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for k, v := range d.Time {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			out[k] = t
		}
	}
	return out, nil
}

// Attestations returns the raw attestation bundle list of a version.
func (r *RegistryClient) Attestations(ctx context.Context, name, version string) ([]byte, error) {
	return r.Net.Get(ctx, r.Base+"/-/npm/v1/attestations/"+escape(name)+"@"+url.PathEscape(version), "application/json")
}

// Downloads returns last-month downloads from the npm downloads API.
func (r *RegistryClient) Downloads(ctx context.Context, name string) (int64, error) {
	var out struct {
		Downloads int64 `json:"downloads"`
	}
	err := r.Net.GetJSON(ctx, DownloadsAPI+escape(name), &out)
	return out.Downloads, err
}

// InstallScripts lists the install-time lifecycle scripts of a version.
func (d *VersionDoc) InstallScripts() []string {
	var out []string
	// "prepare" is not listed: npm runs it only for git dependencies and in
	// the package's own checkout, not when a published tarball is installed
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if s, ok := d.Scripts[k]; ok && s != "" {
			out = append(out, k+": "+s)
		}
	}
	return out
}

// AuthorField returns the "author" of the manifest, which is a string or an
// object with a name.
func (d *VersionDoc) AuthorField() string {
	switch a := d.Author.(type) {
	case string:
		return a
	case map[string]any:
		s, _ := a["name"].(string)
		return s
	}
	return ""
}

// RepoURL extracts the source repository URL.
func (d *VersionDoc) RepoURL() string {
	switch x := d.Repository.(type) {
	case string:
		return x
	case map[string]any:
		if u, ok := x["url"].(string); ok {
			return u
		}
	}
	return ""
}

// ---------------------------------------------------------------- resolver source

type source struct {
	reg *RegistryClient
}

func (s *source) Rule() resolve.Rule { return resolve.NPMDedupe }
func (s *source) Normalise(n string) string {
	return n
}

func (s *source) Versions(ctx context.Context, name string) ([]string, error) {
	p, err := s.reg.Packument(ctx, name)
	if err != nil {
		return nil, err
	}
	vs := make([]string, 0, len(p.Versions))
	for v := range p.Versions {
		if _, err := semver.NewVersion(v); err == nil {
			vs = append(vs, v)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return Compare(vs[i], vs[j]) < 0 })
	return vs, nil
}

func (s *source) Deps(ctx context.Context, name, version string, _ []string) ([]resolve.Dep, error) {
	p, err := s.reg.Packument(ctx, name)
	if err != nil {
		return nil, err
	}
	d, ok := p.Versions[version]
	if !ok {
		return nil, fmt.Errorf("version %s not in packument", version)
	}
	var out []resolve.Dep
	add := func(m map[string]string, sc model.Scope, opt bool) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, resolve.Dep{Name: n, Range: m[n], Scope: sc, Optional: opt})
		}
	}
	add(d.Dependencies, model.ScopeRuntime, false)
	add(d.OptionalDependencies, model.ScopeOptional, true)
	peers := map[string]string{}
	for n, r := range d.PeerDependencies {
		if !d.PeerDependenciesMeta[n].Optional {
			peers[n] = r
		}
	}
	add(peers, model.ScopeRuntime, false)
	return out, nil
}

func (s *source) Satisfies(v, r string) bool { return Satisfies(v, r) }

func (s *source) Pinned(r string) (string, bool) {
	if _, err := semver.StrictNewVersion(strings.TrimPrefix(r, "=")); err == nil {
		return strings.TrimPrefix(r, "="), true
	}
	return "", false
}

func (s *source) MarkerApplies(d resolve.Dep) bool {
	r := d.Range
	return !(strings.HasPrefix(r, "file:") || strings.HasPrefix(r, "link:") || strings.HasPrefix(r, "git") ||
		strings.HasPrefix(r, "http") || strings.HasPrefix(r, "workspace:") || strings.Contains(r, "/") && !strings.HasPrefix(r, "npm:"))
}

func (s *source) Component(name, version string) *model.Component { return npmComponent(name, version) }

func (s *source) Transitive(parent model.Scope, d resolve.Dep, depth int) (model.Scope, bool) {
	if parent == model.ScopeDev {
		return model.ScopeDev, true
	}
	if d.Optional {
		return model.ScopeOptional, true
	}
	return parent, true
}

func (s *source) Managed(string) (string, model.Scope, bool) { return "", "", false }
