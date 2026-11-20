// Package maven is the Maven ecosystem plugin. Maven has no lockfile, so the
// graph is always resolved: the plugin builds the effective POM (parents,
// properties, BOM imports, profiles) and applies "nearest definition wins".
package maven

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Central is the default remote repository.
var Central = "https://repo1.maven.org/maven2"

type props map[string]string

func (p *props) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = props{}
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch x := t.(type) {
		case xml.StartElement:
			var v string
			if err := d.DecodeElement(&v, &x); err != nil {
				return err
			}
			(*p)[x.Name.Local] = strings.TrimSpace(v)
		case xml.EndElement:
			return nil
		}
	}
}

type exclusion struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

type pomDep struct {
	GroupID    string      `xml:"groupId"`
	ArtifactID string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Type       string      `xml:"type"`
	Classifier string      `xml:"classifier"`
	Scope      string      `xml:"scope"`
	Optional   string      `xml:"optional"`
	Exclusions []exclusion `xml:"exclusions>exclusion"`
}

func (d pomDep) key() string {
	t := d.Type
	if t == "" {
		t = "jar"
	}
	return d.GroupID + ":" + d.ArtifactID + ":" + t + ":" + d.Classifier
}

type profile struct {
	ID         string `xml:"id"`
	Activation struct {
		ActiveByDefault string `xml:"activeByDefault"`
		JDK             string `xml:"jdk"`
		Property        *struct {
			Name  string `xml:"name"`
			Value string `xml:"value"`
		} `xml:"property"`
	} `xml:"activation"`
	Properties           props    `xml:"properties"`
	Dependencies         []pomDep `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []pomDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Modules []string `xml:"modules>module"`
}

// POM is the subset of the Maven project model used by the suite.
type POM struct {
	XMLName xml.Name `xml:"project"`
	Parent  *struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	GroupID              string   `xml:"groupId"`
	ArtifactID           string   `xml:"artifactId"`
	Version              string   `xml:"version"`
	Packaging            string   `xml:"packaging"`
	Name                 string   `xml:"name"`
	Organization         string   `xml:"organization>name"`
	Developers           []string `xml:"developers>developer>name"`
	Properties           props    `xml:"properties"`
	Dependencies         []pomDep `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []pomDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Modules  []string  `xml:"modules>module"`
	Profiles []profile `xml:"profiles>profile"`
	Licenses []struct {
		Name string `xml:"name"`
	} `xml:"licenses>license"`
	Repositories []struct {
		URL string `xml:"url"`
	} `xml:"repositories>repository"`
	PluginRepositories []struct {
		URL string `xml:"url"`
	} `xml:"pluginRepositories>pluginRepository"`
	Distribution struct {
		Relocation *struct {
			GroupID    string `xml:"groupId"`
			ArtifactID string `xml:"artifactId"`
			Version    string `xml:"version"`
		} `xml:"relocation"`
	} `xml:"distributionManagement"`
	SCM struct {
		URL string `xml:"url"`
	} `xml:"scm"`
	URL string `xml:"url"`

	dir string // local directory for reactor modules
}

// Effective is the merged and interpolated model of a POM.
type Effective struct {
	GroupID, ArtifactID, Version string
	Packaging                    string
	Props                        map[string]string
	Managed                      []pomDep // dependencyManagement after BOM import
	Deps                         []pomDep
	Licenses                     []string
	Modules                      []string
	Repos                        []string
	RepoDecls                    []model.Repository // Repos and the plugin repositories, with the POM that declares each
	SCM                          string
	Problems                     []string
}

func parsePOM(b []byte) (*POM, error) {
	var p POM
	dec := xml.NewDecoder(strings.NewReader(string(b)))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Repo fetches and caches POMs and metadata from remote repositories.
type Repo struct {
	Net   *netx.Client
	URLs  []string
	mu    sync.Mutex
	poms  map[string]*pomResult
	effs  map[string]*effResult
	local map[string]*POM // reactor modules by g:a:v
}

type pomResult struct {
	once sync.Once
	p    *POM
	err  error
}

type effResult struct {
	once sync.Once
	e    *Effective
	err  error
}

// NewRepo creates a repository client for Maven Central.
func NewRepo(n *netx.Client) *Repo {
	return &Repo{Net: n, URLs: []string{Central}, poms: map[string]*pomResult{}, effs: map[string]*effResult{}, local: map[string]*POM{}}
}

func gav(g, a, v string) string { return g + ":" + a + ":" + v }

// Fetch returns the raw POM of g:a:v.
func (r *Repo) Fetch(ctx context.Context, g, a, v string) (*POM, error) {
	k := gav(g, a, v)
	r.mu.Lock()
	if p, ok := r.local[k]; ok {
		r.mu.Unlock()
		return p, nil
	}
	res, ok := r.poms[k]
	if !ok {
		res = &pomResult{}
		r.poms[k] = res
	}
	r.mu.Unlock()
	res.once.Do(func() {
		path := strings.ReplaceAll(g, ".", "/") + "/" + a + "/" + v + "/" + a + "-" + v + ".pom"
		var lastErr error
		for _, base := range r.URLs {
			b, err := r.Net.Get(ctx, base+"/"+path, "application/xml")
			if err != nil {
				lastErr = err
				continue
			}
			res.p, res.err = parsePOM(b)
			if res.err != nil {
				res.err = fmt.Errorf("%s: %w", k, res.err)
			}
			return
		}
		res.err = fmt.Errorf("POM %s: %w", k, lastErr)
	})
	return res.p, res.err
}

// Versions lists the published versions of g:a from maven-metadata.xml.
func (r *Repo) Versions(ctx context.Context, g, a string) ([]string, error) {
	var md struct {
		Versions []string `xml:"versioning>versions>version"`
	}
	var lastErr error
	for _, base := range r.URLs {
		b, err := r.Net.Get(ctx, base+"/"+strings.ReplaceAll(g, ".", "/")+"/"+a+"/maven-metadata.xml", "application/xml")
		if err != nil {
			lastErr = err
			continue
		}
		if err := xml.Unmarshal(b, &md); err != nil {
			return nil, err
		}
		return md.Versions, nil
	}
	return nil, lastErr
}

var propRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// Supplier returns the producer declared by the POM of a component or by its
// parents: the nearest <organization>, otherwise the nearest developer. The
// second result says that it is an organization. Unresolved "${...}" values
// are not names.
func (r *Repo) Supplier(ctx context.Context, g, a, v string) (string, bool) {
	var chain []*POM
	for i := 0; i < 16; i++ {
		p, err := r.Fetch(ctx, g, a, v)
		if err != nil {
			break
		}
		chain = append(chain, p)
		if p.Parent == nil {
			break
		}
		g, a, v = p.Parent.GroupID, p.Parent.ArtifactID, p.Parent.Version
	}
	usable := func(s string) bool { return s != "" && !strings.Contains(s, "${") }
	for _, p := range chain {
		if s := strings.Join(strings.Fields(p.Organization), " "); usable(s) {
			return s, true
		}
	}
	for _, p := range chain {
		for _, d := range p.Developers {
			if s := strings.Join(strings.Fields(d), " "); usable(s) {
				return s, false
			}
		}
	}
	return "", false
}

// JarSHA1 returns the SHA-1 that the repository publishes next to the jar of
// a component, or "" (no jar, for example a BOM, or the file is unavailable).
func (r *Repo) JarSHA1(ctx context.Context, g, a, v string) string {
	u := Central + "/" + strings.ReplaceAll(g, ".", "/") + "/" + a + "/" + v + "/" + a + "-" + v + ".jar.sha1"
	b, err := r.Net.Get(ctx, u, "")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f[0]) != 40 {
		return ""
	}
	h := strings.ToLower(f[0])
	if _, err := hex.DecodeString(h); err != nil {
		return ""
	}
	return h
}

func interpolate(s string, p map[string]string) string {
	for i := 0; i < 10 && strings.Contains(s, "${"); i++ {
		n := propRe.ReplaceAllStringFunc(s, func(m string) string {
			k := m[2 : len(m)-1]
			if v, ok := p[k]; ok {
				return v
			}
			return m
		})
		if n == s {
			break
		}
		s = n
	}
	return strings.TrimSpace(s)
}

// Effective computes the effective model of g:a:v (remote) or of a local POM.
func (r *Repo) Effective(ctx context.Context, g, a, v string) (*Effective, error) {
	k := gav(g, a, v)
	r.mu.Lock()
	res, ok := r.effs[k]
	if !ok {
		res = &effResult{}
		r.effs[k] = res
	}
	r.mu.Unlock()
	res.once.Do(func() {
		p, err := r.Fetch(ctx, g, a, v)
		if err != nil {
			res.err = err
			return
		}
		if rl := p.Distribution.Relocation; rl != nil {
			ng, na, nv := or(rl.GroupID, g), or(rl.ArtifactID, a), or(rl.Version, v)
			if gav(ng, na, nv) != k {
				res.e, res.err = r.Effective(ctx, ng, na, nv)
				return
			}
		}
		res.e, res.err = r.build(ctx, p, 0)
	})
	return res.e, res.err
}

func or(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return b
}

// EffectiveLocal computes the effective model of a POM read from disk.
func (r *Repo) EffectiveLocal(ctx context.Context, p *POM) (*Effective, error) {
	return r.build(ctx, p, 0)
}

func (r *Repo) parentOf(ctx context.Context, p *POM) (*POM, error) {
	if p.Parent == nil {
		return nil, nil
	}
	pg, pa, pv := p.Parent.GroupID, p.Parent.ArtifactID, p.Parent.Version
	if p.dir != "" {
		rel := "../pom.xml"
		if p.Parent.RelativePath != nil {
			rel = *p.Parent.RelativePath
		}
		if rel != "" {
			path := filepath.Join(p.dir, rel)
			if st, err := os.Stat(path); err == nil && st.IsDir() {
				path = filepath.Join(path, "pom.xml")
			}
			if lp, err := ReadLocal(path); err == nil && lp.ArtifactID == pa {
				return lp, nil
			}
		}
	}
	return r.Fetch(ctx, pg, pa, pv)
}

// build computes the effective model: the parent chain is merged first with
// uninterpolated values, then the merged model is interpolated once with the
// final property set (a child property overrides the value used by inherited
// dependencyManagement, as in Maven), and finally BOMs are imported.
func (r *Repo) build(ctx context.Context, p *POM, depth int) (*Effective, error) {
	e, err := r.raw(ctx, p, depth)
	if err != nil {
		return nil, err
	}
	return r.finalize(ctx, e), nil
}

func (r *Repo) raw(ctx context.Context, p *POM, depth int) (*Effective, error) {
	if depth > 20 {
		return nil, fmt.Errorf("parent chain too deep")
	}
	e := &Effective{Props: map[string]string{}}
	if pp, err := r.parentOf(ctx, p); err != nil {
		e.Problems = append(e.Problems, "parent: "+err.Error())
	} else if pp != nil {
		pe, err := r.raw(ctx, pp, depth+1)
		if err != nil {
			e.Problems = append(e.Problems, "parent: "+err.Error())
		} else {
			for k, v := range pe.Props {
				e.Props[k] = v
			}
			e.Managed = append(e.Managed, pe.Managed...)
			e.Deps = append(e.Deps, pe.Deps...)
			e.Licenses = pe.Licenses
			e.Repos = pe.Repos
			e.RepoDecls = pe.RepoDecls
			e.SCM = pe.SCM
			e.GroupID, e.Version = pe.GroupID, pe.Version
			e.Problems = append(e.Problems, pe.Problems...)
		}
	}
	if p.Parent != nil {
		e.Props["project.parent.groupId"] = p.Parent.GroupID
		e.Props["project.parent.version"] = p.Parent.Version
		e.Props["parent.version"] = p.Parent.Version
		e.GroupID = or(e.GroupID, p.Parent.GroupID)
		e.Version = or(e.Version, p.Parent.Version)
	}
	e.GroupID = or(p.GroupID, e.GroupID)
	e.ArtifactID = p.ArtifactID
	e.Version = or(p.Version, e.Version)
	e.Packaging = or(p.Packaging, "jar")
	e.Modules = p.Modules
	if len(p.Licenses) > 0 {
		e.Licenses = nil
		for _, l := range p.Licenses {
			e.Licenses = append(e.Licenses, strings.TrimSpace(l.Name))
		}
	}
	if p.SCM.URL != "" {
		e.SCM = p.SCM.URL
	}
	self := gav(e.GroupID, e.ArtifactID, e.Version)
	for _, rp := range p.Repositories {
		e.Repos = append(e.Repos, strings.TrimSpace(rp.URL))
		e.RepoDecls = append(e.RepoDecls, model.Repository{URL: strings.TrimSpace(rp.URL), DeclaredIn: self})
	}
	for _, rp := range p.PluginRepositories {
		e.RepoDecls = append(e.RepoDecls, model.Repository{URL: strings.TrimSpace(rp.URL), Plugin: true, DeclaredIn: self})
	}
	for k, v := range p.Properties {
		e.Props[k] = v
	}
	managed := append([]pomDep{}, p.DependencyManagement.Dependencies...)
	deps := append([]pomDep{}, p.Dependencies...)
	for _, pr := range p.Profiles {
		if strings.TrimSpace(pr.Activation.ActiveByDefault) == "true" {
			for k, v := range pr.Properties {
				e.Props[k] = v
			}
			managed = append(managed, pr.DependencyManagement.Dependencies...)
			deps = append(deps, pr.Dependencies...)
			e.Modules = append(e.Modules, pr.Modules...)
		}
	}
	for k, v := range map[string]string{
		"project.groupId": e.GroupID, "pom.groupId": e.GroupID, "groupId": e.GroupID,
		"project.artifactId": e.ArtifactID, "pom.artifactId": e.ArtifactID,
		"project.version": e.Version, "pom.version": e.Version, "version": e.Version,
	} {
		e.Props[k] = v
	}
	// child declarations override inherited ones with the same key; keys are
	// interpolated with the properties known so far only for matching
	e.Managed = mergeDeps(interpKeys(managed, e.Props), e.Managed)
	e.Deps = mergeDeps(lastWins(interpKeys(deps, e.Props)), e.Deps)
	return e, nil
}

// lastWins keeps one of several declarations of a dependency in one POM (an
// active profile included) as Maven's model normaliser does: the last
// declaration wins and takes the position of the first.
func lastWins(ds []pomDep) []pomDep {
	at := map[string]int{}
	var out []pomDep
	for _, d := range ds {
		if i, ok := at[d.key()]; ok {
			out[i] = d
			continue
		}
		at[d.key()] = len(out)
		out = append(out, d)
	}
	return out
}

// interpKeys interpolates the coordinates (not the versions) so that merge
// keys are comparable across the parent chain.
func interpKeys(ds []pomDep, p map[string]string) []pomDep {
	out := make([]pomDep, len(ds))
	for i, d := range ds {
		d.GroupID = interpolate(d.GroupID, p)
		d.ArtifactID = interpolate(d.ArtifactID, p)
		out[i] = d
	}
	return out
}

func (r *Repo) finalize(ctx context.Context, e *Effective) *Effective {
	// the project's own coordinates may be properties ("CI-friendly"
	// versions: <version>${revision}</version>)
	e.GroupID = interpolate(e.GroupID, e.Props)
	e.ArtifactID = interpolate(e.ArtifactID, e.Props)
	e.Version = interpolate(e.Version, e.Props)
	for i := range e.RepoDecls {
		e.RepoDecls[i].URL = interpolate(e.RepoDecls[i].URL, e.Props)
		e.RepoDecls[i].DeclaredIn = interpolate(e.RepoDecls[i].DeclaredIn, e.Props)
	}
	for i := range e.Managed {
		interpDep(&e.Managed[i], e.Props)
	}
	for i := range e.Deps {
		interpDep(&e.Deps[i], e.Props)
	}
	// import BOMs, in declaration order; earlier declarations win
	var final []pomDep
	for _, m := range e.Managed {
		if m.Scope == "import" && (m.Type == "pom") {
			be, err := r.Effective(ctx, m.GroupID, m.ArtifactID, m.Version)
			if err != nil {
				e.Problems = append(e.Problems, "BOM "+m.GroupID+":"+m.ArtifactID+": "+err.Error())
				continue
			}
			final = append(final, be.Managed...)
			continue
		}
		final = append(final, m)
	}
	e.Managed = mergeDeps(nil, final)
	// apply dependencyManagement to direct dependencies
	idx := map[string]pomDep{}
	for _, m := range e.Managed {
		if _, ok := idx[m.key()]; !ok {
			idx[m.key()] = m
		}
	}
	for i := range e.Deps {
		d := &e.Deps[i]
		if m, ok := idx[d.key()]; ok {
			if d.Version == "" {
				d.Version = m.Version
			}
			if d.Scope == "" {
				d.Scope = m.Scope
			}
			if len(d.Exclusions) == 0 {
				d.Exclusions = m.Exclusions
			}
		}
	}
	return e
}

// mergeDeps returns child entries followed by inherited entries whose key is
// not already declared by the child.
func mergeDeps(child, inherited []pomDep) []pomDep {
	seen := map[string]bool{}
	var out []pomDep
	for _, d := range child {
		if !seen[d.key()] {
			seen[d.key()] = true
			out = append(out, d)
		}
	}
	for _, d := range inherited {
		if !seen[d.key()] {
			seen[d.key()] = true
			out = append(out, d)
		}
	}
	return out
}

func interpDep(d *pomDep, p map[string]string) {
	d.GroupID = interpolate(d.GroupID, p)
	d.ArtifactID = interpolate(d.ArtifactID, p)
	d.Version = interpolate(d.Version, p)
	d.Scope = interpolate(d.Scope, p)
	d.Type = interpolate(d.Type, p)
	d.Classifier = interpolate(d.Classifier, p)
	d.Optional = interpolate(d.Optional, p)
}

// ReadLocal parses a pom.xml from disk.
func ReadLocal(path string) (*POM, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := parsePOM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.dir = filepath.Dir(path)
	return p, nil
}
