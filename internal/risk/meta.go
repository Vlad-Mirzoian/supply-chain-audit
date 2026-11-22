// Package risk is module M4: registry metadata collection, malicious-package
// signals, health indicators, typosquat detection and the composite risk
// score with propagation through the graph (Algorithms 3.2 and 3.3).
package risk

import (
	"context"
	"errors"
	"mime"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/maven"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// DepsDev is the deps.dev v3 API.
var DepsDev = "https://api.deps.dev/v3"

// Collector gathers PackageMeta for every component.
type Collector struct {
	Net       *netx.Client
	Now       time.Time
	Downloads bool // query download counts (npm only)
	// ArtifactHashes also records the checksums that the registries publish
	// for the files of a release, for the SBOM: the SHA-1 next to a Maven jar
	// (one more request) and the SHA-256 of the PyPI files (from the Simple API
	// page that is read anyway).
	ArtifactHashes bool
	npm            *npm.RegistryClient
	maven          *maven.Repo
	pypi           *pypi.Client
	scoreMu        sync.Mutex
	scorecards     map[string]scoreResult
}

type scoreResult struct {
	score float64
	err   error
}

// NewCollector creates a collector.
func NewCollector(n *netx.Client, now time.Time) *Collector {
	return &Collector{Net: n, Now: now, npm: npm.NewRegistry(n), pypi: &pypi.Client{Net: n}, maven: maven.NewRepo(n), scorecards: map[string]scoreResult{}}
}

func system(eco string) string {
	if eco == model.PyPI {
		return "pypi"
	}
	return eco
}

type ddVersion struct {
	VersionKey struct {
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt time.Time `json:"publishedAt"`
	IsDefault   bool      `json:"isDefault"`
}

type ddPackage struct {
	Versions []ddVersion `json:"versions"`
}

type ddVersionDetail struct {
	PublishedAt     time.Time `json:"publishedAt"`
	Licenses        []string  `json:"licenses"`
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType string `json:"relationType"`
	} `json:"relatedProjects"`
	Attestations []struct {
		URL      string `json:"url"`
		Verified bool   `json:"verified"`
	} `json:"attestations"`
	SlsaProvenances []struct {
		SourceRepository string `json:"sourceRepository"`
		Verified         bool   `json:"verified"`
	} `json:"slsaProvenances"`
}

func (c *Collector) ddPackage(ctx context.Context, eco, name string) (*ddPackage, error) {
	var p ddPackage
	err := c.Net.GetJSON(ctx, DepsDev+"/systems/"+system(eco)+"/packages/"+url.PathEscape(name), &p)
	return &p, err
}

func (c *Collector) ddVersion(ctx context.Context, eco, name, version string) (*ddVersionDetail, error) {
	var v ddVersionDetail
	err := c.Net.GetJSON(ctx, DepsDev+"/systems/"+system(eco)+"/packages/"+url.PathEscape(name)+"/versions/"+url.PathEscape(version), &v)
	return &v, err
}

// Scorecard returns the OpenSSF Scorecard aggregate of a project (-1 if none)
// and the error of the request, if it failed.
func (c *Collector) Scorecard(ctx context.Context, project string) (float64, error) {
	if project == "" {
		return -1, nil
	}
	c.scoreMu.Lock()
	if s, ok := c.scorecards[project]; ok {
		c.scoreMu.Unlock()
		return s.score, s.err
	}
	c.scoreMu.Unlock()
	var p struct {
		Scorecard *struct {
			OverallScore float64 `json:"overallScore"`
		} `json:"scorecard"`
	}
	s := -1.0
	err := c.Net.GetJSON(ctx, DepsDev+"/projects/"+url.PathEscape(project), &p)
	if err == nil && p.Scorecard != nil {
		s = p.Scorecard.OverallScore
	}
	c.scoreMu.Lock()
	c.scorecards[project] = scoreResult{s, err}
	c.scoreMu.Unlock()
	return s, err
}

// scorecard sets the Scorecard of the package's repository.
func (c *Collector) scorecard(ctx context.Context, m *model.PackageMeta) {
	s, err := c.Scorecard(ctx, m.Repository)
	m.Scorecard = s
	unavailable(m, "deps.dev", err)
}

// unavailable records a failed metadata request. "Not found" is an answer:
// the source does not know the package. Any other error (network, server, a
// response missing from an offline snapshot) means that the indicators
// computed from this source may be wrong; it is recorded once per source.
func unavailable(m *model.PackageMeta, source string, err error) {
	if err == nil || errors.Is(err, netx.ErrNotFound) {
		return
	}
	for _, u := range m.Unavailable {
		if strings.HasPrefix(u, source+": ") {
			return
		}
	}
	m.Unavailable = append(m.Unavailable, source+": "+err.Error())
}

// previousVersion returns the highest stable version below version that was
// published before it (cur; zero when unknown), from the publication times
// of all versions (a zero time counts as "before").
func previousVersion(eco, version string, cur time.Time, published map[string]time.Time) string {
	var cands []string
	for v, t := range published {
		if vuln.Compare(eco, v, version) < 0 && !isPre(v) && (cur.IsZero() || !t.After(cur)) {
			cands = append(cands, v)
		}
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if d := vuln.Compare(eco, cands[i], cands[j]); d != 0 {
			return d < 0
		}
		return cands[i] < cands[j]
	})
	return cands[len(cands)-1]
}

// Collect fills Meta for all components using a bounded worker pool.
func (c *Collector) Collect(ctx context.Context, comps []*model.Component) {
	sem := make(chan struct{}, 24)
	var wg sync.WaitGroup
	for _, comp := range comps {
		wg.Add(1)
		go func(comp *model.Component) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			comp.Meta = c.collectOne(ctx, comp)
		}(comp)
	}
	wg.Wait()
}

func (c *Collector) collectOne(ctx context.Context, comp *model.Component) *model.PackageMeta {
	m := &model.PackageMeta{Scorecard: -1}
	name := comp.FullName()
	pkg, err := c.ddPackage(ctx, comp.Ecosystem, name)
	unavailable(m, "deps.dev", err)
	history := err == nil // release history from deps.dev; else from the registry
	var prev string
	if err == nil {
		var latest time.Time
		var cur time.Time
		for _, v := range pkg.Versions {
			if v.PublishedAt.After(latest) {
				latest = v.PublishedAt
			}
			if !v.PublishedAt.IsZero() {
				m.Releases++
				if m.FirstReleaseAt.IsZero() || v.PublishedAt.Before(m.FirstReleaseAt) {
					m.FirstReleaseAt = v.PublishedAt
				}
			}
			if v.VersionKey.Version == comp.Version {
				cur = v.PublishedAt
			}
		}
		m.LatestReleaseAt = latest
		m.PublishedAt = cur
		// previous version: the highest version below the current one
		// among stable releases published before it
		published := map[string]time.Time{}
		for _, v := range pkg.Versions {
			published[v.VersionKey.Version] = v.PublishedAt
		}
		prev = previousVersion(comp.Ecosystem, comp.Version, cur, published)
		m.PreviousVersion = prev
	} else {
		m.Incomplete = append(m.Incomplete, "deps.dev package: "+err.Error())
	}
	vd, err := c.ddVersion(ctx, comp.Ecosystem, name, comp.Version)
	unavailable(m, "deps.dev", err)
	if err == nil {
		if len(comp.Licenses) == 0 {
			comp.Licenses = vd.Licenses
		}
		for _, rp := range vd.RelatedProjects {
			if rp.RelationType == "SOURCE_REPO" && m.Repository == "" {
				m.Repository = rp.ProjectKey.ID
			}
		}
		if len(vd.SlsaProvenances) > 0 || len(vd.Attestations) > 0 {
			m.HasProvenance = true
		}
		if m.PublishedAt.IsZero() {
			m.PublishedAt = vd.PublishedAt
		}
	}
	c.scorecard(ctx, m)
	m.NewDepMinAgeDays = -1 // unknown until the age of a new dependency is found
	switch comp.Ecosystem {
	case model.NPM:
		c.npmMeta(ctx, comp, m, prev, history)
	case model.PyPI:
		c.pypiMeta(ctx, comp, m, prev, history)
	case model.Maven:
		// Maven Central has no install scripts and no publisher identity in
		// the API; its PGP signatures are not verified (out of scope, Section
		// 3.3.1), so Maven components carry no provenance signals.
		m.Supplier, m.SupplierOrg = c.maven.Supplier(ctx, comp.Namespace, comp.Name, comp.Version)
		if c.ArtifactHashes {
			m.RepoSHA1 = c.maven.JarSHA1(ctx, comp.Namespace, comp.Name, comp.Version)
		}
	}
	if m.HasProvenance {
		m.AnyProvenance = true
	}
	return m
}

func isPre(v string) bool {
	l := strings.ToLower(v)
	for _, s := range []string{"-", "alpha", "beta", "rc", "dev", "snapshot"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// npmMeta collects the registry metadata of an npm package. history says
// that deps.dev gave the release history; without it the previous version is
// taken from the registry's record of the versions.
func (c *Collector) npmMeta(ctx context.Context, comp *model.Component, m *model.PackageMeta, prev string, history bool) {
	name := comp.FullName()
	cur, err := c.npm.Version(ctx, name, comp.Version)
	unavailable(m, "npm registry", err)
	if err != nil {
		m.Incomplete = append(m.Incomplete, "npm registry: "+err.Error())
		return
	}
	// deps.dev indexes a new version only after a delay: a release published
	// minutes ago, which is when a hijacked release is installed, would have
	// no age. The registry's own record of the publication times fills it in,
	// and the whole release history when deps.dev gave none.
	if m.PublishedAt.IsZero() || !history {
		times, err := c.npm.Times(ctx, name)
		unavailable(m, "npm registry", err)
		if err == nil {
			if m.PublishedAt.IsZero() {
				registryTimes(m, comp.Version, times)
			}
			if !history && prev == "" {
				delete(times, "created")
				delete(times, "modified")
				prev = previousVersion(comp.Ecosystem, comp.Version, m.PublishedAt, times)
				m.PreviousVersion = prev
			}
		}
	}
	m.Supplier = personName(cur.AuthorField())
	m.InstallScripts = cur.InstallScripts()
	if cur.HasInstall && len(m.InstallScripts) == 0 {
		m.InstallScripts = []string{"install: node-gyp rebuild (implicit, binding.gyp)"}
	}
	m.Maintainers = len(cur.Maintainers)
	if cur.NpmUser != nil {
		m.Publisher = cur.NpmUser.Name
	}
	m.HasProvenance = cur.Dist.Attestations != nil
	m.RegistryIntegrity = cur.Dist.Integrity
	if d, ok := cur.Deprecated.(string); ok {
		m.Deprecated = d
	}
	if m.Repository == "" {
		m.Repository = normaliseRepo(cur.RepoURL())
		c.scorecard(ctx, m)
	}
	if prev != "" {
		p, err := c.npm.Version(ctx, name, prev)
		unavailable(m, "npm registry", err)
		if err == nil {
			m.PrevInstallScripts = p.InstallScripts()
			if p.NpmUser != nil {
				m.PreviousPublisher = p.NpmUser.Name
			}
			for _, x := range p.Maintainers {
				m.PrevMaintainers = append(m.PrevMaintainers, x.Name)
			}
			m.PrevHasProvenance = p.Dist.Attestations != nil
			for dep := range cur.Dependencies {
				if _, ok := p.Dependencies[dep]; !ok {
					m.NewDependencies = append(m.NewDependencies, dep)
				}
			}
			sort.Strings(m.NewDependencies)
		}
	}
	newDepAge(m, func(dep string) []time.Time {
		var ts []time.Time
		dp, err := c.ddPackage(ctx, model.NPM, dep)
		unavailable(m, "deps.dev", err)
		if err == nil {
			for _, v := range dp.Versions {
				if !v.PublishedAt.IsZero() {
					ts = append(ts, v.PublishedAt)
				}
			}
		}
		if len(ts) == 0 { // not yet in deps.dev: a package published hours ago
			times, err := c.npm.Times(ctx, dep)
			unavailable(m, "npm registry", err)
			for _, t := range times {
				ts = append(ts, t)
			}
		}
		return ts
	})
	if c.Downloads {
		d, err := c.npm.Downloads(ctx, name)
		unavailable(m, "npm download counts", err)
		if err == nil {
			m.Downloads = d
		}
	}
}

// pypiMeta collects the index metadata of a PyPI package; without the
// release history of deps.dev (history false) the history and the previous
// version come from the upload times of the Simple API.
func (c *Collector) pypiMeta(ctx context.Context, comp *model.Component, m *model.PackageMeta, prev string, history bool) {
	sp, err := c.pypi.Simple(ctx, comp.Name)
	unavailable(m, "PyPI", err)
	if err != nil {
		m.Incomplete = append(m.Incomplete, "PyPI simple API: "+err.Error())
		return
	}
	times := sp.ReleaseTimes()
	if !history {
		registryTimes(m, comp.Version, times)
		if prev == "" {
			prev = previousVersion(comp.Ecosystem, comp.Version, m.PublishedAt, times)
			m.PreviousVersion = prev
		}
	}
	hasWheel := map[string]bool{}
	prov := map[string]bool{}
	for _, f := range sp.Files {
		v := pypi.VersionFromFilename(sp.Name, f.Filename)
		if c.ArtifactHashes && v == comp.Version && f.Hashes["sha256"] != "" {
			// every file of the release is a valid form of the component
			m.RepoSHA256 = append(m.RepoSHA256, strings.ToLower(f.Hashes["sha256"]))
		}
		if strings.HasSuffix(f.Filename, ".whl") {
			hasWheel[v] = true
		}
		if f.Provenance != nil && *f.Provenance != "" {
			prov[v] = true
			m.AnyProvenance = true
		}
	}
	m.HasProvenance = prov[comp.Version]
	m.PrevHasProvenance = prev != "" && prov[prev]
	// a release without any wheel is installed by running setup.py
	if !hasWheel[comp.Version] {
		m.InstallScripts = []string{"setup.py (source distribution only)"}
	}
	if prev != "" && !hasWheel[prev] {
		m.PrevInstallScripts = []string{"setup.py (source distribution only)"}
	}
	if t, ok := times[comp.Version]; ok && m.PublishedAt.IsZero() {
		m.PublishedAt = t
	}
	vi, err := c.pypi.Version(ctx, comp.Name, comp.Version)
	unavailable(m, "PyPI", err)
	if err == nil {
		m.Maintainers = countPeople(vi.Info.Author, vi.Info.AuthorEmail, vi.Info.Maintainer, vi.Info.MaintEmail)
		for _, f := range []string{vi.Info.Author, vi.Info.AuthorEmail, vi.Info.Maintainer, vi.Info.MaintEmail} {
			if m.Supplier = personName(f); m.Supplier != "" {
				break
			}
		}
		if m.Repository == "" {
			for k, u := range vi.Info.ProjectURLs {
				lk := strings.ToLower(k)
				if strings.Contains(u, "github.com") && (strings.Contains(lk, "source") || strings.Contains(lk, "repo") || strings.Contains(lk, "code") || lk == "homepage") {
					m.Repository = normaliseRepo(u)
					break
				}
			}
			c.scorecard(ctx, m)
		}
		if prev != "" {
			pv, err := c.pypi.Version(ctx, comp.Name, prev)
			unavailable(m, "PyPI", err)
			if err == nil {
				old := map[string]bool{}
				for _, r := range pv.Info.RequiresDist {
					if rq, ok := pypi.ParseRequirement(r); ok {
						old[rq.Name] = true
					}
				}
				for _, r := range vi.Info.RequiresDist {
					if rq, ok := pypi.ParseRequirement(r); ok && !old[rq.Name] && pypi.EvalMarker(rq.Marker, nil) {
						m.NewDependencies = append(m.NewDependencies, rq.Name)
					}
				}
				// PyPI does not say which account uploaded a release; the
				// people declared in the metadata stand in for the publisher
				cur := pypiPeople(vi.Info.Author, vi.Info.AuthorEmail, vi.Info.Maintainer, vi.Info.MaintEmail)
				prevPeople := pypiPeople(pv.Info.Author, pv.Info.AuthorEmail, pv.Info.Maintainer, pv.Info.MaintEmail)
				m.Publisher = strings.Join(cur, ", ")
				m.PreviousPublisher = strings.Join(prevPeople, ", ")
				m.PrevMaintainers = prevPeople
			}
		}
	}
	newDepAge(m, func(dep string) []time.Time {
		sp, err := c.pypi.Simple(ctx, dep)
		unavailable(m, "PyPI", err)
		if err != nil {
			return nil
		}
		var ts []time.Time
		for _, t := range sp.ReleaseTimes() {
			ts = append(ts, t)
		}
		return ts
	})
}

// registryTimes completes the release dates from the registry's record when
// deps.dev has not (yet) indexed the version or the package: the publication
// time of the version and, if deps.dev had nothing at all, the number, the
// first and the latest of the releases.
func registryTimes(m *model.PackageMeta, version string, times map[string]time.Time) {
	if t, ok := times[version]; ok {
		m.PublishedAt = t
	}
	if m.Releases > 0 {
		return
	}
	for v, t := range times {
		if v == "created" || v == "modified" {
			continue
		}
		m.Releases++
		if m.FirstReleaseAt.IsZero() || t.Before(m.FirstReleaseAt) {
			m.FirstReleaseAt = t
		}
		if t.After(m.LatestReleaseAt) {
			m.LatestReleaseAt = t
		}
	}
}

// newDepAge sets NewDepMinAgeDays to the age of the youngest new dependency
// (time between its first release and the release of the component); it
// stays -1 when no release date of a new dependency is known.
func newDepAge(m *model.PackageMeta, releases func(dep string) []time.Time) {
	if m.PublishedAt.IsZero() {
		return
	}
	for _, dep := range m.NewDependencies {
		first := time.Time{}
		for _, t := range releases(dep) {
			if !t.IsZero() && (first.IsZero() || t.Before(first)) {
				first = t
			}
		}
		if first.IsZero() {
			continue
		}
		age := m.PublishedAt.Sub(first).Hours() / 24
		if m.NewDepMinAgeDays < 0 || age < m.NewDepMinAgeDays {
			m.NewDepMinAgeDays = age
		}
	}
}

// personName reduces a declared author ("Name <a@b.org> (https://x)", which
// may be RFC 2047 encoded) to the name; a bare e-mail address is not a name,
// and addresses are not copied into an SBOM.
func personName(s string) string {
	if d, err := new(mime.WordDecoder).DecodeHeader(s); err == nil {
		s = d
	}
	if i := strings.IndexAny(s, "<("); i >= 0 {
		s = s[:i]
	}
	s = strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(s), `"'`)), " ")
	if strings.Contains(s, "@") {
		return ""
	}
	return s
}

// pypiPeople returns the sorted, normalised e-mail addresses and names of
// the authors and maintainers declared in PyPI core metadata, so that a
// change of format ("Name <a@b.org>" instead of "a@b.org") is not taken
// for a new publisher.
func pypiPeople(fields ...string) []string {
	seen := map[string]bool{}
	dec := new(mime.WordDecoder)
	add := func(s string) {
		if d, err := dec.DecodeHeader(s); err == nil {
			s = d // RFC 2047 encoded names ("=?utf-8?q?...?=")
		}
		s = strings.ToLower(strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(s), `"'`)), " "))
		if s != "" {
			seen[s] = true
		}
	}
	for _, f := range fields {
		for _, p := range strings.FieldsFunc(f, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
			i, j := strings.Index(p, "<"), strings.LastIndex(p, ">")
			switch {
			case i >= 0 && j > i:
				add(p[:i])
				add(p[i+1 : j])
			default:
				add(p)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func countPeople(fields ...string) int {
	seen := map[string]bool{}
	for _, f := range fields {
		for _, p := range strings.FieldsFunc(f, func(r rune) bool { return r == ',' || r == ';' }) {
			if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
				seen[p] = true
			}
		}
	}
	n := len(seen)
	if n > 1 {
		n = (n + 1) / 2 // name and e-mail usually describe the same person
	}
	return n
}

// normaliseRepo converts a repository URL to a deps.dev project key.
func normaliseRepo(u string) string {
	u = strings.TrimSpace(strings.ToLower(u))
	u = strings.TrimPrefix(u, "git+")
	for _, p := range []string{"https://", "http://", "git://", "ssh://git@", "git@", "github:"} {
		u = strings.TrimPrefix(u, p)
	}
	u = strings.Replace(u, "github.com:", "github.com/", 1)
	if !strings.HasPrefix(u, "github.com/") && !strings.HasPrefix(u, "gitlab.com/") {
		if strings.Count(u, "/") == 1 && !strings.Contains(u, ".") {
			u = "github.com/" + u
		} else {
			return ""
		}
	}
	u = strings.TrimSuffix(u, ".git")
	parts := strings.Split(u, "/")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], "/")
}
