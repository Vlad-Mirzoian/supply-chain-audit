package integrity

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Verifier runs the M3 checks for all components.
type Verifier struct {
	Net   *netx.Client
	Trust *Trust
	// Provenance enables Sigstore verification of npm provenance and PyPI
	// PEP 740 attestations (one or two extra requests per component).
	Provenance bool
	// Expect maps package names to the repository that must have signed them
	// (policy "require_provenance"); a package listed here without valid
	// provenance is reported as an unsigned artifact.
	Expect map[string]string
	// Registries are mirrors of the public registries (policy
	// "registries"); Internal is the organisation's own registry.
	Registries []string
	Internal   string
	// TrustedBuilders are the accepted SLSA builder IDs (policy
	// "trusted_builders"; DefaultTrustedBuilders when empty).
	TrustedBuilders []string
}

// mavenCentral are the addresses of Maven Central (scheme removed).
var mavenCentral = []string{"repo.maven.apache.org/maven2", "repo1.maven.org/maven2"}

// Repositories checks the package repositories that the project files
// declare (T-08, T-12): the Maven repositories of the POMs here, the pip
// sources of requirements files in pythonIndex. Maven searches a repository declared in a POM before
// Maven Central, so a repository outside Central can replace any dependency
// with its own artifact, and Maven has no lockfile hash that would notice.
// Central itself, a mirror named in the policy (registries) and the
// organisation's repository (internal.registry) are accepted over HTTPS;
// plain HTTP is never accepted, because nothing protects the download.
// The findings belong to the project (root).
func (v *Verifier) Repositories(root string, repos []model.Repository) []*model.Finding {
	var out []*model.Finding
	for _, r := range repos {
		if r.Kind != "" {
			if f := v.pythonIndex(root, r); f != nil {
				out = append(out, f)
			}
			continue
		}
		u := strings.TrimSuffix(strings.TrimSpace(r.URL), "/")
		lu := strings.ToLower(u)
		what := "repository"
		if r.Plugin {
			what = "plugin repository"
		}
		ev := map[string]any{"url": r.URL, "declared_in": r.DeclaredIn, "plugin": r.Plugin}
		switch {
		case strings.HasPrefix(lu, "http://"):
			out = append(out, &model.Finding{
				ID: "SSCA-REPOSITORY-SOURCE", Kind: model.KindIntegrity, Rule: "repository-source", Component: root,
				Severity: model.SevCritical, Module: "M3", Evidence: ev,
				Title:  "Maven " + what + " without transport security",
				Detail: fmt.Sprintf("%s declares the %s %s over plain HTTP: anyone on the network path can replace the artifacts downloaded from it (Maven 3.8.1 and later block such repositories)", r.DeclaredIn, what, r.URL),
			})
		case strings.HasPrefix(lu, "https://") && slices.Contains(mavenCentral, strings.TrimPrefix(lu, "https://")):
		case v.acceptedMirror(u):
		default:
			out = append(out, &model.Finding{
				ID: "SSCA-REPOSITORY-SOURCE", Kind: model.KindIntegrity, Rule: "repository-source", Component: root,
				Severity: model.SevHigh, Module: "M3", Evidence: ev,
				Title:  "Maven " + what + " outside Maven Central",
				Detail: fmt.Sprintf("%s declares the %s %s; Maven looks up artifacts there before Maven Central, so it can replace any dependency; add the mirror to the policy (registries), name the organisation's repository (internal.registry) or add an exception if this source is intended", r.DeclaredIn, what, r.URL),
			})
		}
	}
	return out
}

var pypiIndexes = []string{"pypi.org/simple", "pypi.python.org/simple"}

// pythonIndex checks a package source that a requirements file names with a
// pip option. --index-url replaces PyPI: accepted for PyPI itself, a mirror
// named in the policy and the organisation's registry. --extra-index-url and
// --find-links add a source next to PyPI, and pip takes the highest version
// of a name from all of them, so a name published on PyPI can replace an
// internal package (dependency confusion): only PyPI itself and a mirror of
// the policy (registries) are accepted. Plain HTTP is never accepted. ssca
// resolves the requirements against PyPI, so what pip would download from
// such a source is not what was analysed.
func (v *Verifier) pythonIndex(root string, r model.Repository) *model.Finding {
	u := strings.TrimSuffix(strings.TrimSpace(r.URL), "/")
	lu := strings.ToLower(u)
	mirror := false
	for _, b := range v.Registries {
		if b != "" && strings.HasPrefix(lu, "https://") && (strings.EqualFold(strings.TrimSuffix(b, "/"), u) || underURL(u+"/", b)) {
			mirror = true
		}
	}
	f := &model.Finding{
		ID: "SSCA-REPOSITORY-SOURCE", Kind: model.KindIntegrity, Rule: "repository-source", Component: root,
		Severity: model.SevHigh, Module: "M3",
		Evidence: map[string]any{"url": r.URL, "declared_in": r.DeclaredIn, "option": "--" + r.Kind},
	}
	switch {
	case strings.HasPrefix(lu, "https://") && slices.Contains(pypiIndexes, strings.TrimPrefix(lu, "https://")):
		return nil
	case strings.HasPrefix(lu, "http://"):
		f.Severity = model.SevCritical
		f.Title = "Python package source without transport security"
		f.Detail = fmt.Sprintf("%s names the package source %s over plain HTTP (--%s): anyone on the network path can replace the packages downloaded from it", r.DeclaredIn, r.URL, r.Kind)
	case r.Kind == "index-url" && v.acceptedMirror(u):
		return nil
	case r.Kind == "index-url":
		f.Title = "Python package index outside PyPI"
		f.Detail = fmt.Sprintf("%s replaces PyPI with %s (--index-url): pip downloads every package from there, while ssca analysed the packages of PyPI; add the mirror to the policy (registries), name the organisation's index (internal.registry) or add an exception if this source is intended", r.DeclaredIn, r.URL)
	case mirror:
		return nil
	default:
		f.Title = "Additional Python package source"
		f.Detail = fmt.Sprintf("%s adds the package source %s (--%s): pip takes the highest version of a name from all sources, so a package published on PyPI under the same name can replace an internal one (dependency confusion), and packages from this source were not analysed; use --index-url with an index that proxies PyPI, or add an exception if this source is intended", r.DeclaredIn, r.URL, r.Kind)
	}
	return f
}

// acceptedMirror reports whether an HTTPS repository is a mirror named in the
// policy or the organisation's registry.
func (v *Verifier) acceptedMirror(u string) bool {
	if !strings.HasPrefix(strings.ToLower(u), "https://") {
		return false
	}
	for _, b := range append(append([]string{}, v.Registries...), v.Internal) {
		if b != "" && (strings.EqualFold(strings.TrimSuffix(b, "/"), u) || underURL(u+"/", b)) {
			return true
		}
	}
	return false
}

// Outcomes of the lockfile hash check, recorded in Component.HashCheck.
const (
	HashVerified    = "verified"         // every hash shared with the registry matches
	HashMismatch    = "mismatch"         // a lockfile hash differs from the registry (finding)
	HashNoLockfile  = "no-lockfile-hash" // the lockfile records no hash, or there is no lockfile
	HashOtherSource = "other-source"     // not downloaded from the public registry or PyPI
	HashNoReference = "no-registry-hash" // the registry publishes no hash of the same algorithm
	HashNotFound    = "not-on-registry"  // the registry does not know this version
	HashUnavailable = "unavailable"      // registry data could not be fetched
)

// Check returns integrity and provenance findings, the provenance results and
// the reasons why registry data for the hash check was unavailable (which
// make the analysis incomplete). It sets Component.HashCheck.
func (v *Verifier) Check(ctx context.Context, comps []*model.Component) ([]*model.Finding, map[string]Result, map[string]string) {
	var mu sync.Mutex
	var out []*model.Finding
	results := map[string]Result{}
	unavailable := map[string]string{}
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, c := range comps {
		wg.Add(1)
		go func(c *model.Component) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fs, r, h := v.checkOne(ctx, c)
			c.HashCheck = h.Status
			mu.Lock()
			out = append(out, fs...)
			if r != nil {
				results[c.PURL] = *r
			}
			if h.Status == HashUnavailable {
				unavailable[c.PURL] = h.Error
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	return out, results, unavailable
}

// HashResult is the outcome of the lockfile hash check of one component.
type HashResult struct {
	Status string
	Error  string // why registry data was unavailable
}

func (v *Verifier) checkOne(ctx context.Context, c *model.Component) ([]*model.Finding, *Result, HashResult) {
	var out []*model.Finding
	var res *Result
	h := HashResult{Status: HashNoLockfile} // Maven: no lockfile
	switch c.Ecosystem {
	case model.NPM:
		var fs []*model.Finding
		fs, h = v.npmHash(ctx, c)
		out = append(out, fs...)
		switch {
		case !v.Provenance:
		case c.Meta != nil && c.Meta.HasProvenance:
			r := v.npmProvenance(ctx, c)
			res = &r
		case v.expects(c) && !npmMetaRead(c):
			// the policy requires provenance, but the registry metadata that
			// says whether this version has an attestation was not read
			// (missing from the offline snapshot, registry outage, metadata
			// not collected): ask the attestation endpoint directly. A 404
			// means that there is none; any other error leaves the
			// provenance unchecked, which makes the analysis incomplete
			// instead of reporting the package as unsigned.
			r := v.npmProvenance(ctx, c)
			res = &r
		}
	case model.PyPI:
		var fs []*model.Finding
		fs, res, h = v.pypiCheck(ctx, c)
		out = append(out, fs...)
		if res == nil && h.Status == HashUnavailable && v.Provenance && v.expects(c) {
			// the package index (which lists the attestations) could not be
			// read, so it is unknown whether this release has provenance
			res = &Result{Error: "package index: " + h.Error, Unavailable: true}
		}
	}
	if c.Extraneous {
		// npm ci installs every entry of package-lock.json, also one that no
		// dependency requires: an entry added to the lockfile alone (for
		// example in a pull request) installs and runs a package that the
		// manifests do not mention
		out = append(out, &model.Finding{
			ID: "SSCA-LOCKFILE-EXTRANEOUS", Kind: model.KindIntegrity, Rule: "lockfile-extraneous", Component: c.PURL,
			Severity: model.SevHigh, Module: "M3",
			Title:  "Lockfile installs a package that no dependency requires",
			Detail: fmt.Sprintf("%s has an entry in the lockfile, but neither the project nor any locked package depends on it; npm ci installs it anyway", c.FullName()),
		})
	}
	if c.LockScope != "" {
		// the lockfile hides a package that production code needs from the
		// production view: --omit=dev would not install it, and scanners
		// that trust the flag skip its vulnerabilities
		out = append(out, &model.Finding{
			ID: "SSCA-LOCKFILE-SCOPE", Kind: model.KindIntegrity, Rule: "lockfile-scope", Component: c.PURL,
			Severity: model.SevHigh, Module: "M3",
			Title:  "Lockfile marks a production package as a development dependency",
			Detail: fmt.Sprintf("%s is marked %q in the lockfile, but %s needs it; it is analysed as a %s dependency", c.FullName(), c.LockScope, c.ScopeVia, c.Scope),
		})
	}
	// provenance that could not be checked is not reported as missing: it
	// makes the analysis incomplete (exit code 2), it is not a policy violation
	if exp, ok := v.Expect[c.FullName()]; ok && (res == nil || !res.Unavailable) {
		if res == nil || !res.Verified {
			reason := "no provenance attestation"
			if res != nil && res.Error != "" {
				reason = res.Error
			}
			out = append(out, &model.Finding{
				ID: "SSCA-UNSIGNED", Kind: model.KindProvenance, Rule: "unsigned-artifact", Component: c.PURL,
				Severity: model.SevHigh, Module: "M3",
				Title:  "Artifact without valid signature/provenance from the expected source",
				Detail: fmt.Sprintf("policy requires provenance from %s: %s", exp, reason),
			})
		} else if exp != "" && !strings.Contains(strings.ToLower(res.SourceRepo+res.SignerSAN), strings.ToLower(strings.TrimPrefix(exp, "github.com/"))) {
			out = append(out, &model.Finding{
				ID: "SSCA-PROV-SOURCE", Kind: model.KindProvenance, Rule: "unexpected-source", Component: c.PURL,
				Severity: model.SevHigh, Module: "M3",
				Title:  "Provenance from an unexpected repository",
				Detail: fmt.Sprintf("expected %s, signed by %s", exp, res.SignerSAN),
			})
		}
	}
	if res != nil && res.Verified && !Trusted(*res, v.TrustedBuilders) {
		// a valid signature from the expected repository, but the build ran
		// on a builder that the policy does not trust (e.g. a self-hosted
		// runner, which gives SLSA Build L2 at most)
		out = append(out, &model.Finding{
			ID: "SSCA-PROV-BUILDER", Kind: model.KindProvenance, Rule: "untrusted-builder", Component: c.PURL,
			Severity: model.SevMedium, Module: "M3",
			Title:  "Provenance from a builder that is not trusted",
			Detail: fmt.Sprintf("built by %s (runner %s), which is not a trusted builder", res.BuilderID, orUnknown(res.RunnerEnvironment)),
		})
	}
	if res != nil && res.Error != "" && !res.Unavailable && c.Meta != nil && c.Meta.HasProvenance {
		if res.NotServed {
			out = append(out, &model.Finding{
				ID: "SSCA-PROV-UNAVAILABLE", Kind: model.KindProvenance, Rule: "provenance-unavailable", Component: c.PURL,
				Severity: model.SevMedium, Module: "M3",
				Title:  "Provenance attestation announced but not served by the registry",
				Detail: res.Error,
			})
		} else {
			out = append(out, &model.Finding{
				ID: "SSCA-PROV-INVALID", Kind: model.KindProvenance, Rule: "provenance-invalid", Component: c.PURL,
				Severity: model.SevCritical, Module: "M3",
				Title:  "Provenance attestation does not verify",
				Detail: res.Error,
			})
		}
	}
	return out, res, h
}

// expects reports whether the policy requires provenance for the package
// (require_provenance).
func (v *Verifier) expects(c *model.Component) bool {
	_, ok := v.Expect[c.FullName()]
	return ok
}

// npmMetaRead reports whether the npm registry metadata of the component was
// read, so that Meta.HasProvenance says whether the version has an
// attestation (a version that the registry does not know counts as read).
func npmMetaRead(c *model.Component) bool {
	if c.Meta == nil {
		return false
	}
	for _, u := range c.Meta.Unavailable {
		if strings.HasPrefix(u, "npm registry: ") {
			return false
		}
	}
	return true
}

// fetchFailed classifies a download error. An attestation that the registry
// reports as missing (404) is not served: nothing was verified, a warning when
// the metadata announces it (a required attestation stays unsigned); any other
// error (network, offline snapshot) only means that nothing could be checked
// and makes the analysis incomplete.
func fetchFailed(what string, err error) Result {
	notFound := errors.Is(err, netx.ErrNotFound)
	return Result{Error: what + ": " + err.Error(), Unavailable: !notFound, NotServed: notFound}
}

// notServed is the result for a registry response that is not the announced
// attestation (for example "OK" instead of a JSON document).
func notServed(what, why string) Result {
	return Result{Error: what + ": " + why, NotServed: true}
}

// npmPublic are the hosts that serve the packages of the public npm registry.
var npmPublic = []string{"https://registry.npmjs.org/", "https://registry.yarnpkg.com/"}

// npm download origins of a lockfile entry
const (
	originPublic   = iota // public registry or one of its mirrors
	originInternal        // the organisation's registry (policy internal.registry)
	originForeign         // anything else: another host, git, a local path
)

// npmOrigin classifies the download location recorded in a lockfile. An
// entry without one (pnpm and yarn berry registry packages, older npm
// lockfiles) is installed from the configured registry.
func (v *Verifier) npmOrigin(resolved string) int {
	if resolved == "" {
		return originPublic
	}
	for _, b := range append(append([]string{npm.Registry}, npmPublic...), v.Registries...) {
		if underURL(resolved, b) {
			return originPublic
		}
	}
	if v.Internal != "" && underURL(resolved, v.Internal) {
		return originInternal
	}
	return originForeign
}

// underURL reports whether u lies below base; http and https are treated
// alike, because the lockfile hash protects the download either way.
func underURL(u, base string) bool {
	strip := func(s string) string {
		s = strings.ToLower(s)
		for _, p := range []string{"https://", "http://"} {
			if strings.HasPrefix(s, p) {
				return s[len(p):]
			}
		}
		return ""
	}
	b, x := strip(base), strip(u)
	return b != "" && x != "" && strings.HasPrefix(x, strings.TrimSuffix(b, "/")+"/")
}

// npmHash checks where the lockfile downloads a package from and compares
// its integrity values with the registry (T-08, T-11). Every algorithm that
// both sides record is compared: sha512 with dist.integrity and sha1 with
// dist.shasum, so that an old or edited lockfile with only a sha1 value is
// checked as well.
func (v *Verifier) npmHash(ctx context.Context, c *model.Component) ([]*model.Finding, HashResult) {
	switch v.npmOrigin(c.Resolved) {
	case originInternal:
		return nil, HashResult{Status: HashOtherSource}
	case originForeign:
		return []*model.Finding{{
			ID: "SSCA-LOCKFILE-SOURCE", Kind: model.KindIntegrity, Rule: "lockfile-source", Component: c.PURL,
			Severity: model.SevHigh, Module: "M3",
			Title:  "Lockfile installs the package from outside the registry",
			Detail: fmt.Sprintf("%s is downloaded from %s, not from the npm registry; add the mirror to the policy (registries) or an exception if this source is intended", c.FullName(), c.Resolved),
		}}, HashResult{Status: HashOtherSource}
	}
	doc, err := npm.NewRegistry(v.Net).Version(ctx, c.FullName(), c.Version)
	if errors.Is(err, netx.ErrNotFound) {
		return nil, HashResult{Status: HashNotFound}
	}
	if err != nil {
		return nil, HashResult{Status: HashUnavailable, Error: err.Error()}
	}
	var out []*model.Finding
	if want := tarballSuffix(c.FullName(), doc.Dist.Tarball); c.Resolved != "" && want != "" && !strings.HasSuffix(urlPath(c.Resolved), want) {
		// the URL is on the registry but names another package or version;
		// without a lockfile hash npm would install it unchecked
		out = append(out, &model.Finding{
			ID: "SSCA-LOCKFILE-SOURCE", Kind: model.KindIntegrity, Rule: "lockfile-source", Component: c.PURL,
			Severity: model.SevCritical, Module: "M3",
			Title:  "Lockfile download URL is not the registry tarball of this version",
			Detail: fmt.Sprintf("lockfile %s, registry %s", c.Resolved, doc.Dist.Tarball),
		})
	}
	lock := sriDigests(c.Integrity...)
	if len(lock) == 0 {
		return out, HashResult{Status: HashNoLockfile}
	}
	reg := sriDigests(doc.Dist.Integrity)
	if b, err := hex.DecodeString(doc.Dist.Shasum); err == nil && len(b) == sha1.Size {
		reg["sha1"] = b
	}
	compared := false
	for _, alg := range []string{"sha512", "sha384", "sha256", "sha1"} {
		l, ok1 := lock[alg]
		r, ok2 := reg[alg]
		if !ok1 || !ok2 {
			continue
		}
		compared = true
		if !bytes.Equal(l, r) {
			return append(out, &model.Finding{
				ID: "SSCA-HASH-MISMATCH", Kind: model.KindIntegrity, Rule: "hash-mismatch", Component: c.PURL,
				Severity: model.SevCritical, Module: "M3",
				Title:  "Lockfile integrity value differs from the registry",
				Detail: fmt.Sprintf("%s: lockfile %s, registry %s", alg, short(sriText(l)), short(sriText(r))),
			}), HashResult{Status: HashMismatch}
		}
	}
	if !compared {
		return out, HashResult{Status: HashNoReference}
	}
	return out, HashResult{Status: HashVerified}
}

// sriDigests decodes Subresource Integrity values ("sha512-<base64>", several
// separated by spaces) into digests by algorithm. A value that is not valid
// base64 is kept as text, so that it is still compared (and differs from any
// real digest) instead of counting as no hash.
func sriDigests(vals ...string) map[string][]byte {
	out := map[string][]byte{}
	for _, v := range vals {
		for _, f := range strings.Fields(v) {
			alg, b64, ok := strings.Cut(f, "-")
			if !ok || b64 == "" {
				continue
			}
			b, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				b = []byte("text:" + b64)
			}
			out[strings.ToLower(alg)] = b
		}
	}
	return out
}

// sriText prints a digest of sriDigests as it appears in the lockfile.
func sriText(b []byte) string {
	if t, ok := strings.CutPrefix(string(b), "text:"); ok {
		return t
	}
	return base64.StdEncoding.EncodeToString(b)
}

// tarballSuffix returns "/<name>/-/<file>.tgz" of a registry tarball URL;
// mirrors keep this part of the path.
func tarballSuffix(name, tarball string) string {
	p := urlPath(tarball)
	if p == "" || !strings.Contains(p, "/-/") {
		return ""
	}
	return "/" + name + "/-/" + path.Base(p)
}

// urlPath returns the unescaped path of a URL ("" if it cannot be parsed).
func urlPath(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Path
}

func short(s string) string {
	if len(s) > 24 {
		return s[:24] + "…"
	}
	return s
}

func (v *Verifier) npmProvenance(ctx context.Context, c *model.Component) Result {
	tr, err := v.Trust.Root()
	if err != nil {
		return Result{Error: "trusted root: " + err.Error(), Unavailable: true}
	}
	raw, err := npm.NewRegistry(v.Net).Attestations(ctx, c.FullName(), c.Version)
	if err != nil {
		return fetchFailed("attestations", err)
	}
	var doc struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return notServed("attestations", "the registry response is not an attestation document ("+err.Error()+")")
	}
	digest, alg := sriDigest(c)
	if digest == nil {
		return Result{Error: "no sha512 integrity value to bind the provenance to"}
	}
	var id *Identity
	if c.Meta != nil && strings.HasPrefix(c.Meta.Repository, "github.com/") {
		x := RepoIdentity(c.Meta.Repository)
		id = &x
	}
	for _, a := range doc.Attestations {
		if !strings.HasPrefix(a.PredicateType, "https://slsa.dev/provenance/") {
			continue
		}
		r := VerifyBundle(tr, a.Bundle, alg, digest, nil, id)
		if !r.Verified && id != nil && strings.Contains(r.Error, "certificate") {
			// repository renamed or moved: verify without identity and report
			if r2 := VerifyBundle(tr, a.Bundle, alg, digest, nil, nil); r2.Verified {
				r2.Error = ""
				r2.Verified = true
				return r2
			}
		}
		return r
	}
	return notServed("attestations", "no SLSA provenance attestation in the registry response")
}

func sriDigest(c *model.Component) ([]byte, string) {
	for _, s := range c.Integrity {
		for _, f := range strings.Fields(s) { // an SRI value may list several hashes
			if v, ok := strings.CutPrefix(f, "sha512-"); ok {
				if b, err := base64.StdEncoding.DecodeString(v); err == nil {
					return b, "sha512"
				}
			}
		}
	}
	if c.Meta != nil && strings.HasPrefix(c.Meta.RegistryIntegrity, "sha512-") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.Meta.RegistryIntegrity, "sha512-"))
		if err == nil {
			return b, "sha512"
		}
	}
	return nil, ""
}

// pypiCheck compares lockfile hashes with the hashes published by PyPI and
// verifies PEP 740 attestations for the matching file.
func (v *Verifier) pypiCheck(ctx context.Context, c *model.Component) ([]*model.Finding, *Result, HashResult) {
	if c.Resolved != "" && !pypi.IsPyPIIndex(c.Resolved) {
		// installed from another index (recorded as a graph note)
		return nil, nil, HashResult{Status: HashOtherSource}
	}
	cl := &pypi.Client{Net: v.Net}
	sp, err := cl.Simple(ctx, c.Name)
	if errors.Is(err, netx.ErrNotFound) {
		return nil, nil, HashResult{Status: HashNotFound}
	}
	if err != nil {
		return nil, nil, HashResult{Status: HashUnavailable, Error: err.Error()}
	}
	published := map[string]pypi.SimpleFile{}
	for _, f := range sp.Files {
		if pypi.VersionFromFilename(sp.Name, f.Filename) == c.Version {
			published[strings.ToLower(f.Hashes["sha256"])] = f
		}
	}
	var out []*model.Finding
	var match *pypi.SimpleFile
	h := HashResult{Status: HashNoLockfile}
	for _, lh := range c.Integrity {
		alg, val, ok := strings.Cut(lh, ":")
		if !ok || alg != "sha256" {
			if h.Status == HashNoLockfile {
				h.Status = HashNoReference // PyPI publishes sha256 only
			}
			continue
		}
		h.Status = HashVerified
		if f, ok := published[strings.ToLower(val)]; ok {
			if match == nil || strings.HasSuffix(f.Filename, ".whl") {
				match = &f
			}
		}
	}
	switch {
	case h.Status != HashVerified:
	case len(published) == 0:
		h.Status = HashNoReference // no file of this version on PyPI
	case match == nil:
		h.Status = HashMismatch
		out = append(out, &model.Finding{
			ID: "SSCA-HASH-MISMATCH", Kind: model.KindIntegrity, Rule: "hash-mismatch", Component: c.PURL,
			Severity: model.SevCritical, Module: "M3",
			Title:  "No lockfile hash matches a file published on PyPI",
			Detail: fmt.Sprintf("%d lockfile hashes, %d published files", len(c.Integrity), len(published)),
		})
	}
	if !v.Provenance {
		return out, nil, h
	}
	if match == nil {
		// in the order of the index, so that every run checks the same file
		for _, f := range sp.Files {
			f := f
			if pypi.VersionFromFilename(sp.Name, f.Filename) != c.Version || f.Provenance == nil {
				continue
			}
			if match == nil || strings.HasSuffix(f.Filename, ".whl") && !strings.HasSuffix(match.Filename, ".whl") {
				match = &f
			}
		}
	}
	if match == nil || match.Provenance == nil || *match.Provenance == "" {
		return out, nil, h
	}
	r := v.pep740(ctx, *match)
	return out, &r, h
}

// pep740 converts a PEP 740 provenance object into Sigstore bundles and
// verifies them against the file digest and the trusted publisher identity.
func (v *Verifier) pep740(ctx context.Context, f pypi.SimpleFile) Result {
	tr, err := v.Trust.Root()
	if err != nil {
		return Result{Error: "trusted root: " + err.Error(), Unavailable: true}
	}
	raw, err := v.Net.Get(ctx, *f.Provenance, "application/vnd.pypi.integrity.v1+json")
	if err != nil {
		return fetchFailed("provenance", err)
	}
	var prov struct {
		Bundles []struct {
			Publisher struct {
				Kind       string `json:"kind"`
				Repository string `json:"repository"`
				Workflow   string `json:"workflow"`
			} `json:"publisher"`
			Attestations []struct {
				Material struct {
					Certificate string            `json:"certificate"`
					Entries     []json.RawMessage `json:"transparency_entries"`
				} `json:"verification_material"`
				Envelope struct {
					Statement string `json:"statement"`
					Signature string `json:"signature"`
				} `json:"envelope"`
			} `json:"attestations"`
		} `json:"attestation_bundles"`
	}
	if err := json.Unmarshal(raw, &prov); err != nil {
		return notServed("provenance", "the index response is not a provenance object ("+err.Error()+")")
	}
	digest, err := hex.DecodeString(f.Hashes["sha256"])
	if err != nil {
		return Result{Error: "file digest: " + err.Error()}
	}
	for _, b := range prov.Bundles {
		var id *Identity
		if b.Publisher.Kind == "GitHub" && b.Publisher.Repository != "" {
			x := RepoIdentity(b.Publisher.Repository)
			id = &x
		}
		for _, a := range b.Attestations {
			bundleJSON, _ := json.Marshal(map[string]any{
				"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
				"verificationMaterial": map[string]any{
					"certificate": map[string]any{"rawBytes": a.Material.Certificate},
					"tlogEntries": a.Material.Entries,
				},
				"dsseEnvelope": map[string]any{
					"payload":     a.Envelope.Statement,
					"payloadType": "application/vnd.in-toto+json",
					"signatures":  []map[string]string{{"sig": a.Envelope.Signature}},
				},
			})
			r := VerifyBundle(tr, bundleJSON, "sha256", digest, nil, id)
			if r.Verified && r.SourceRepo == "" {
				r.SourceRepo = "https://github.com/" + b.Publisher.Repository
			}
			return r
		}
	}
	return notServed("provenance", "no attestation in the provenance object")
}

func orUnknown(s string) string {
	if s == "" {
		return "not stated"
	}
	return s
}
