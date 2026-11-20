// Package integrity is module M3: hash verification against lockfiles and
// registries, Sigstore bundle verification (Fulcio certificate, Rekor
// inclusion proof, signer identity) and SLSA provenance checks.
package integrity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Trust provides the Sigstore trusted root. An online run obtains it through
// TUF and saves a copy in the data snapshot directory; only an explicit
// offline run uses that copy. When TUF fails online the copy is not used: it
// may be of any age, and signatures that a revoked key made would pass. The
// signatures are then not checked, which makes the analysis incomplete.
type Trust struct {
	CacheDir string
	Offline  bool
	once     sync.Once
	tr       *root.TrustedRoot
	err      error
	fetched  time.Time // when the copy used by an offline run was obtained
}

// rootCopyFile is the saved copy of the trusted root in the cache directory.
const rootCopyFile = "sigstore-trusted_root.json"

// fetchedSuffix names the file next to the saved copy that records when TUF
// delivered it; unlike the modification time it survives a plain copy of the
// data snapshot.
const fetchedSuffix = ".fetched"

// fetchTUF returns the trusted root from TUF (a variable for tests).
var fetchTUF = func(dir string) ([]byte, error) {
	cl, err := tuf.New(tuf.DefaultOptions().WithCachePath(dir).WithCacheValidity(1))
	if err != nil {
		return nil, err
	}
	return cl.GetTarget("trusted_root.json")
}

// Root returns the trusted root.
func (t *Trust) Root() (*root.TrustedRoot, error) {
	t.once.Do(func() {
		snap := filepath.Join(t.CacheDir, rootCopyFile)
		if t.Offline {
			if t.tr, t.err = root.NewTrustedRootFromPath(snap); t.err == nil {
				t.fetched = copyFetched(snap)
			}
			return
		}
		raw, err := fetchTUF(filepath.Join(t.CacheDir, "sigstore-tuf"))
		if err != nil {
			t.err = fmt.Errorf("sigstore TUF: %w", err)
			return
		}
		if t.tr, t.err = root.NewTrustedRootFromJSON(raw); t.err != nil {
			return
		}
		_ = os.WriteFile(snap, raw, 0o644)
		_ = os.WriteFile(snap+fetchedSuffix, []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)
	})
	return t.tr, t.err
}

// copyFetched returns when the saved copy was obtained: the recorded time or,
// for a snapshot made before it was recorded, the modification time.
func copyFetched(snap string) time.Time {
	if b, err := os.ReadFile(snap + fetchedSuffix); err == nil {
		if at, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); err == nil {
			return at
		}
	}
	st, err := os.Stat(snap)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// RootCopy describes the saved trusted root that an offline run relied on.
type RootCopy struct {
	Fetched time.Time `json:"fetched"`
	AgeDays int       `json:"age_days"`
}

func (c RootCopy) String() string {
	age := "less than a day old"
	switch {
	case c.AgeDays == 1:
		age = "1 day old"
	case c.AgeDays > 1:
		age = fmt.Sprintf("%d days old", c.AgeDays)
	}
	return fmt.Sprintf("saved copy fetched %s, %s", c.Fetched.UTC().Format("2006-01-02"), age)
}

// SavedCopy describes the copy of the trusted root that was loaded, or
// returns nil when no copy was used (online run, or Root was never needed).
func (t *Trust) SavedCopy(now time.Time) *RootCopy {
	if t.fetched.IsZero() {
		return nil
	}
	return newRootCopy(t.fetched, now)
}

// SavedRoot describes the saved trusted root of a cache directory without
// loading it; nil when there is none.
func SavedRoot(cacheDir string, now time.Time) *RootCopy {
	snap := filepath.Join(cacheDir, rootCopyFile)
	if _, err := os.Stat(snap); err != nil {
		return nil
	}
	return newRootCopy(copyFetched(snap), now)
}

func newRootCopy(fetched, now time.Time) *RootCopy {
	return &RootCopy{Fetched: fetched.UTC(), AgeDays: max(int(now.Sub(fetched).Hours()/24), 0)}
}

// Identity is the expected signer of an artifact.
type Identity struct {
	Issuer    string // OIDC issuer, e.g. GitHub Actions
	SANRegexp string // certificate subject (workflow URI) pattern
}

// GitHubActions is the issuer of GitHub Actions workload identities.
const GitHubActions = "https://token.actions.githubusercontent.com"

// RepoIdentity returns an identity for any workflow of a GitHub repository.
func RepoIdentity(repo string) Identity {
	repo = strings.TrimPrefix(repo, "github.com/")
	return Identity{Issuer: GitHubActions, SANRegexp: "^https://github\\.com/" + regexp.QuoteMeta(repo) + "/"}
}

// Result summarises one verification.
type Result struct {
	Verified   bool   `json:"verified"`
	Error      string `json:"error,omitempty"`
	SignerSAN  string `json:"signer,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	SourceRepo string `json:"source_repository,omitempty"`
	BuilderID  string `json:"builder_id,omitempty"`
	// RunnerEnvironment is the Fulcio certificate extension of a GitHub
	// workflow identity: "github-hosted" or "self-hosted".
	RunnerEnvironment string `json:"runner_environment,omitempty"`
	BuildType         string `json:"build_type,omitempty"`
	LogIndex          int64  `json:"rekor_log_index,omitempty"`
	PredicateType     string `json:"predicate_type,omitempty"`
	// Unavailable means that the attestation or the trusted root could not be
	// obtained (network error, not in the offline snapshot): nothing was
	// verified, which makes the analysis incomplete but is not evidence of
	// tampering.
	Unavailable bool `json:"unavailable,omitempty"`
	// TrustedRootCopy is set by verify-artifact when an offline run verified
	// against the saved trusted root.
	TrustedRootCopy *RootCopy `json:"trusted_root_copy,omitempty"`
}

// VerifyBundle verifies a Sigstore bundle against an artifact digest (or the
// artifact bytes when digest is nil) and an expected identity.
func VerifyBundle(tr *root.TrustedRoot, raw []byte, alg string, digest []byte, artifact []byte, id *Identity) Result {
	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return Result{Error: "bundle: " + err.Error()}
	}
	v, err := verify.NewVerifier(tr, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return Result{Error: err.Error()}
	}
	var art verify.ArtifactPolicyOption
	if digest != nil {
		art = verify.WithArtifactDigest(alg, digest)
	} else {
		art = verify.WithArtifact(strings.NewReader(string(artifact)))
	}
	var pol verify.PolicyBuilder
	if id != nil {
		ci, err := verify.NewShortCertificateIdentity(id.Issuer, "", "", id.SANRegexp)
		if err != nil {
			return Result{Error: err.Error()}
		}
		pol = verify.NewPolicy(art, verify.WithCertificateIdentity(ci))
	} else {
		pol = verify.NewPolicy(art, verify.WithoutIdentitiesUnsafe())
	}
	res, err := v.Verify(&b, pol)
	if err != nil {
		return Result{Error: err.Error()}
	}
	out := Result{Verified: true}
	if res.Signature != nil && res.Signature.Certificate != nil {
		out.SignerSAN = res.Signature.Certificate.SubjectAlternativeName
		out.Issuer = res.Signature.Certificate.Issuer
		out.SourceRepo = res.Signature.Certificate.SourceRepositoryURI
		out.RunnerEnvironment = res.Signature.Certificate.RunnerEnvironment
	}
	if entries := b.GetVerificationMaterial().GetTlogEntries(); len(entries) > 0 {
		out.LogIndex = entries[0].GetLogIndex()
	}
	if res.Statement != nil {
		out.PredicateType = res.Statement.GetPredicateType()
		if p := res.Statement.GetPredicate(); p != nil {
			m := p.AsMap()
			if rd, ok := m["runDetails"].(map[string]any); ok {
				if bl, ok := rd["builder"].(map[string]any); ok {
					out.BuilderID, _ = bl["id"].(string)
				}
			} else if bl, ok := m["builder"].(map[string]any); ok { // SLSA v0.2
				out.BuilderID, _ = bl["id"].(string)
			}
			if bd, ok := m["buildDefinition"].(map[string]any); ok {
				out.BuildType, _ = bd["buildType"].(string)
			}
		}
	}
	return out
}

// DefaultTrustedBuilders are the builders whose SLSA provenance is accepted
// when the policy names none (trusted_builders): the GitHub-hosted runners
// (SLSA v1), the GitHub runner as npm wrote it into later SLSA v0.2
// statements, the npm CLI as npm 9.5-9.6 wrote it into the first SLSA v0.2
// statements (2023, builds on GitHub Actions), and the runners of GitLab.com.
// An entry that ends with "/" or "@" is a prefix, any other entry must match
// exactly, so ".../runner/self-hosted" is not trusted by default.
var DefaultTrustedBuilders = []string{
	"https://github.com/actions/runner/github-hosted",
	"https://github.com/actions/runner",
	"https://github.com/npm/cli@",
	"https://gitlab.com/gitlab-org/gitlab-runner/",
}

// TrustedBuilder reports whether a builder ID is on the list (FR-08). An
// empty builder ID (a PEP 740 publish attestation, which names no builder)
// is not judged.
func TrustedBuilder(id string, list []string) bool {
	if id == "" {
		return true
	}
	if len(list) == 0 {
		list = DefaultTrustedBuilders
	}
	for _, b := range list {
		if id == b || (strings.HasSuffix(b, "/") || strings.HasSuffix(b, "@")) && strings.HasPrefix(id, b) {
			return true
		}
	}
	return false
}

// GitHubWorkflowBuildType is the build type of GitHub artifact attestations
// (actions/attest-build-provenance). Their builder ID is the workflow that
// ran the build, e.g. https://github.com/OWNER/REPO/.github/workflows/
// release.yml@refs/tags/v1.0.0, not the runner as in npm provenance.
const GitHubWorkflowBuildType = "https://actions.github.io/buildtypes/workflow/v1"

// Trusted judges a verified result: its builder must be trusted, and with
// the default list a certificate that states a self-hosted GitHub runner is
// not trusted either, whatever builder ID the statement names (the SLSA v0.2
// statements of npm do not tell hosted and self-hosted runners apart).
// With the default list a GitHub artifact attestation is trusted when the
// Fulcio certificate of GitHub Actions states a GitHub-hosted runner and the
// builder is the workflow that signed the statement: the build then ran on a
// GitHub-hosted runner, as with the runner builder IDs of the list.
func Trusted(r Result, list []string) bool {
	if len(list) == 0 {
		if r.RunnerEnvironment == "self-hosted" {
			return false
		}
		if r.BuildType == GitHubWorkflowBuildType && r.Issuer == GitHubActions &&
			r.RunnerEnvironment == "github-hosted" && r.BuilderID != "" && r.BuilderID == r.SignerSAN {
			return true
		}
	}
	return TrustedBuilder(r.BuilderID, list)
}
