package integrity

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// A real npm provenance bundle (sigstore@2.0.0) verifies offline against the
// public-good trusted root; the builder ID of the SLSA statement is read and
// judged against the trusted builders (FR-08): the GitHub-hosted runner is
// trusted by default, a self-hosted runner is not, and a policy list
// replaces the default.
func TestTrustedBuilder(t *testing.T) {
	tr, err := root.NewTrustedRootFromPath("../../testdata/sigstore/public-good.json")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/sigstore/sigstore.js@2.0.0-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := hex.DecodeString("46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c")
	id := RepoIdentity("sigstore/sigstore-js")
	res := VerifyBundle(tr, raw, "sha512", d, nil, &id)
	if !res.Verified || res.BuilderID != "https://github.com/actions/runner/github-hosted" {
		t.Fatalf("verified %v builder %q error %q", res.Verified, res.BuilderID, res.Error)
	}
	if !Trusted(res, nil) {
		t.Errorf("GitHub-hosted runner not trusted by default")
	}
	// a certificate that states a self-hosted runner is not trusted by
	// default, whatever the statement names as builder
	self := res
	self.BuilderID, self.RunnerEnvironment = "https://github.com/npm/cli@9.5.1", "self-hosted"
	if Trusted(self, nil) || !Trusted(self, []string{"https://github.com/npm/cli@"}) {
		t.Errorf("self-hosted runner: default %v, explicit list %v", Trusted(self, nil), Trusted(self, []string{"https://github.com/npm/cli@"}))
	}
	for _, c := range []struct {
		id   string
		list []string
		want bool
	}{
		{"https://github.com/actions/runner/self-hosted", nil, false},
		{"https://github.com/actions/runner", nil, true}, // SLSA v0.2 statements of npm
		{"https://gitlab.com/gitlab-org/gitlab-runner/-/glob/v17.0.0/abc", nil, true},
		{"https://github.com/actions/runner/github-hosted", []string{"https://builder.example/"}, false},
		{"https://builder.example/ci/1", []string{"https://builder.example/"}, true},
		{"", nil, true}, // PEP 740 publish attestations name no builder
		{"https://github.com/npm/cli@9.5.1", nil, true}, // first SLSA v0.2 statements of npm
		{"https://github.com/npm/clix", nil, false},
	} {
		if got := TrustedBuilder(c.id, c.list); got != c.want {
			t.Errorf("TrustedBuilder(%q, %v) = %v", c.id, c.list, got)
		}
	}
}
