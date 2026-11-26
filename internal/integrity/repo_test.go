package integrity

import (
	"regexp"
	"testing"
)

// The expected repository of require_provenance and verify-artifact --repo
// is compared by whole path segments: a repository whose owner or name only
// contains the expected one must not pass (it did with a substring test).
func TestFromRepo(t *testing.T) {
	res := func(repo, san string) Result { return Result{Verified: true, SourceRepo: repo, SignerSAN: san} }
	axios := res("https://github.com/axios/axios", "https://github.com/axios/axios/.github/workflows/publish.yml@refs/tags/v1.21.0")
	for _, exp := range []string{"github.com/axios/axios", "axios/axios", "https://github.com/Axios/Axios", "axios/axios/", "github.com/axios/axios.git"} {
		if !FromRepo(axios, exp) {
			t.Errorf("%q: axios/axios not accepted", exp)
		}
	}
	// a reusable workflow of another repository signs, the certificate names the source
	gen := res("https://github.com/axios/axios", "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator.yml@refs/tags/v2.0.0")
	if !FromRepo(gen, "github.com/axios/axios") {
		t.Error("source repository of a reusable-workflow signature not accepted")
	}
	for name, r := range map[string]Result{
		"owner ends with the expected owner": res("https://github.com/evil-axios/axios", "https://github.com/evil-axios/axios/.github/workflows/p.yml@refs/heads/main"),
		"name starts with the expected name": res("https://github.com/axios/axios-fork", "https://github.com/axios/axios-fork/.github/workflows/p.yml@refs/heads/main"),
		"other host":                         res("https://gitlab.com/axios/axios", "https://gitlab.com/axios/axios//.gitlab-ci.yml@refs/heads/main"),
	} {
		if FromRepo(r, "github.com/axios/axios") {
			t.Errorf("%s: accepted as axios/axios", name)
		}
	}
	if !FromRepo(res("", "https://gitlab.com/group/project//.gitlab-ci.yml@refs/heads/main"), "gitlab.com/group/project") {
		t.Error("GitLab signing identity not accepted")
	}
}

func TestRepoIdentity(t *testing.T) {
	san := "https://github.com/Vlad-Mirzoian/supply-chain-audit/.github/workflows/release.yml@refs/tags/v1.0.6"
	for _, repo := range []string{"Vlad-Mirzoian/supply-chain-audit", "vlad-mirzoian/supply-chain-audit", "github.com/Vlad-Mirzoian/supply-chain-audit",
		"https://github.com/Vlad-Mirzoian/supply-chain-audit", "Vlad-Mirzoian/supply-chain-audit/"} {
		if !regexp.MustCompile(RepoIdentity(repo).SANRegexp).MatchString(san) {
			t.Errorf("%q does not match the signer %s", repo, san)
		}
	}
	if regexp.MustCompile(RepoIdentity("Vlad-Mirzoian/supply-chain").SANRegexp).MatchString(san) {
		t.Error("a repository name prefix matched")
	}
}
