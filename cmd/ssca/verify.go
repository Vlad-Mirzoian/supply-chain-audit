// verify-artifact: verification of a file against a Sigstore bundle (M3).

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/integrity"
)

// cmdVerifyArtifact verifies a build artifact against its Sigstore bundle and
// the expected signer identity; a missing bundle is an unsigned artifact.
func cmdVerifyArtifact(args []string) int {
	fset := flag.NewFlagSet("verify-artifact", flag.ContinueOnError)
	g := addNet(fset)
	bundlePath := fset.String("bundle", "", "Sigstore bundle (default: <artifact>.sigstore.json)")
	repo := fset.String("repo", "", "expected GitHub repository owner/name of the signing workflow")
	digest := fset.String("sha512", "", "verify against this hex SHA-512 digest instead of the file")
	asJSON := fset.Bool("json", false, "print the verification result as JSON")
	builders := fset.String("builder", "", "comma-separated trusted SLSA builder IDs (a trailing / makes a prefix); default: GitHub-hosted and GitLab.com runners")
	if code, ok := parseArgs(fset, args); !ok {
		return code
	}
	if fset.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: ssca verify-artifact [--bundle B] [--repo owner/name] [--builder IDS] [--sha512 HEX] [--json] ARTIFACT")
		return exitUsage
	}
	art := fset.Arg(0)
	var want []byte
	if *digest != "" {
		d, err := hex.DecodeString(*digest)
		if err != nil || len(d) != 64 {
			fmt.Fprintf(os.Stderr, "error: --sha512 %q is not a hex SHA-512 digest (128 hex digits)\n", *digest)
			return exitUsage
		}
		want = d
	} else if st, err := os.Stat(art); err != nil || st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: artifact %s is not a readable file\n", art)
		return exitUsage
	}
	if *bundlePath == "" {
		*bundlePath = art + ".sigstore.json"
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		if *asJSON {
			printJSON(integrity.Result{Error: "unsigned artifact: no Sigstore bundle: " + err.Error()})
		} else {
			fmt.Printf("FAIL unsigned artifact: %s has no Sigstore bundle\n", art)
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Printf("  bundle       %s not found (--bundle gives another path)\n", *bundlePath)
			} else {
				fmt.Printf("  bundle       %v\n", err)
			}
		}
		return exitViolation
	}
	trust := &integrity.Trust{CacheDir: g.cacheDir, Offline: g.offline}
	tr, err := trust.Root()
	if err != nil {
		if *asJSON {
			printJSON(integrity.Result{Error: "trusted root: " + err.Error(), Unavailable: true})
		} else {
			fmt.Println("INCOMPLETE signature not checked:", art)
			fmt.Printf("  %-12s %v\n", "trusted root", err)
		}
		return exitIncomplete
	}
	var id *integrity.Identity
	if *repo != "" {
		x := integrity.RepoIdentity(*repo)
		id = &x
	}
	var body []byte
	if want == nil {
		if body, err = os.ReadFile(art); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitUsage
		}
	}
	verifyWith := func(id *integrity.Identity) integrity.Result {
		if want != nil {
			return integrity.VerifyBundle(tr, raw, "sha512", want, nil, id)
		}
		return integrity.VerifyBundle(tr, raw, "", nil, body, id)
	}
	res := verifyWith(id)
	res.TrustedRootCopy = trust.SavedCopy(time.Now())
	var trusted []string
	if *builders != "" {
		trusted = strings.Split(*builders, ",")
	}
	if res.Verified && !integrity.Trusted(res, trusted) {
		// a valid signature, but the build ran on a builder that is not
		// trusted (FR-08): the release gate does not accept it
		res.Verified = false
		res.Error = "untrusted builder: " + res.BuilderID
	}
	if *asJSON {
		printJSON(res)
	} else {
		// when the signer identity is rejected, the signature is verified
		// once more without it to name the identity that did sign
		var actual integrity.Result
		if !res.Verified && id != nil {
			actual = verifyWith(nil)
		}
		printVerify(os.Stdout, art, *repo, res, actual)
	}
	if !res.Verified {
		return exitViolation
	}
	return exitOK
}

func printJSON(v any) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// printVerify is the text form of the result: the decision first, then the
// identity and provenance of a verified artifact or the reason of a failure.
// actual is the result without the identity check (only after a failure).
func printVerify(w io.Writer, art, repo string, res, actual integrity.Result) {
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "  %-12s %s\n", k, v)
		}
	}
	rootRow := func() {
		if res.TrustedRootCopy != nil {
			row("trusted root", res.TrustedRootCopy.String())
		}
	}
	if res.Verified {
		fmt.Fprintln(w, "OK artifact verified:", art)
		rootRow()
		row("signer", res.SignerSAN)
		row("issuer", res.Issuer)
		row("repository", res.SourceRepo)
		row("builder", res.BuilderID)
		row("build type", res.BuildType)
		row("provenance", res.PredicateType)
		if res.LogIndex > 0 {
			row("rekor", fmt.Sprintf("log index %d", res.LogIndex))
		}
		if repo == "" {
			row("note", "the signer was not checked; --repo owner/name requires a workflow of that repository")
		}
		return
	}
	fmt.Fprintln(w, "FAIL artifact signature or provenance does not verify:", art)
	rootRow()
	switch {
	case strings.HasPrefix(res.Error, "untrusted builder: "):
		row("reason", "built by a builder that is not trusted (--builder)")
		row("builder", strings.TrimPrefix(res.Error, "untrusted builder: "))
		row("signer", res.SignerSAN)
	case actual.Verified:
		row("reason", "signed by another identity than expected")
		row("expected", "a workflow of github.com/"+strings.TrimPrefix(repo, "github.com/"))
		row("signer", actual.SignerSAN)
	case strings.Contains(res.Error, "digests do not match"):
		row("reason", "the file is not the one that was signed (its digest differs)")
		row("error", res.Error)
	case strings.HasPrefix(res.Error, "bundle: "):
		row("reason", "the bundle is not a valid Sigstore bundle")
		row("error", res.Error)
	default:
		row("error", res.Error)
	}
}
