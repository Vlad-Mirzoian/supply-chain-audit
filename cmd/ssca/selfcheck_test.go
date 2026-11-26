package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Every command that reads a data snapshot offline stops with exit code 4
// on a damaged seal manifest, as scan does, and prints no result; online
// runs ignore the seal.
func TestSealSelfCheckAllCommands(t *testing.T) {
	proj := filepath.Join("..", "..", "testdata", "npm-v3")
	art := filepath.Join("..", "..", "testdata", "sigstore", "acme-orders-api-1.4.0.tgz")
	damaged := t.TempDir()
	os.WriteFile(filepath.Join(damaged, netx.SealFile), []byte("{"), 0o644)
	a := cdx(t, "2026-03-20T00:00:00Z", "lodash@4.17.21")
	b := cdx(t, "2026-03-31T00:00:00Z", "lodash@4.17.21", "plain-crypto-js@4.2.1")
	for _, args := range [][]string{
		{"graph", "--offline", "--cache", damaged, proj},
		{"graph", "--offline", "--cache", damaged, "--json", proj},
		{"sbom", "--offline", "--cache", damaged, "--out", t.TempDir(), proj},
		{"sbom", "--offline", "--cache", damaged, "--no-enrich", "--out", t.TempDir(), proj},
		{"scan", "--offline", "--cache", damaged, "--quiet", "--out", t.TempDir(), proj},
		{"verify-artifact", "--offline", "--cache", damaged, art},
		{"typosquat", "--offline", "--cache", damaged, "loadsh"},
		{"diff", "--offline", "--cache", damaged, "--mode", "release-vs-release", a, b},
	} {
		if code, out := stdout(t, args...); code != exitSelfCheck || out != "" {
			t.Errorf("ssca %v: exit %d, want %d without output; output:\n%s", args[:1], code, exitSelfCheck, out)
		}
	}
	// sbom writes no SBOM after a failed self-check
	out := t.TempDir()
	run([]string{"sbom", "--offline", "--cache", damaged, "--out", out, proj})
	if _, err := os.Stat(filepath.Join(out, "sbom.cdx.json")); err == nil {
		t.Error("sbom wrote an SBOM after a failed self-check")
	}
}

// verify-artifact --offline checks the saved trusted root of a sealed
// snapshot against the seal: a copy changed after sealing is a self-check
// failure, not a verification against an untrusted root.
func TestVerifyArtifactSealedRoot(t *testing.T) {
	art := filepath.Join("..", "..", "testdata", "sigstore", "acme-orders-api-1.4.0.tgz")
	root, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sigstore", "trusted_root-2026-11-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	os.WriteFile(filepath.Join(cache, "sigstore-trusted_root.json"), root, 0o644)
	if _, err := netx.SealCache(cache, time.Now()); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"verify-artifact", "--offline", "--cache", cache, art}); code != exitOK {
		t.Fatalf("sealed, unchanged root: exit %d, want %d", code, exitOK)
	}
	os.WriteFile(filepath.Join(cache, "sigstore-trusted_root.json"), append(root, '\n'), 0o644)
	if code := run([]string{"verify-artifact", "--offline", "--cache", cache, art}); code != exitSelfCheck {
		t.Errorf("sealed, changed root: exit %d, want %d", code, exitSelfCheck)
	}
	// without a saved copy the result is incomplete, and the output says why
	code, out := stdout(t, "verify-artifact", "--offline", "--cache", t.TempDir(), art)
	if code != exitIncomplete || !strings.Contains(out, "no saved copy in ") {
		t.Errorf("no saved root: exit %d:\n%s", code, out)
	}
}

// ssca help COMMAND prints the help of the command; flags that only one
// mode reads are usage errors in the other modes instead of being ignored.
func TestHelpCommandAndIgnoredFlags(t *testing.T) {
	sb := cdx(t, "2026-03-20T00:00:00Z", "lodash@4.17.21")
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"help", "scan"}, exitOK},
		{[]string{"help", "cache"}, exitOK},
		{[]string{"help", "bogus"}, exitUsage},
		{[]string{"help"}, exitOK},
		{[]string{"diff", "--now", "2026-01-01T00:00:00Z", sb, sb}, exitUsage},
		{[]string{"diff", "--offline", sb, sb}, exitUsage},
		{[]string{"diff", "--mode", "vendor-vs-generated", "--cache", t.TempDir(), sb, sb}, exitUsage},
		{[]string{"diff", sb, sb}, exitOK},
		{[]string{"sbom", "--offline", "--validate", sb}, exitUsage},
		{[]string{"sbom", "--cache", t.TempDir(), "--validate", sb}, exitUsage},
	} {
		if got := run(c.args); got != c.want {
			t.Errorf("ssca %v: exit %d, want %d", c.args, got, c.want)
		}
	}
}

// release-vs-release does not take a package for an old one when its age
// cannot be judged: a first release after the reference time (a wrong
// timestamp, or a name registered again) is an unknown age, exit code 2.
func TestDiffFirstReleaseAfterReference(t *testing.T) {
	registryMock(t)
	a := cdx(t, "2026-03-01T00:00:00Z", "lodash@4.17.21")
	b := cdx(t, "2026-03-02T00:00:00Z", "lodash@4.17.21", "plain-crypto-js@4.2.1")
	code, out := stdout(t, "diff", "--cache", t.TempDir(), "--mode", "release-vs-release", a, b)
	if code != exitIncomplete || !strings.Contains(out, "npm/plain-crypto-js: first release 2026-03-30 is later than 2026-03-02") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}
