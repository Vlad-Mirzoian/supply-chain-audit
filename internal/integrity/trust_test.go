package integrity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// stubTUF replaces the TUF download for one test.
func stubTUF(t *testing.T, f func(string) ([]byte, error)) {
	t.Helper()
	old := fetchTUF
	fetchTUF = f
	t.Cleanup(func() { fetchTUF = old })
}

// Online, a TUF failure must not silently fall back to a saved copy of any
// age, even a valid one: nothing is verified against it.
func TestTrustOnlineFailureDoesNotUseCopy(t *testing.T) {
	dir := t.TempDir()
	trustedRoot(t, dir)
	stubTUF(t, func(string) ([]byte, error) { return nil, errors.New("connection refused") })
	tr := &Trust{CacheDir: dir}
	r, err := tr.Root()
	if r != nil || err == nil || !strings.Contains(err.Error(), "sigstore TUF: connection refused") {
		t.Fatalf("root %v, error %v; want no root and the TUF error", r, err)
	}
	if c := tr.SavedCopy(time.Now()); c != nil {
		t.Errorf("online run reports a saved copy: %v", c)
	}
}

// Online with TUF available: the root is used and saved, with its fetch time,
// and no saved copy is reported.
func TestTrustOnlineSavesCopy(t *testing.T) {
	src := t.TempDir()
	trustedRoot(t, src)
	raw, err := os.ReadFile(filepath.Join(src, "sigstore-trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stubTUF(t, func(string) ([]byte, error) { return raw, nil })
	tr := &Trust{CacheDir: dir}
	if r, err := tr.Root(); r == nil || err != nil {
		t.Fatalf("root %v, error %v", r, err)
	}
	if tr.SavedCopy(time.Now()) != nil {
		t.Error("online run with TUF reports a saved copy")
	}
	snap := filepath.Join(dir, "sigstore-trusted_root.json")
	if b, err := os.ReadFile(snap); err != nil || string(b) != string(raw) {
		t.Errorf("copy not saved: %v", err)
	}
	if time.Since(copyFetched(snap)) > time.Minute {
		t.Errorf("fetch time not recorded: %v", copyFetched(snap))
	}
}

// --offline uses the copy and reports its age: from the recorded fetch time,
// which survives a plain copy of the snapshot, else from the file time.
func TestTrustOfflineReportsAge(t *testing.T) {
	stubTUF(t, func(string) ([]byte, error) { t.Error("--offline must not contact TUF"); return nil, errors.New("no") })
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	dir := t.TempDir()
	trustedRoot(t, dir)
	snap := filepath.Join(dir, "sigstore-trusted_root.json")
	old := now.Add(-3 * 24 * time.Hour)
	if err := os.Chtimes(snap, old, old); err != nil {
		t.Fatal(err)
	}
	tr := &Trust{CacheDir: dir, Offline: true}
	if r, err := tr.Root(); r == nil || err != nil {
		t.Fatalf("root %v, error %v", r, err)
	}
	if c := tr.SavedCopy(now); c == nil || c.AgeDays != 3 {
		t.Errorf("age by file time: %v, want 3 days", c)
	}

	dir = t.TempDir()
	trustedRoot(t, dir) // file time is now, the recorded time is older
	os.WriteFile(filepath.Join(dir, "sigstore-trusted_root.json"+fetchedSuffix), []byte("2026-10-30T12:00:00Z\n"), 0o644)
	tr = &Trust{CacheDir: dir, Offline: true}
	tr.Root()
	c := tr.SavedCopy(now)
	if c == nil || c.AgeDays != 10 || !strings.Contains(c.String(), "2026-10-30, 10 days old") {
		t.Errorf("age by recorded time: %v", c)
	}

	if c := (&Trust{CacheDir: dir, Offline: true}).SavedCopy(now); c != nil {
		t.Errorf("a root that was never loaded is reported: %v", c)
	}
}

// Without a trusted root a package that the policy requires to be signed is
// "not checked": the analysis is incomplete, the package is not reported as
// unsigned (which would be exit code 1 for a package with valid provenance).
func TestNoTrustedRootIsNotUnsigned(t *testing.T) {
	stubTUF(t, func(string) ([]byte, error) { return nil, errors.New("connection refused") })
	cache := t.TempDir()
	v := &Verifier{Net: netx.New(cache, true), Trust: &Trust{CacheDir: cache}, Provenance: true, Expect: map[string]string{"demo": "github.com/acme/demo"}}
	c := model.NewComponent(model.NPM, "", "demo", "1.0.0")
	c.Meta = &model.PackageMeta{HasProvenance: true}
	fs, r, _ := v.checkOne(context.Background(), c)
	if r == nil || !r.Unavailable || r.Verified {
		t.Fatalf("result %+v, want unavailable", r)
	}
	for _, f := range fs {
		if f.Kind == model.KindProvenance {
			t.Errorf("provenance finding without a check: %s %s", f.ID, f.Detail)
		}
	}
	// a package without any provenance is still reported as unsigned
	c2 := model.NewComponent(model.NPM, "", "demo", "1.0.0")
	c2.Meta = &model.PackageMeta{}
	fs, _, _ = v.checkOne(context.Background(), c2)
	unsigned := false
	for _, f := range fs {
		unsigned = unsigned || f.ID == "SSCA-UNSIGNED"
	}
	if !unsigned {
		t.Errorf("package without provenance not reported: %+v", fs)
	}
}

// The sha512 value is found also in an SRI string with several hashes.
func TestSriDigestSeveralHashes(t *testing.T) {
	c := model.NewComponent(model.NPM, "", "demo", "1.0.0")
	c.Integrity = []string{"sha1-AAAA sha512-AQID"}
	if b, alg := sriDigest(c); alg != "sha512" || string(b) != "\x01\x02\x03" {
		t.Errorf("digest %x, algorithm %q", b, alg)
	}
}
