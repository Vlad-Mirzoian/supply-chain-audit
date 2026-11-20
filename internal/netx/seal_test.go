package netx

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// A sealed snapshot is checked as it is read in offline runs: unchanged
// entries are served, an entry changed after sealing or added to it is a
// self-check failure (ErrSeal, exit code 4), and so is a manifest that does
// not match its own ID. Online runs do not use the seal.
func TestSealedSnapshot(t *testing.T) {
	dir := t.TempDir()
	on := New(dir, false)
	u1, u2 := "https://api.osv.dev/v1/vulns/A", "https://registry.npmjs.org/a"
	k1 := on.key(http.MethodGet, u1, nil, "application/json")
	k2 := on.key(http.MethodGet, u2, nil, "application/json")
	on.store(k1, u1, 200, []byte(`{"id":"A"}`))
	on.store(k2, u2, 200, []byte(`{"name":"a"}`))
	os.WriteFile(dir+"/sigstore-trusted_root.json", []byte(`{}`), 0o644)
	s, err := SealCache(dir, time.Now())
	if err != nil || len(s.Files) != 3 || !strings.HasPrefix(s.ID, "sha256:") {
		t.Fatalf("seal %+v, %v", s, err)
	}
	ctx := context.Background()

	off := New(dir, true)
	if off.Seal == nil || off.Seal.ID != s.ID {
		t.Fatalf("offline client did not load the seal")
	}
	if b, err := off.Get(ctx, u1, "application/json"); err != nil || string(b) != `{"id":"A"}` || off.SealError() != nil {
		t.Fatalf("unchanged entry: %q %v %v", b, err, off.SealError())
	}

	// an entry changed after sealing
	p := off.path(k2)
	raw, _ := os.ReadFile(p)
	os.WriteFile(p, append(append([]byte{}, raw...), ' '), 0o644) // still valid JSON
	off = New(dir, true)
	if _, err := off.Get(ctx, u2, "application/json"); !errors.Is(err, ErrSeal) || !errors.Is(off.SealError(), ErrSeal) {
		t.Errorf("changed entry: %v / %v", err, off.SealError())
	}
	os.WriteFile(p, raw, 0o644)

	// an entry added after sealing
	u3 := "https://registry.npmjs.org/c"
	on.store(on.key(http.MethodGet, u3, nil, "application/json"), u3, 200, []byte(`{"name":"c"}`))
	off = New(dir, true)
	if _, err := off.Get(ctx, u3, "application/json"); !errors.Is(err, ErrSeal) {
		t.Errorf("added entry: %v", err)
	}
	// online runs refresh the cache and ignore the seal
	if New(dir, false).Seal != nil {
		t.Errorf("online client loaded the seal")
	}

	// a manifest edited by hand no longer matches its ID
	m, _ := os.ReadFile(dir + "/" + SealFile)
	os.WriteFile(dir+"/"+SealFile, []byte(strings.Replace(string(m), s.Files[k1[:2]+"/"+k1+".json"], strings.Repeat("0", 64), 1)), 0o644)
	if _, err := LoadSeal(dir); !errors.Is(err, ErrSeal) {
		t.Errorf("edited manifest: %v", err)
	}
	if off := New(dir, true); !errors.Is(off.SealError(), ErrSeal) {
		t.Errorf("edited manifest not reported by the client")
	}
}
