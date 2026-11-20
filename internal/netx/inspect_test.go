package netx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The state of a cache is read from the entries: per source, with the
// responses that an online run would reuse, and the body is not needed.
func TestInspectCache(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, false)
	c.store(strings.Repeat("a", 64), "https://api.osv.dev/v1/query", 200, []byte(`{}`))
	c.store(strings.Repeat("b", 64), "https://api.osv.dev/v1/vulns/X", 404, nil)
	c.store(strings.Repeat("c", 64), "https://registry.npmjs.org/a", 200, []byte(`{"name":"a"}`))
	now := time.Now().Add(2 * time.Hour)
	st, err := InspectCache(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Responses != 3 || st.Fresh != 3 || st.Unreadable != 0 || st.Bytes == 0 || len(st.Hosts) != 2 {
		t.Fatalf("state %+v", st)
	}
	if h := st.Hosts[0]; h.Host != "api.osv.dev" || h.Responses != 2 || h.NotFound != 1 || h.Newest.IsZero() {
		t.Errorf("first source %+v", h)
	}
	if st, _ = InspectCache(dir, now.Add(25*time.Hour)); st.Fresh != 0 || st.Responses != 3 {
		t.Errorf("after the TTL: %+v", st)
	}

	// other files of the cache are not entries; a damaged entry is counted
	os.WriteFile(filepath.Join(dir, "sigstore-trusted_root.json"), []byte(`{}`), 0o644)
	os.MkdirAll(filepath.Join(dir, "sigstore-tuf"), 0o755)
	os.WriteFile(filepath.Join(dir, "aa", "broken.json"), []byte(`{"url"`), 0o644)
	if st, _ = InspectCache(dir, now); st.Responses != 3 || st.Unreadable != 1 {
		t.Errorf("with a damaged entry: %+v", st)
	}

	empty, err := InspectCache(t.TempDir(), now)
	if err != nil || empty.Responses != 0 || !empty.Oldest.IsZero() {
		t.Errorf("empty cache: %+v, %v", empty, err)
	}
}
