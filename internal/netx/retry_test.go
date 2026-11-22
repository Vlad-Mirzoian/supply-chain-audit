package netx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// After HTTP 429 the client waits as long as the server asks with
// Retry-After (capped at MaxRetryAfter) instead of its own back-off, and
// then retries; without the header it waits defaultRetryDelay.
func TestRetryAfter(t *testing.T) {
	var waits []time.Duration
	old := sleep
	sleep = func(ctx context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	defer func() { sleep = old }()

	for _, c := range []struct {
		header string
		want   time.Duration
	}{
		{"7", 7 * time.Second},
		{"3600", MaxRetryAfter},     // capped
		{"", defaultRetryDelay},     // no header
		{"soon", defaultRetryDelay}, // unreadable
		{"0", 0},                    // retry at once
	} {
		var n atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) == 1 {
				if c.header != "" {
					w.Header().Set("Retry-After", c.header)
				}
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Write([]byte("ok"))
		}))
		waits = nil
		b, err := New("", false).Get(context.Background(), srv.URL, "")
		srv.Close()
		if err != nil || string(b) != "ok" || n.Load() != 2 {
			t.Fatalf("Retry-After %q: %q %v after %d requests", c.header, b, err, n.Load())
		}
		// one wait after the 429; the back-off of the second attempt is skipped
		// only when the server gave the delay
		want := []time.Duration{c.want}
		if c.header == "" || c.header == "soon" {
			want = append(want, 500*time.Millisecond)
		}
		if len(waits) != len(want) || waits[0] != want[0] || (len(want) == 2 && waits[1] != want[1]) {
			t.Errorf("Retry-After %q: waits %v, want %v", c.header, waits, want)
		}
	}
	// an HTTP date
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if d, given := retryDelay(now.Add(30*time.Second).Format(http.TimeFormat), now); d != 30*time.Second || !given {
		t.Errorf("HTTP date: %v %v", d, given)
	}
	if d, _ := retryDelay(now.Add(-time.Minute).Format(http.TimeFormat), now); d != 0 {
		t.Errorf("date in the past: %v", d)
	}
}
