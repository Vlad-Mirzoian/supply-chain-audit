// Package netx is the network layer shared by all data-source adapters. It
// caches every response on disk, so that a run can be repeated offline from
// the same data snapshot (NFR-03, NFR-06, NFR-10), limits concurrency per
// host and validates response sizes at trust boundary TB-A.
package netx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// homeURL is model.HomeURL (netx does not import the data model).
const homeURL = "https://github.com/Vlad-Mirzoian/supply-chain-audit"

// DefaultTTL is how long an online run reuses a cached response.
const DefaultTTL = 24 * time.Hour

// MaxBody is the largest response accepted from any external source.
const MaxBody = 256 << 20

// ErrNotFound is returned for HTTP 404 responses.
var ErrNotFound = errors.New("not found")

// ErrOffline is returned when a response is not cached in offline mode.
var ErrOffline = errors.New("not in offline snapshot")

// Client is a caching HTTP client.
type Client struct {
	HTTP      *http.Client
	CacheDir  string
	Offline   bool
	TTL       time.Duration
	UserAgent string

	mu       sync.Mutex
	hostSem  map[string]chan struct{}
	used     map[string]string // cache key -> body hash, for the snapshot id
	inflight map[string]*call

	Requests  atomic.Int64 // network requests actually sent
	CacheHits atomic.Int64

	// Seal is the manifest of a sealed snapshot, checked in offline runs
	// (nil when the cache is not sealed or the run is online).
	Seal    *Seal
	sealErr error
}

// SealError returns the first file of a sealed snapshot that did not match
// its manifest (nil if none): a self-check failure, exit code 4.
func (c *Client) SealError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sealErr
}

func (c *Client) sealFailed(err error) {
	c.mu.Lock()
	if c.sealErr == nil {
		c.sealErr = err
	}
	c.mu.Unlock()
}

type call struct {
	wg   sync.WaitGroup
	body []byte
	err  error
}

// New creates a client. cacheDir may be empty to disable the disk cache.
func New(cacheDir string, offline bool) *Client {
	c := &Client{
		HTTP:      &http.Client{Timeout: 60 * time.Second, Transport: testTransport()},
		CacheDir:  cacheDir,
		Offline:   offline,
		TTL:       DefaultTTL,
		UserAgent: "ssca (+" + homeURL + ")",
		hostSem:   map[string]chan struct{}{},
		used:      map[string]string{},
		inflight:  map[string]*call{},
	}
	if offline && cacheDir != "" {
		c.Seal, c.sealErr = LoadSeal(cacheDir)
	}
	return c
}

type cacheEntry struct {
	URL     string    `json:"url"`
	Status  int       `json:"status"`
	Fetched time.Time `json:"fetched"`
	Body    []byte    `json:"body"`
}

func (c *Client) key(method, u string, body []byte, accept string) string {
	h := sha256.New()
	io.WriteString(h, method+" "+u+" "+accept+"\n")
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) sem(host string) chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.hostSem[host]
	if !ok {
		n := 16
		if strings.Contains(host, "api.first.org") {
			n = 2
		}
		s = make(chan struct{}, n)
		c.hostSem[host] = s
	}
	return s
}

// Get fetches a URL with the given Accept header.
func (c *Client) Get(ctx context.Context, u, accept string) ([]byte, error) {
	return c.Do(ctx, http.MethodGet, u, nil, accept)
}

// GetJSON fetches and decodes a JSON document.
func (c *Client) GetJSON(ctx context.Context, u string, v any) error {
	b, err := c.Get(ctx, u, "application/json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// PostJSON posts a JSON body and decodes the JSON response.
func (c *Client) PostJSON(ctx context.Context, u string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	b, err := c.Do(ctx, http.MethodPost, u, body, "application/json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Do performs a request through the cache. Concurrent identical requests
// are collapsed into one.
func (c *Client) Do(ctx context.Context, method, u string, body []byte, accept string) ([]byte, error) {
	k := c.key(method, u, body, accept)
	c.mu.Lock()
	if cl, ok := c.inflight[k]; ok {
		c.mu.Unlock()
		cl.wg.Wait()
		return cl.body, cl.err
	}
	cl := &call{}
	cl.wg.Add(1)
	c.inflight[k] = cl
	c.mu.Unlock()

	cl.body, cl.err = c.do(ctx, k, method, u, body, accept)
	cl.wg.Done()
	c.mu.Lock()
	delete(c.inflight, k)
	c.mu.Unlock()
	return cl.body, cl.err
}

func (c *Client) path(k string) string {
	return filepath.Join(c.CacheDir, k[:2], k+".json")
}

func (c *Client) record(k string, status int, b []byte) {
	h := sha256.Sum256(append([]byte(fmt.Sprint(status)), b...))
	c.mu.Lock()
	c.used[k] = hex.EncodeToString(h[:8])
	c.mu.Unlock()
}

func (c *Client) do(ctx context.Context, k, method, u string, body []byte, accept string) ([]byte, error) {
	if c.CacheDir != "" {
		if raw, err := os.ReadFile(c.path(k)); err == nil {
			if c.Offline && c.Seal != nil {
				if err := c.Seal.Check(k[:2]+"/"+k+".json", raw); err != nil {
					c.sealFailed(err)
					return nil, err
				}
			}
			var e cacheEntry
			if json.Unmarshal(raw, &e) == nil && (c.Offline || time.Since(e.Fetched) < c.TTL) {
				c.CacheHits.Add(1)
				c.record(k, e.Status, e.Body)
				if e.Status == http.StatusNotFound {
					return nil, ErrNotFound
				}
				return e.Body, nil
			}
		}
	}
	if c.Offline {
		return nil, fmt.Errorf("%w: %s", ErrOffline, u)
	}
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	s := c.sem(pu.Host)
	select {
	case s <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s }()

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", c.UserAgent)
		c.Requests.Add(1)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if len(b) > MaxBody {
			return nil, fmt.Errorf("response from %s exceeds size limit", pu.Host)
		}
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			c.store(k, u, resp.StatusCode, nil)
			c.record(k, resp.StatusCode, nil)
			return nil, ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
			time.Sleep(2 * time.Second)
			continue
		case resp.StatusCode >= 300:
			return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
		}
		c.store(k, u, resp.StatusCode, b)
		c.record(k, resp.StatusCode, b)
		return b, nil
	}
	return nil, lastErr
}

func (c *Client) store(k, u string, status int, b []byte) {
	if c.CacheDir == "" {
		return
	}
	raw, _ := json.Marshal(cacheEntry{URL: u, Status: status, Fetched: time.Now().UTC(), Body: b})
	p := c.path(k)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := p + ".tmp" + fmt.Sprint(time.Now().UnixNano())
	if os.WriteFile(tmp, raw, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
}

// SnapshotID summarises all external responses used in this run. Two runs
// with the same snapshot id saw identical external data.
func (c *Client) SnapshotID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keys := make([]string, 0, len(c.used))
	for k := range c.used {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		io.WriteString(h, k+"="+c.used[k]+"\n")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:32]
}
