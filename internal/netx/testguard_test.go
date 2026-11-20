package netx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Inside a test binary a client reaches only loopback servers, so that a test
// that forgot to redirect a data source fails instead of going online.
func TestClientIsLoopbackOnlyInTests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	c := New("", false)
	if b, err := c.Get(context.Background(), srv.URL, ""); err != nil || string(b) != "ok" {
		t.Fatalf("loopback request: %q %v", b, err)
	}
	_, err := c.Get(context.Background(), "https://registry.npmjs.org/left-pad", "")
	if err == nil || !strings.Contains(err.Error(), "external host registry.npmjs.org") {
		t.Fatalf("external request not refused: %v", err)
	}
}

// The User-Agent names the home page of the suite, as the SARIF reports do.
func TestUserAgentNamesHomePage(t *testing.T) {
	if homeURL != model.HomeURL {
		t.Fatalf("netx home URL %q differs from model.HomeURL %q", homeURL, model.HomeURL)
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.UserAgent() }))
	defer srv.Close()
	if _, err := New("", false).Get(context.Background(), srv.URL, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, model.HomeURL) || strings.Contains(got, "0.9") {
		t.Fatalf("User-Agent %q", got)
	}
}
