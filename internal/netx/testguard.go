package netx

import (
	"fmt"
	"net"
	"net/http"
	"testing"
)

// loopbackOnly is the transport of every client created inside a test binary:
// tests use httptest servers on the loopback interface, and a request to any
// other host means that a test forgot to redirect a data source. Refusing it
// keeps the test suite offline and deterministic (also in CI).
type loopbackOnly struct{ next http.RoundTripper }

func (t loopbackOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	host := r.URL.Hostname()
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("netx: test tried to reach external host %s (redirect the data source to an httptest server)", host)
	}
	return t.next.RoundTrip(r)
}

func testTransport() http.RoundTripper {
	if testing.Testing() {
		return loopbackOnly{http.DefaultTransport}
	}
	return nil // http.DefaultTransport
}
