package maven

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

func TestSupplierAndJarSHA1(t *testing.T) {
	sha := strings.Repeat("Ab", 20)
	pom := func(a, extra string) string {
		return `<project><groupId>g</groupId><artifactId>` + a + `</artifactId><version>1</version>` + extra + `</project>`
	}
	parent := `<parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent>`
	dev := `<developers><developer><name>  Dan   D </name></developer></developers>`
	files := map[string]string{
		"/g/p/1/p-1.pom":          pom("p", `<organization><name>The Org</name></organization>`),
		"/g/kid/1/kid-1.pom":      pom("kid", parent+dev),
		"/g/dev/1/dev-1.pom":      pom("dev", dev),
		"/g/var/1/var-1.pom":      pom("var", `<organization><name>${org}</name></organization>`),
		"/g/kid/1/kid-1.jar.sha1": sha + "  kid-1.jar\n",
		"/g/dev/1/dev-1.jar.sha1": "not a hash\n",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprint(w, b)
	}))
	defer srv.Close()
	old := Central
	Central = srv.URL
	defer func() { Central = old }()
	r := NewRepo(netx.New("", false))
	ctx := context.Background()
	for _, tc := range []struct {
		a, want string
		org     bool
	}{{"kid", "The Org", true}, {"dev", "Dan D", false}, {"var", "", false}, {"none", "", false}} {
		if s, org := r.Supplier(ctx, "g", tc.a, "1"); s != tc.want || org != tc.org {
			t.Errorf("%s: %q %v, want %q %v", tc.a, s, org, tc.want, tc.org)
		}
	}
	if h := r.JarSHA1(ctx, "g", "kid", "1"); h != strings.ToLower(sha) {
		t.Errorf("sha1 %q", h)
	}
	for _, a := range []string{"dev", "none"} {
		if h := r.JarSHA1(ctx, "g", a, "1"); h != "" {
			t.Errorf("%s: sha1 %q, want none", a, h)
		}
	}
}
