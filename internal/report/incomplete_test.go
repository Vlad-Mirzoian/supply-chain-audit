package report

import (
	"strings"
	"testing"
)

// Duplicates are dropped and "not in offline snapshot" reasons are folded
// into one line naming the packages; other reasons are kept.
func TestCompactIncomplete(t *testing.T) {
	pom := func(ga, v string) string {
		p := strings.ReplaceAll(ga, ":", "/")
		return "metadata for " + ga + "@" + v + " unavailable: POM " + ga + ":" + v + ": not in offline snapshot: https://repo1.maven.org/maven2/" + p + "/" + v + "/x.pom"
	}
	in := []string{
		pom("javax.xml.bind:jaxb-api", "2.3.0"),
		"CI configuration .github/workflows/x.yml: cannot be parsed",
		pom("javax.xml.bind:jaxb-api", "2.3.0"), // second module
		pom("junit:junit", "4.12"),
		`prettier "^3.0.0" (required by pkg:npm/demo-tools@0.0.0) not resolved: not in offline snapshot: https://registry.npmjs.org/prettier`,
		"module m: parent: POM a:b:1: not in offline snapshot: https://repo1.maven.org/maven2/a/b/1/b-1.pom",
		pom("c:d", "1"),
	}
	out := CompactIncomplete(in, 3)
	if len(out) != 2 {
		t.Fatalf("got %d lines: %q", len(out), out)
	}
	if !strings.HasPrefix(out[0], "5 items are not in the offline snapshot: javax.xml.bind:jaxb-api@2.3.0, junit:junit@4.12, prettier and 2 more") {
		t.Errorf("folded line %q", out[0])
	}
	if out[1] != in[1] {
		t.Errorf("other reason %q", out[1])
	}
	if got := CompactIncomplete(in[5:6], 5); !strings.Contains(got[0], ": a:b@1 (") {
		t.Errorf("parent POM %q", got)
	}
	if got := CompactIncomplete([]string{"a", "a", "b"}, 5); len(got) != 2 {
		t.Errorf("duplicates kept: %q", got)
	}
	if got := CompactIncomplete([]string{pom("x:y", "1")}, 5); !strings.HasPrefix(got[0], "1 item is not in the offline snapshot: x:y@1 (run without --offline to fetch it") {
		t.Errorf("singular %q", got)
	}
}

// One unavailable trusted root is one line, not one line per package.
func TestCompactIncompleteNoTrustedRoot(t *testing.T) {
	in := []string{
		"provenance of pkg:npm/a@1 could not be checked: trusted root: sigstore TUF: connection refused",
		"provenance of pkg:npm/b@1 could not be checked: trusted root: sigstore TUF: connection refused",
		"provenance of pkg:npm/c@1 could not be checked: attestations: HTTP 500",
	}
	out := CompactIncomplete(in, 5)
	if len(out) != 2 || out[0] != "Sigstore trusted root unavailable, provenance of 2 packages not checked: sigstore TUF: connection refused" || out[1] != in[2] {
		t.Errorf("got %q", out)
	}
}
