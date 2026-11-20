package pypi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Constraints files limit versions without adding requirements; editable,
// VCS, URL and local requirements cannot be analysed and are reported; a
// comment containing a URL does not hide its requirement.
func TestReadRequirements(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt", `requests==2.32.3 \
    --hash=sha256:aa
idna  # see https://example.com/idna
-c constraints.txt
--requirement=extra.txt
-r missing.txt
-e git+https://github.com/foo/bar.git#egg=bar
-e .
./local-pkg
https://example.com/pkg-1.0.tar.gz
bar @ git+https://github.com/foo/bar.git
--index-url https://pypi.org/simple
--extra-index-url=https://pkgs.acme.internal/simple
-f ./wheels
`)
	write("constraints.txt", "idna==3.10\nflask<3\n")
	write("extra.txt", "urllib3>=2 ; python_version >= \"3.8\"\n-i http://mirror.example/simple\n")
	var idx []model.Repository
	lines, skipped, err := readRequirements(filepath.Join(dir, "requirements.txt"), map[string]bool{}, &idx)
	if err != nil {
		t.Fatal(err)
	}
	var reqs, cons []string
	for _, l := range lines {
		if l.constraint {
			cons = append(cons, l.Name+l.Spec)
		} else {
			reqs = append(reqs, l.Name+l.Spec)
		}
	}
	if got := strings.Join(reqs, " "); got != "requests==2.32.3 idna urllib3>=2" {
		t.Errorf("requirements: %s", got)
	}
	if got := strings.Join(cons, " "); got != "idna==3.10 flask<3" {
		t.Errorf("constraints: %s", got)
	}
	if len(skipped) != 6 {
		t.Errorf("skipped %d lines: %q", len(skipped), skipped)
	}
	var srcs []string
	for _, r := range idx {
		srcs = append(srcs, r.Kind+" "+r.URL+" "+r.DeclaredIn)
	}
	if got := strings.Join(srcs, "|"); got != "index-url http://mirror.example/simple extra.txt|index-url https://pypi.org/simple requirements.txt|extra-index-url https://pkgs.acme.internal/simple requirements.txt|find-links ./wheels requirements.txt" {
		t.Errorf("package sources: %s", got)
	}
	if lines[0].Hashes[0] != "sha256:aa" {
		t.Errorf("hash of a continued line lost: %v", lines[0].Hashes)
	}
}

func TestSourceConstraints(t *testing.T) {
	s := &source{constraints: map[string][]string{"idna": {">=3.7", "<3.11"}}}
	if got := s.constrain("idna", []string{"3.6", "3.7", "3.10", "3.11"}); strings.Join(got, " ") != "3.7 3.10" {
		t.Errorf("constraints keep %v", got)
	}
	if got := s.constrain("requests", []string{"2.0", "2.1"}); len(got) != 2 {
		t.Errorf("unconstrained package filtered: %v", got)
	}
}
