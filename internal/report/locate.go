package report

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// locator finds the line of a component in the project's manifests and
// lockfiles, so that SARIF annotations point at the entry of the package
// instead of the first line of the lockfile.
type locator struct {
	inputs []string            // project inputs, in the order they were read
	lines  map[string][]string // input -> lower-case lines
}

func newLocator(dir string, inputs []string) *locator {
	l := &locator{inputs: inputs, lines: map[string][]string{}}
	for _, in := range inputs {
		if b, err := os.ReadFile(filepath.Join(dir, in)); err == nil {
			l.lines[in] = strings.Split(strings.ToLower(string(b)), "\n")
		}
	}
	return l
}

// inputEcosystem returns the ecosystem a project input belongs to.
func inputEcosystem(file string) string {
	switch b := filepath.Base(file); {
	case b == "pom.xml":
		return model.Maven
	case b == "package.json" || b == "package-lock.json" || b == "npm-shrinkwrap.json" ||
		b == "yarn.lock" || b == "pnpm-lock.yaml":
		return model.NPM
	}
	return model.PyPI
}

// find returns the input file and the 1-based line of component c. Lines
// that declare the package (lockfile keys, "name = ..." entries, Maven
// artifactId) are preferred over lines that mention its name and version,
// which are preferred over lines that mention only its name. Without a match
// the first input of the component's ecosystem and line 1 are returned.
func (l *locator) find(c *model.Component) (string, int) {
	if c == nil {
		return "", 0
	}
	names := []string{strings.ToLower(c.FullName())}
	switch c.Ecosystem {
	case model.Maven:
		names = []string{strings.ToLower(c.Name)}
	case model.PyPI: // PEP 503 names: '-', '_' and '.' are interchangeable
		n := names[0]
		names = append(names, strings.ReplaceAll(n, "-", "_"), strings.ReplaceAll(n, "_", "-"))
	}
	version := strings.ToLower(c.Version)
	file, line, best := "", 0, 0
	for _, in := range l.inputs {
		if inputEcosystem(in) != c.Ecosystem {
			continue
		}
		if file == "" {
			file, line = in, 1
		}
		for i, text := range l.lines[in] {
			for _, n := range names {
				s := score(strings.TrimSpace(text), n, version)
				if s > best {
					file, line, best = in, i+1, s
				}
			}
		}
		if best == 3 {
			break
		}
	}
	return file, line
}

func score(t, name, version string) int {
	switch {
	case strings.Contains(t, `"node_modules/`+name+`"`), // package-lock.json
		strings.HasPrefix(t, name+"@"), strings.HasPrefix(t, `"`+name+`@`), // yarn.lock
		strings.HasPrefix(t, "/"+name+"@"), strings.HasPrefix(t, `'`+name+`@`), strings.HasPrefix(t, `'/`+name+`@`), // pnpm-lock.yaml
		t == `name = "`+name+`"`,                                 // poetry.lock, uv.lock
		strings.Contains(t, "<artifactid>"+name+"</artifactid>"): // pom.xml
		return 3
	case !hasToken(t, name):
		return 0
	case version != "" && hasToken(t, version):
		return 2
	}
	return 1
}

// hasToken reports whether s occurs in t as a whole package name or version.
func hasToken(t, s string) bool {
	part := func(b byte) bool {
		return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.'
	}
	for i := 0; ; {
		j := strings.Index(t[i:], s)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(s)
		if (j == 0 || !part(t[j-1])) && (end == len(t) || !part(t[end])) {
			return true
		}
		i = j + 1
	}
}
