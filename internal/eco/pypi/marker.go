package pypi

import (
	"regexp"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
)

// Env is the target environment used to evaluate PEP 508 markers. The
// default corresponds to a Linux x86-64 CI runner with CPython 3.12.
var Env = map[string]string{
	"python_version":                 "3.12",
	"python_full_version":            "3.12.3",
	"os_name":                        "posix",
	"sys_platform":                   "linux",
	"platform_system":                "Linux",
	"platform_machine":               "x86_64",
	"platform_python_implementation": "CPython",
	"implementation_name":            "cpython",
	"implementation_version":         "3.12.3",
	"platform_release":               "",
}

// EvalMarker evaluates a PEP 508 marker for the given extras. Unknown
// constructs evaluate to true so that dependencies are not silently lost.
func EvalMarker(marker string, extras []string) bool {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return true
	}
	p := &mparser{toks: tokenize(marker), extras: extras}
	v, ok := p.or()
	if !ok {
		return true
	}
	return v
}

// EvalMarkerAnyEnv says whether a marker can hold in some environment for the
// given extras: only the conditions on extras are evaluated, those on the
// Python version or the platform count as met. A lockfile that names the
// target of a requirement shows that the requirement applies somewhere, also
// when it does not in the environment of this analysis.
func EvalMarkerAnyEnv(marker string, extras []string) bool {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return true
	}
	p := &mparser{toks: tokenize(marker), extras: extras, anyEnv: true}
	v, ok := p.or()
	if !ok {
		return true
	}
	return v
}

var tokRe = regexp.MustCompile(`\s*("[^"]*"|'[^']*'|\(|\)|===|==|!=|<=|>=|~=|<|>|not in|in|and|or|[A-Za-z_][A-Za-z0-9_.]*)`)

func tokenize(s string) []string {
	var out []string
	for _, m := range tokRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

type mparser struct {
	toks   []string
	i      int
	extras []string
	anyEnv bool // see EvalMarkerAnyEnv
}

func (p *mparser) peek() string {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return ""
}

func (p *mparser) or() (bool, bool) {
	l, ok := p.and()
	for ok && p.peek() == "or" {
		p.i++
		r, ok2 := p.and()
		l, ok = l || r, ok2
	}
	return l, ok
}

func (p *mparser) and() (bool, bool) {
	l, ok := p.atom()
	for ok && p.peek() == "and" {
		p.i++
		r, ok2 := p.atom()
		l, ok = l && r, ok2
	}
	return l, ok
}

func (p *mparser) atom() (bool, bool) {
	if p.peek() == "(" {
		p.i++
		v, ok := p.or()
		if p.peek() == ")" {
			p.i++
		}
		return v, ok
	}
	if p.i+2 >= len(p.toks) {
		return true, false
	}
	l, op, r := p.toks[p.i], p.toks[p.i+1], p.toks[p.i+2]
	p.i += 3
	return p.compare(l, op, r), true
}

func (p *mparser) value(t string) (string, bool) {
	if strings.HasPrefix(t, `"`) || strings.HasPrefix(t, `'`) {
		return t[1 : len(t)-1], false
	}
	if t == "extra" {
		return "extra", true
	}
	return Env[t], true
}

func (p *mparser) compare(l, op, r string) bool {
	lv, lvar := p.value(l)
	rv, rvar := p.value(r)
	if lv == "extra" && lvar || rv == "extra" && rvar {
		other := rv
		if rv == "extra" && rvar {
			other = lv
		}
		in := false
		for _, e := range p.extras {
			if Normalise(e) == Normalise(other) {
				in = true
			}
		}
		if op == "!=" {
			return !in
		}
		return in
	}
	if p.anyEnv {
		return true
	}
	switch op {
	case "in":
		return strings.Contains(rv, lv)
	case "not in":
		return !strings.Contains(rv, lv)
	}
	// version comparison when both sides parse as versions
	if a, err := pep440.Parse(lv); err == nil {
		if b, err := pep440.Parse(rv); err == nil {
			c := a.Compare(b)
			switch op {
			case "==", "===":
				return c == 0
			case "!=":
				return c != 0
			case "<":
				return c < 0
			case "<=":
				return c <= 0
			case ">":
				return c > 0
			case ">=":
				return c >= 0
			case "~=":
				ss, err := pep440.NewSpecifiers("~=" + rv)
				return err == nil && ss.Check(a)
			}
		}
	}
	switch op {
	case "==", "===":
		return lv == rv
	case "!=":
		return lv != rv
	}
	return true
}
