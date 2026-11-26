package sbom

import (
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Mode selects the use case of the SBOM comparison.
type Mode string

const (
	DeclaredVsObserved Mode = "declared-vs-observed"
	ReleaseVsRelease   Mode = "release-vs-release"
	VendorVsGenerated  Mode = "vendor-vs-generated"
)

// Change is one element of Δ.
type Change struct {
	Class    string `json:"class"`
	Key      string `json:"key"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

// DiffResult is the result of Diff.
type DiffResult struct {
	Mode    Mode     `json:"mode"`
	Changes []Change `json:"changes"`
	Jaccard float64  `json:"jaccard"`
	OnlyA   int      `json:"only_a"`
	OnlyB   int      `json:"only_b"`
	Both    int      `json:"both"`
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// Key normalises a purl to "type/namespace/name" without version or
// qualifiers (PEP 503 normalisation for PyPI, lower case for npm).
func Key(purl string) string {
	p := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > strings.LastIndex(p, "/") {
		p = p[:i]
	}
	p, _ = url.PathUnescape(p)
	typ, rest, _ := strings.Cut(p, "/")
	typ = strings.ToLower(typ)
	switch typ {
	case "pypi":
		rest = pypiSep.ReplaceAllString(strings.ToLower(rest), "-")
	case "npm":
		rest = strings.ToLower(rest)
	}
	return typ + "/" + rest
}

func versionOf(purl string) string {
	p := purl
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, "@"); i > strings.LastIndex(p, "/") {
		v, _ := url.PathUnescape(p[i+1:])
		return v
	}
	return ""
}

// Diff compares two SBOMs. cmp orders versions (may be nil); young reports
// whether a newly added package is younger than the cooldown period.
func Diff(a, b *Doc, mode Mode, cmp func(eco, x, y string) int, young func(key string) bool) DiffResult {
	ma, mb := index(a), index(b)
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	res := DiffResult{Mode: mode}
	add := func(c Change) {
		c.Severity = severity(c, mode)
		res.Changes = append(res.Changes, c)
	}
	for _, k := range sorted {
		xa, xb := ma[k], mb[k]
		switch {
		case len(xa) == 0:
			res.OnlyB++
			cls := "ADDED"
			if mode == DeclaredVsObserved {
				cls = "PHANTOM"
			}
			c := Change{Class: cls, Key: k, To: versionsOf(xb)}
			if mode == ReleaseVsRelease && young != nil && young(k) {
				c.Detail = "young"
			}
			add(c)
		case len(xb) == 0:
			res.OnlyA++
			cls := "REMOVED"
			if mode == DeclaredVsObserved {
				cls = "MISSING"
			}
			add(Change{Class: cls, Key: k, From: versionsOf(xa)})
		default:
			res.Both++
			byVer := map[string]Comp{}
			for _, x := range xa {
				byVer[x.Version] = x
			}
			matched := map[string]bool{}
			for _, y := range xb {
				x, ok := byVer[y.Version]
				if !ok {
					continue
				}
				matched[y.Version] = true
				for alg, h := range x.Hashes {
					// sets of files: one common value is the same release
					if h2, ok := y.Hashes[alg]; ok && !slices.ContainsFunc(h, func(v string) bool { return slices.Contains(h2, v) }) {
						add(Change{Class: "HASH_MISMATCH", Key: k, From: x.Version, To: y.Version, Detail: alg})
						break
					}
				}
				if x.Supplier != "" && y.Supplier != "" && !strings.EqualFold(x.Supplier, y.Supplier) {
					add(Change{Class: "SUPPLIER_CHANGED", Key: k, From: x.Supplier, To: y.Supplier})
				}
				if len(x.Licenses) > 0 && len(y.Licenses) > 0 && strings.Join(x.Licenses, ",") != strings.Join(y.Licenses, ",") {
					add(Change{Class: "LICENSE_CHANGED", Key: k, From: strings.Join(x.Licenses, ","), To: strings.Join(y.Licenses, ",")})
				}
				if x.Provenance != "" && y.Provenance != "" && x.Provenance != y.Provenance {
					add(Change{Class: "PROVENANCE_CHANGED", Key: k, From: x.Provenance, To: y.Provenance})
				}
			}
			var va, vb []string
			for _, x := range xa {
				if !matched[x.Version] {
					va = append(va, x.Version)
				}
			}
			for _, y := range xb {
				if !matched[y.Version] {
					vb = append(vb, y.Version)
				}
			}
			// several versions of one package: a version that only
			// disappears or only appears is a removal or an addition
			if len(matched) > 0 && len(va) > 0 && len(vb) == 0 {
				cls := "REMOVED"
				if mode == DeclaredVsObserved {
					cls = "MISSING"
				}
				add(Change{Class: cls, Key: k, From: strings.Join(va, ",")})
			} else if len(matched) > 0 && len(vb) > 0 && len(va) == 0 {
				cls := "ADDED"
				if mode == DeclaredVsObserved {
					cls = "PHANTOM"
				}
				add(Change{Class: cls, Key: k, To: strings.Join(vb, ",")})
			} else if len(va) > 0 || len(vb) > 0 {
				c := Change{Class: "VERSION_CHANGED", Key: k, From: strings.Join(va, ","), To: strings.Join(vb, ",")}
				if len(va) == 1 && len(vb) == 1 && cmp != nil {
					eco, _, _ := strings.Cut(k, "/")
					switch {
					case cmp(eco, va[0], vb[0]) > 0:
						c.Detail = "downgrade"
					default:
						c.Detail = "upgrade " + size(va[0], vb[0])
					}
				}
				add(c)
			}
		}
	}
	// edge comparison on version-less keys
	ea, eb := edgeSet(a), edgeSet(b)
	for e := range eb {
		if !ea[e] {
			from, to, _ := strings.Cut(e, " -> ")
			if len(ma[from]) > 0 && len(ma[to]) > 0 || mode == ReleaseVsRelease {
				add(Change{Class: "EDGE_ADDED", Key: to, From: from, To: to})
			}
		}
	}
	for e := range ea {
		if !eb[e] {
			from, to, _ := strings.Cut(e, " -> ")
			if len(mb[from]) > 0 && len(mb[to]) > 0 {
				add(Change{Class: "EDGE_REMOVED", Key: to, From: from, To: to})
			}
		}
	}
	union := res.Both + res.OnlyA + res.OnlyB
	if union > 0 {
		res.Jaccard = float64(res.Both) / float64(union)
	}
	return res
}

func index(d *Doc) map[string][]Comp {
	m := map[string][]Comp{}
	for _, c := range d.Components {
		k := Key(c.PURL)
		if c.Version == "" {
			c.Version = versionOf(c.PURL)
		}
		m[k] = append(m[k], c)
	}
	return m
}

func edgeSet(d *Doc) map[string]bool {
	m := map[string]bool{}
	for _, e := range d.Edges {
		m[Key(e[0])+" -> "+Key(e[1])] = true
	}
	return m
}

func versionsOf(cs []Comp) string {
	var v []string
	for _, c := range cs {
		v = append(v, c.Version)
	}
	sort.Strings(v)
	return strings.Join(v, ",")
}

func size(a, b string) string {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	switch {
	case len(pa) > 0 && len(pb) > 0 && pa[0] != pb[0]:
		return "major"
	case len(pa) > 1 && len(pb) > 1 && pa[1] != pb[1]:
		return "minor"
	}
	return "patch"
}

// severity assigns the default severity of a change.
func severity(c Change, mode Mode) string {
	switch c.Class {
	case "PHANTOM", "PROVENANCE_CHANGED":
		return model.SevHigh
	case "HASH_MISMATCH":
		return model.SevCritical
	case "MISSING", "LICENSE_CHANGED":
		return model.SevLow
	case "REMOVED", "EDGE_REMOVED":
		return model.SevInfo
	case "ADDED":
		if c.Detail == "young" {
			return model.SevHigh
		}
		return model.SevMedium
	case "VERSION_CHANGED":
		if c.Detail == "downgrade" {
			return model.SevMedium
		}
		return model.SevLow
	case "SUPPLIER_CHANGED", "EDGE_ADDED":
		return model.SevMedium
	}
	return model.SevInfo
}
