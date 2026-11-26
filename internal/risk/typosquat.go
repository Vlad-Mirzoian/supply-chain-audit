package risk

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
)

// Popular is one entry of the popular-package corpus.
type Popular struct {
	Name      string `json:"project"`
	Downloads int64  `json:"download_count"`
}

// Squat is one suspected typosquatting target.
type Squat struct {
	Target     string  `json:"target"`
	Similarity float64 `json:"similarity"`
	Class      string  `json:"class"`
	Distance   float64 `json:"distance,omitempty"`
}

// Index is the corpus index of the typosquatting detector.
type Index struct {
	Eco       string
	K         int     // maximum number of deletions (k)
	Tau       float64 // similarity threshold (τ)
	GapFactor float64 // required popularity ratio (100 by default)
	names     []string
	downloads map[string]int64
	exact     map[string]bool
	deletes   map[uint64][]int32
	tokens    map[string][]int32
	scoped    map[string][]int32 // npm: bare name -> scoped popular names
	floor     int64
}

// NewIndex builds the symmetric-deletion index over the corpus.
func NewIndex(eco string, corpus []Popular, internal []string) *Index {
	ix := &Index{Eco: eco, K: 2, Tau: 0.80, GapFactor: 100,
		downloads: map[string]int64{}, exact: map[string]bool{},
		deletes: map[uint64][]int32{}, tokens: map[string][]int32{}, scoped: map[string][]int32{}}
	ix.floor = -1
	add := func(name string, dl int64) {
		n := ix.normalise(name)
		if ix.exact[n] {
			return
		}
		ix.exact[n] = true
		ix.downloads[n] = dl
		id := int32(len(ix.names))
		ix.names = append(ix.names, n)
		for _, v := range deletions(bare(n), ix.K) {
			h := hash(v)
			ix.deletes[h] = append(ix.deletes[h], id)
		}
		tk := tokenKey(bare(n))
		ix.tokens[tk] = append(ix.tokens[tk], id)
		if strings.HasPrefix(n, "@") {
			ix.scoped[bare(n)] = append(ix.scoped[bare(n)], id)
		}
		if dl > 0 && (ix.floor < 0 || dl < ix.floor) {
			ix.floor = dl
		}
	}
	for _, p := range corpus {
		add(p.Name, p.Downloads)
	}
	// internal package names are protected as if they were very popular:
	// a look-alike of an internal name is a dependency-confusion attempt.
	for _, n := range internal {
		add(n, 1<<50)
	}
	if ix.floor < 0 {
		ix.floor = 1
	}
	return ix
}

// Size returns the number of names in the corpus.
func (ix *Index) Size() int { return len(ix.names) }

func (ix *Index) normalise(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if ix.Eco == "pypi" {
		var b strings.Builder
		prevSep := false
		for _, r := range n {
			if r == '-' || r == '_' || r == '.' {
				if !prevSep {
					b.WriteByte('-')
				}
				prevSep = true
				continue
			}
			prevSep = false
			b.WriteRune(r)
		}
		return b.String()
	}
	if ix.Eco == "maven" {
		if _, a, ok := strings.Cut(n, ":"); ok {
			return a
		}
	}
	return n
}

// bare strips an npm scope.
func bare(n string) string {
	if strings.HasPrefix(n, "@") {
		if i := strings.Index(n, "/"); i > 0 {
			return n[i+1:]
		}
	}
	return n
}

func scopeOf(n string) string {
	if strings.HasPrefix(n, "@") {
		if i := strings.Index(n, "/"); i > 0 {
			return n[1:i]
		}
	}
	return ""
}

func hash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// deletions returns all strings obtained by deleting up to k characters.
func deletions(s string, k int) []string {
	seen := map[string]bool{s: true}
	cur := []string{s}
	for d := 0; d < k; d++ {
		var next []string
		for _, w := range cur {
			for i := 0; i < len(w); i++ {
				v := w[:i] + w[i+1:]
				if !seen[v] {
					seen[v] = true
					next = append(next, v)
				}
			}
		}
		cur = next
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	return out
}

func tokenKey(n string) string {
	f := strings.FieldsFunc(n, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
	sort.Strings(f)
	return strings.Join(f, "-")
}

// ---------------------------------------------------------------- distance

func isSep(c byte) bool { return c == '-' || c == '_' || c == '.' }

var qwerty = []string{"1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"}

var neighbours = func() map[[2]byte]bool {
	pos := map[byte][2]int{}
	for r, row := range qwerty {
		for c := 0; c < len(row); c++ {
			pos[row[c]] = [2]int{r, c}
		}
	}
	m := map[[2]byte]bool{}
	for a, pa := range pos {
		for b, pb := range pos {
			dr, dc := pa[0]-pb[0], pa[1]-pb[1]
			if a != b && dr >= -1 && dr <= 1 && dc >= -1 && dc <= 1 {
				m[[2]byte{a, b}] = true
			}
		}
	}
	return m
}()

var lookalike = map[[2]byte]bool{}

func init() {
	for _, p := range []string{"0o", "1l", "1i", "li", "5s", "8b", "9g", "uv", "vu"} {
		lookalike[[2]byte{p[0], p[1]}] = true
		lookalike[[2]byte{p[1], p[0]}] = true
	}
}

func subCost(a, b byte) float64 {
	switch {
	case a == b:
		return 0
	case isSep(a) && isSep(b):
		return 0.25
	case lookalike[[2]byte{a, b}]:
		return 0.25
	case neighbours[[2]byte{a, b}]:
		return 0.5
	}
	return 1
}

func insdel(c byte) float64 {
	if isSep(c) {
		return 0.25
	}
	return 1
}

// WeightedDL is the weighted Damerau–Levenshtein distance (keyboard
// neighbours, homoglyphs and separators cost less than other edits),
// computed in a band; it returns limit+1 as soon as the distance must exceed
// limit (Ukkonen's cut-off).
func WeightedDL(a, b string, limit float64) float64 {
	n, m := len(a), len(b)
	band := int(limit/0.25) + 1
	if abs(n-m) > band {
		return limit + 1
	}
	inf := limit + 1
	D := make([][]float64, n+1)
	for i := range D {
		D[i] = make([]float64, m+1)
		for j := range D[i] {
			D[i][j] = inf
		}
	}
	D[0][0] = 0
	for i := 1; i <= n && i <= band; i++ {
		D[i][0] = D[i-1][0] + insdel(a[i-1])
	}
	for j := 1; j <= m && j <= band; j++ {
		D[0][j] = D[0][j-1] + insdel(b[j-1])
	}
	for i := 1; i <= n; i++ {
		lo, hi := max(1, i-band), min(m, i+band)
		rowMin := inf
		for j := lo; j <= hi; j++ {
			v := D[i-1][j] + insdel(a[i-1])
			v = min(v, D[i][j-1]+insdel(b[j-1]))
			v = min(v, D[i-1][j-1]+subCost(a[i-1], b[j-1]))
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] && a[i-1] != b[j-1] {
				v = min(v, D[i-2][j-2]+0.5)
			}
			// visually similar multi-character forms: rn <-> m, vv <-> w
			if i > 1 && (a[i-2:i] == "rn" && b[j-1] == 'm' || a[i-2:i] == "vv" && b[j-1] == 'w') {
				v = min(v, D[i-2][j-1]+0.25)
			}
			if j > 1 && (b[j-2:j] == "rn" && a[i-1] == 'm' || b[j-2:j] == "vv" && a[i-1] == 'w') {
				v = min(v, D[i-1][j-2]+0.25)
			}
			D[i][j] = min(v, inf)
			rowMin = min(rowMin, D[i][j])
		}
		if rowMin > limit {
			return inf
		}
	}
	return D[n][m]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Similarity is 1 − d / max(|a|, |b|) for the distance d of a and b.
func Similarity(a, b string, d float64) float64 {
	return 1 - d/float64(max(len(a), len(b)))
}

// ---------------------------------------------------------------- name check

var prefixes = []string{"python-", "py-", "py", "node-", "js-", "go-", "lib", "the-", "real-", "official-"}
var suffixes = []string{"-js", ".js", "js", "-py", "py", "-python", "-node", "-utils", "-util", "-cli", "-dev", "-lib", "-core", "-api", "-sdk", "-tools", "-tool", "-helper", "-helpers", "-plus", "-pro", "-new", "-latest", "-fix", "2", "3", "-v2"}

// Candidates returns every corpus name within the similarity threshold,
// without the popularity-gap filter of Check.
func (ix *Index) Candidates(name string) []Squat {
	n := ix.normalise(name)
	if ix.exact[n] {
		return nil
	}
	best := map[string]Squat{}
	put := func(s Squat) {
		if old, ok := best[s.Target]; !ok || s.Similarity > old.Similarity {
			best[s.Target] = s
		}
	}
	b := bare(n)
	limit := float64(ix.K)
	seen := map[int32]bool{}
	for _, v := range deletions(b, ix.K) {
		for _, id := range ix.deletes[hash(v)] {
			if seen[id] {
				continue
			}
			seen[id] = true
			p := ix.names[id]
			pb := bare(p)
			if abs(len(pb)-len(b)) > 2*ix.K+2 {
				continue
			}
			// a scoped popular name only matches a candidate with a
			// look-alike scope (handled by the scope check below)
			if scopeOf(p) != scopeOf(n) {
				continue
			}
			d := WeightedDL(b, pb, limit)
			if d > limit || d == 0 {
				continue
			}
			s := Similarity(b, pb, d)
			if s >= ix.Tau {
				put(Squat{Target: p, Similarity: round(s), Class: "edit-distance", Distance: d})
			}
		}
	}
	// affix check
	sc := scopeOf(n)
	for _, pre := range prefixes {
		if strings.HasPrefix(b, pre) && sc == "" {
			if t := strings.TrimPrefix(b, pre); t != b && len(t) >= 3 && ix.exact[t] {
				put(Squat{Target: t, Similarity: 0.85, Class: "affix"})
			}
		}
	}
	for _, suf := range suffixes {
		if strings.HasSuffix(b, suf) && sc == "" {
			if t := strings.TrimSuffix(b, suf); t != b && len(t) >= 3 && ix.exact[t] {
				put(Squat{Target: t, Similarity: 0.85, Class: "affix"})
			}
		}
	}
	// reordered tokens
	if strings.ContainsAny(b, "-_.") {
		for _, id := range ix.tokens[tokenKey(b)] {
			if p := ix.names[id]; bare(p) != b && scopeOf(p) == sc {
				put(Squat{Target: p, Similarity: 0.90, Class: "token-order"})
			}
		}
	}
	// npm scopes: same package name under a look-alike scope
	if sc != "" {
		for _, id := range ix.scoped[b] {
			p := ix.names[id]
			ps := scopeOf(p)
			if ps == sc {
				continue
			}
			d := WeightedDL(sc, ps, limit)
			if d <= limit && Similarity(sc, ps, d) >= ix.Tau {
				put(Squat{Target: p, Similarity: 0.85, Class: "scope"})
			}
		}
	}
	out := make([]Squat, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Similarity != out[j].Similarity {
			return out[i].Similarity > out[j].Similarity
		}
		if di, dj := ix.downloads[out[i].Target], ix.downloads[out[j].Target]; di != dj {
			return di > dj
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// Check is the name check including the popularity-gap filter. downloads is
// the popularity of the candidate (negative: unknown, the corpus floor is
// used as an upper estimate).
func (ix *Index) Check(name string, downloads int64) []Squat {
	if downloads < 0 {
		downloads = ix.floor
		if d, ok := ix.downloads[ix.normalise(name)]; ok {
			downloads = d
		}
	}
	var out []Squat
	for _, s := range ix.Candidates(name) {
		if float64(ix.downloads[s.Target]) >= ix.GapFactor*float64(downloads) {
			out = append(out, s)
		}
	}
	return out
}

// Score returns the highest similarity to any corpus name (0 if none);
// used for ROC analysis, where the threshold τ is varied.
func (ix *Index) Score(name string, downloads int64, gap bool) (float64, string) {
	tau := ix.Tau
	ix.Tau = 0.5
	defer func() { ix.Tau = tau }()
	var cands []Squat
	if gap {
		cands = ix.Check(name, downloads)
	} else {
		cands = ix.Candidates(name)
	}
	if len(cands) == 0 {
		return 0, ""
	}
	return cands[0].Similarity, cands[0].Target
}

func round(x float64) float64 { return float64(int(x*1000+0.5)) / 1000 }

// ---------------------------------------------------------------- established packages

// A name match is dismissed for an established package: one whose first
// release is at least EstablishedMinAgeDays before the evaluation time, with
// at least EstablishedMinReleases releases spread over at least
// EstablishedMinSpanDays. A typosquat is published to be installed by mistake
// soon after it appears and is removed when it is found; it does not build a
// release history of years, which cannot be backdated. On the typosquat
// dataset of Section 4 the rule dismisses none of the real typosquats and 53
// of the 247 false positives at τ = 0.80 (for example npm extra-fs, first
// released in 2019, against fs-extra); in corpus (a) it removes matches such
// as PyPI toronado, an inline-CSS library first released in 2013, against
// tornado.
const (
	EstablishedMinAgeDays  = 730
	EstablishedMinReleases = 5
	EstablishedMinSpanDays = 365
)

// Established reports whether the package history in m qualifies as
// established at time now, with a reason for the report. Without registry
// history (no metadata, unknown package) the package is not established.
func Established(m *model.PackageMeta, now time.Time) (bool, string) {
	if m == nil || m.FirstReleaseAt.IsZero() {
		return false, ""
	}
	day := 24 * time.Hour
	age := now.Sub(m.FirstReleaseAt)
	span := m.LatestReleaseAt.Sub(m.FirstReleaseAt)
	if age < EstablishedMinAgeDays*day || m.Releases < EstablishedMinReleases || span < EstablishedMinSpanDays*day {
		return false, ""
	}
	return true, fmt.Sprintf("established package: first release %s, %d releases over %.1f years",
		m.FirstReleaseAt.UTC().Format("2006-01-02"), m.Releases, span.Hours()/24/365.25)
}

// ---------------------------------------------------------------- npm confirmation

// ConfirmNPMSquat re-checks a suspected npm typosquat name@version of target
// with registry data that the corpus does not hold: the popularity gap of
// Check with the real downloads of the last month (the
// candidate is no typosquat if the target has fewer than 100 times its
// downloads), and the maintainers (a candidate that shares a maintainer with
// the target is a companion package, such as mongodb-core of mongodb). It
// returns whether the match stands, the downloads of the candidate (-1 if
// unknown) and, for a dismissed match, the reason. Data that cannot be read
// leaves the match standing.
func ConfirmNPMSquat(ctx context.Context, reg *npm.RegistryClient, name, version, target string) (bool, int64, string) {
	dl := int64(-1)
	if d, err := reg.Downloads(ctx, name); err == nil {
		dl = d
		tgt, err2 := reg.Downloads(ctx, target)
		if err2 == nil && float64(tgt) < 100*float64(max(d, 1)) {
			return false, dl, fmt.Sprintf("popular in its own right: %d downloads last month, %s has %d", d, target, tgt)
		}
	}
	cur, err := reg.Version(ctx, name, version)
	if err != nil {
		return true, dl, ""
	}
	tp, err := reg.Packument(ctx, target)
	if err != nil {
		return true, dl, ""
	}
	td, err := reg.Version(ctx, target, tp.DistTags["latest"])
	if err != nil {
		return true, dl, ""
	}
	owners := map[string]bool{}
	for _, m := range td.Maintainers {
		owners[strings.ToLower(m.Name)] = true
	}
	for _, m := range cur.Maintainers {
		if owners[strings.ToLower(m.Name)] {
			return false, dl, fmt.Sprintf("shares the maintainer %s with %s", m.Name, target)
		}
	}
	return true, dl, ""
}
