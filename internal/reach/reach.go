// Package reach implements the optional reachability analysis (FR-19) at
// package level: starting from the import statements of the application, it
// follows the import statements found inside dependency archives. Archives
// are only read as data; no package code is executed (NFR-07).
package reach

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// Status values.
const (
	Yes     = "yes"
	No      = "no"
	Unknown = "unknown"
)

// MaxArchive limits the size of a downloaded archive.
const MaxArchive = 40 << 20

var (
	jsReq     = regexp.MustCompile(`(?:require|import)\s*\(\s*['"]([^'"\s]+)['"]\s*\)`)
	jsImport  = regexp.MustCompile(`(?m)(?:^|[;\s])(?:import|export)\s[^'";]*?from\s*['"]([^'"\s]+)['"]|(?m)^\s*import\s*['"]([^'"\s]+)['"]`)
	jsDynamic = regexp.MustCompile(`(?:\brequire|\bimport)\s*\(\s*([^'"\x60)\s][^)]*)\)`)
	strLit    = regexp.MustCompile(`['"]([@A-Za-z0-9_][@A-Za-z0-9_./-]{1,80})['"]`)
	pyImport  = regexp.MustCompile(`(?m)^\s*import\s+([A-Za-z_][\w.]*(?:\s*(?:as\s+\w+)?\s*,\s*[A-Za-z_][\w.]*)*)`)
	pyFrom    = regexp.MustCompile(`(?m)^\s*from\s+([A-Za-z_][\w.]*)\s+import\b`)
	pyDynamic = regexp.MustCompile(`importlib\.import_module\(|__import__\(`)
)

// imports is what one code base imports.
type imports struct {
	names   map[string]bool // npm package names or Python top-level modules
	dynamic bool
	ok      bool
	files   int // source files of the code base that were read
}

func npmName(spec string) string {
	if strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.HasPrefix(spec, "node:") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func scanJS(src []byte, into *imports) {
	for _, m := range jsReq.FindAllSubmatch(src, -1) {
		if n := npmName(string(m[1])); n != "" {
			into.names[n] = true
		}
	}
	for _, m := range jsImport.FindAllSubmatch(src, -1) {
		s := string(m[1])
		if s == "" {
			s = string(m[2])
		}
		if n := npmName(s); n != "" {
			into.names[n] = true
		}
	}
	for _, m := range jsDynamic.FindAllSubmatch(src, -1) {
		arg := string(m[1])
		// local files loaded through a computed path are not package imports
		if strings.Contains(arg, "__dirname") || strings.Contains(arg, "path.") || strings.Contains(arg, "./") ||
			strings.Contains(arg, "process.cwd") || strings.HasPrefix(arg, "require.resolve") {
			continue
		}
		into.dynamic = true
		break
	}
}

// scanStrings records quoted strings that may name a package or module, so
// that string-based loading in the application's own code (Django
// INSTALLED_APPS, plugin lists in configuration) is not missed.
func scanStrings(src []byte, into *imports, py bool) {
	for _, m := range strLit.FindAllSubmatch(src, -1) {
		s := string(m[1])
		if py {
			into.names[strings.Split(s, ".")[0]] = true
			continue
		}
		if n := npmName(s); n != "" {
			into.names[n] = true
		}
	}
}

func scanPy(src []byte, into *imports) {
	for _, m := range pyImport.FindAllSubmatch(src, -1) {
		for _, part := range strings.Split(string(m[1]), ",") {
			f := strings.Fields(part)
			if len(f) > 0 {
				into.names[strings.Split(f[0], ".")[0]] = true
			}
		}
	}
	for _, m := range pyFrom.FindAllSubmatch(src, -1) {
		into.names[strings.Split(string(m[1]), ".")[0]] = true
	}
	_ = pyDynamic // importlib with literal names is covered by scanStrings for the application
}

func isTestPath(p string) bool {
	l := strings.ToLower(filepath.ToSlash(p))
	for _, s := range []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/example/", "/examples/", "/docs/", "/benchmark/", "/fixtures/"} {
		if strings.Contains("/"+l, s) {
			return true
		}
	}
	return strings.HasSuffix(l, ".test.js") || strings.HasSuffix(l, ".spec.js") || strings.HasSuffix(l, ".d.ts") ||
		strings.HasPrefix(filepath.Base(l), "test_")
}

// manifestFile lists dependency declarations, which name every dependency and
// therefore say nothing about use.
var manifestFile = map[string]bool{"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"pnpm-lock.yaml": true, "yarn.lock": true, "pyproject.toml": true, "poetry.lock": true, "uv.lock": true,
	"Pipfile.lock": true, "tsconfig.json": true, ".pre-commit-config.yaml": true, "renovate.json": true}

// AppImports scans the project's own source files. Only source files of the
// ecosystem (not configuration files or tests) count as evidence: without any,
// the imports of the application are not known and the result is not ok, so
// that a directory holding only a manifest does not make every dependency
// unreachable.
func AppImports(dir, eco string) imports {
	im := imports{names: map[string]bool{}}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "dist", "build", "coverage", ".venv", "venv", "site-packages", "__pycache__", "vendor", "target":
				return filepath.SkipDir
			}
			return nil
		}
		rp, _ := filepath.Rel(dir, p)
		if isTestPath(rp) {
			return nil
		}
		ext := filepath.Ext(p)
		st, _ := d.Info()
		if st != nil && st.Size() > 2<<20 {
			return nil
		}
		switch {
		case eco == model.NPM && (ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts" || ext == ".tsx" || ext == ".jsx" || ext == ".vue"):
			if b, err := os.ReadFile(p); err == nil {
				scanJS(b, &im)
				scanStrings(b, &im, false)
				im.files++
			}
		case eco == model.PyPI && ext == ".py":
			if b, err := os.ReadFile(p); err == nil {
				scanPy(b, &im)
				scanStrings(b, &im, true)
				im.files++
			}
		case (ext == ".json" || ext == ".yml" || ext == ".yaml" || ext == ".cfg" || ext == ".ini" || ext == ".toml") && !manifestFile[filepath.Base(p)]:
			if b, err := os.ReadFile(p); err == nil {
				scanStrings(b, &im, eco == model.PyPI)
			}
		}
		return nil
	})
	im.ok = im.files > 0
	return im
}

// Analyzer computes reachability for a graph.
type Analyzer struct {
	Net *netx.Client
	Dir string
	// Stats
	Analysed, Failed int
	// NoSource lists the ecosystems for which no source file of the
	// application was found; their components are Unknown.
	NoSource []string
}

// Result maps component purls to Yes, No or Unknown.
type Result map[string]string

// Run performs the analysis. Every component is analysed according to its own
// ecosystem, so that a project with several ecosystems (an npm front end next
// to a Python back end) is handled; ecosystems without an import scanner, and
// ecosystems without any source file of the application in Dir, are Unknown.
func (a *Analyzer) Run(ctx context.Context, g *model.Graph) Result {
	app := map[string]imports{}
	for _, c := range g.Components() {
		if c.Ecosystem != model.NPM && c.Ecosystem != model.PyPI {
			continue
		}
		if _, ok := app[c.Ecosystem]; !ok {
			app[c.Ecosystem] = AppImports(a.Dir, c.Ecosystem)
			if !app[c.Ecosystem].ok {
				a.NoSource = append(a.NoSource, c.Ecosystem)
			}
		}
	}
	sort.Strings(a.NoSource)
	supported := func(c *model.Component) bool {
		return (c.Ecosystem == model.NPM || c.Ecosystem == model.PyPI) && app[c.Ecosystem].ok
	}
	res := Result{}
	for _, c := range g.Components() {
		if !supported(c) {
			res[c.PURL] = Unknown
		}
	}
	// fetch and scan archives in parallel
	pkgImports := map[string]imports{}
	modules := map[string][]string{} // python: purl -> top-level modules
	var mu sync.Mutex
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, c := range g.Components() {
		if !supported(c) {
			continue
		}
		wg.Add(1)
		go func(c *model.Component) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var im imports
			var mods []string
			switch c.Ecosystem {
			case model.NPM:
				im = a.npmPackage(ctx, c)
			case model.PyPI:
				im, mods = a.pyPackage(ctx, c)
			}
			mu.Lock()
			pkgImports[c.PURL] = im
			modules[c.PURL] = mods
			if im.ok {
				a.Analysed++
			} else {
				a.Failed++
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	// does code with imports `im` import child node `to`?
	importsNode := func(im imports, to string) bool {
		c := g.Nodes[to]
		if c.Ecosystem == model.NPM {
			return im.names[c.FullName()]
		}
		mods := modules[to]
		if len(mods) == 0 {
			mods = []string{strings.ReplaceAll(c.Name, "-", "_")}
		}
		for _, m := range mods {
			if im.names[m] {
				return true
			}
		}
		return false
	}
	reached := map[string]bool{}
	var q []string
	for _, e := range g.Out[g.Root] {
		c := g.Nodes[e.To]
		if c == nil || !supported(c) {
			continue
		}
		if im := app[c.Ecosystem]; im.dynamic || importsNode(im, e.To) {
			reached[e.To] = true
			q = append(q, e.To)
		}
	}
	for len(q) > 0 {
		u := q[0]
		q = q[1:]
		im := pkgImports[u]
		for _, e := range g.Out[u] {
			if reached[e.To] {
				continue
			}
			// unreadable or dynamically loading code: assume every child is used
			if !im.ok || im.dynamic || importsNode(im, e.To) {
				reached[e.To] = true
				q = append(q, e.To)
			}
		}
	}
	for _, c := range g.Components() {
		switch {
		case !supported(c):
		case reached[c.PURL]:
			res[c.PURL] = Yes
		default:
			res[c.PURL] = No
		}
	}
	return res
}

func (a *Analyzer) npmPackage(ctx context.Context, c *model.Component) imports {
	im := imports{names: map[string]bool{}}
	url := c.Resolved
	if !strings.HasPrefix(url, "https://") {
		vd, err := npm.NewRegistry(a.Net).Version(ctx, c.FullName(), c.Version)
		if err != nil {
			return im
		}
		url = vd.Dist.Tarball
	}
	b, err := a.Net.Get(ctx, url, "application/octet-stream")
	if err != nil || len(b) > MaxArchive {
		return im
	}
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return im
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		name := h.Name
		ext := filepath.Ext(name)
		if h.Typeflag != tar.TypeReg || isTestPath(name) || !(ext == ".js" || ext == ".mjs" || ext == ".cjs") || h.Size > 4<<20 {
			continue
		}
		src, err := io.ReadAll(io.LimitReader(tr, 4<<20))
		if err != nil {
			continue
		}
		scanJS(src, &im)
	}
	im.ok = true
	return im
}

func (a *Analyzer) pyPackage(ctx context.Context, c *model.Component) (imports, []string) {
	im := imports{names: map[string]bool{}}
	sp, err := (&pypi.Client{Net: a.Net}).Simple(ctx, c.Name)
	if err != nil {
		return im, nil
	}
	var pick *pypi.SimpleFile
	for i, f := range sp.Files {
		if pypi.VersionFromFilename(sp.Name, f.Filename) != c.Version || !strings.HasSuffix(f.Filename, ".whl") {
			continue
		}
		if pick == nil || strings.Contains(f.Filename, "none-any") || strings.Contains(f.Filename, "manylinux") && strings.Contains(f.Filename, "x86_64") && !strings.Contains(pick.Filename, "none-any") {
			pick = &sp.Files[i]
		}
	}
	if pick == nil {
		return im, nil
	}
	b, err := a.Net.Get(ctx, pick.URL, "application/octet-stream")
	if err != nil || len(b) > MaxArchive {
		return im, nil
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return im, nil
	}
	top := map[string]bool{}
	for _, f := range zr.File {
		parts := strings.Split(f.Name, "/")
		if strings.HasSuffix(parts[0], ".dist-info") || strings.HasSuffix(parts[0], ".data") {
			continue
		}
		mod := strings.TrimSuffix(parts[0], ".py")
		if i := strings.Index(mod, "."); i > 0 { // compiled extension "x.cpython-312-...so"
			mod = mod[:i]
		}
		top[mod] = true
		if !strings.HasSuffix(f.Name, ".py") || isTestPath(f.Name) || f.UncompressedSize64 > 4<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		src, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		scanPy(src, &im)
	}
	var mods []string
	for m := range top {
		mods = append(mods, m)
	}
	im.ok = true
	return im, mods
}
