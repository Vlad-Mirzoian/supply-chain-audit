package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/common"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/maven"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/npm"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/eco/pypi"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/model"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// Exit codes of the suite (README, docs/USAGE.md).
const (
	exitOK         = 0
	exitViolation  = 1
	exitIncomplete = 2
	exitUsage      = 3
	exitSelfCheck  = 4
)

// Version of the suite, set at build time with -ldflags.
var Version = "1.1.1"

type global struct {
	cacheDir string
	offline  bool
	eco      string
	dev      bool // report vulnerabilities of development and test dependencies
	runtime  bool // leave development and test dependencies out of the graph
	resolve  bool
}

// endpoint overrides, used for private mirrors and for the sandboxed
// experiments with a mock registry
func init() {
	if v := os.Getenv("SSCA_NPM_REGISTRY"); v != "" {
		npm.Registry = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("SSCA_PYPI_INDEX"); v != "" {
		pypi.Index = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("SSCA_DEPSDEV"); v != "" {
		risk.DepsDev = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("SSCA_OSV_API"); v != "" {
		vuln.API = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("SSCA_MAVEN_REPO"); v != "" {
		maven.Central = strings.TrimSuffix(v, "/")
	}
	if v := os.Getenv("SSCA_NPM_DOWNLOADS"); v != "" {
		npm.DownloadsAPI = strings.TrimSuffix(v, "/") + "/"
	}
	if v := os.Getenv("SSCA_EPSS"); v != "" {
		vuln.EPSSURL = v
	}
	if v := os.Getenv("SSCA_KEV"); v != "" {
		vuln.KEVURL = v
	}
}

// addNet registers the flags of the data sources: the cache / data snapshot
// and offline mode (every command that reads registry or Sigstore data).
func addNet(fs *flag.FlagSet) *global {
	g := &global{}
	def := os.Getenv("SSCA_CACHE")
	if def == "" {
		if d, err := os.UserCacheDir(); err == nil {
			def = filepath.Join(d, "ssca")
		}
	}
	fs.StringVar(&g.cacheDir, "cache", def, "metadata cache / data snapshot directory")
	fs.BoolVar(&g.offline, "offline", false, "use only the cached data snapshot (no network)")
	return g
}

// addGlobal registers the flags of the commands that build the dependency
// graph of a project directory (scan, graph, sbom).
func addGlobal(fs *flag.FlagSet) *global {
	g := addNet(fs)
	fs.StringVar(&g.eco, "ecosystem", "", "force ecosystem: npm, pypi or maven")
	fs.BoolVar(&g.runtime, "runtime-only", false, "analyse runtime dependencies only: development and test dependencies\nare left out of the graph, the SBOM and all checks")
	fs.BoolVar(&g.resolve, "resolve", false, "ignore lockfiles and resolve from manifests")
	return g
}

// addIncludeDev registers --include-dev, which only scan has: it concerns
// the vulnerabilities that the scan reports.
func (g *global) addIncludeDev(fs *flag.FlagSet) {
	fs.BoolVar(&g.dev, "include-dev", false, "also report vulnerabilities of development and test dependencies\n(they are always checked for known-malicious versions, integrity and malicious-package indicators)")
}

// parseArgs parses the flags of a subcommand; -h prints its usage and ends
// with exit code 0, a flag error with exit code 3. The flag package stops at
// the first argument that is not a flag, so a flag written after the
// arguments would be silently ignored or taken for an argument ("ssca scan .
// --offline" would go online, "ssca typosquat requets --ecosystem pypi"
// would check "--ecosystem" as an npm name): that is a usage error too.
func parseArgs(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	for _, a := range fs.Args() {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "error: %s after the arguments would not be applied: flags go before the arguments (ssca %s -h)\n", a, fs.Name())
			return exitUsage, false
		}
	}
	return exitOK, true
}

// projectDir is the project directory of scan, graph, sbom and ci-audit:
// the only argument, "." without one.
func projectDir(fs *flag.FlagSet) (string, bool) {
	switch fs.NArg() {
	case 0:
		return ".", true
	case 1:
		return fs.Arg(0), true
	}
	fmt.Fprintf(os.Stderr, "error: one project directory expected, got %d arguments (%s)\n", fs.NArg(), strings.Join(fs.Args(), " "))
	return "", false
}

// cacheTTLWarned: a faulty SSCA_CACHE_TTL is reported once per run, although
// a command may create several clients.
var cacheTTLWarned bool

func (g *global) client() *netx.Client {
	c := netx.New(g.cacheDir, g.offline)
	c.UserAgent = "ssca/" + Version + " (+" + model.HomeURL + ")"
	// SSCA_CACHE_TTL (a Go duration) changes how long an online run reuses a
	// cached response; the experiments use a long TTL to add only the
	// responses that a frozen snapshot lacks, without refreshing the others
	if v := os.Getenv("SSCA_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.TTL = d
		} else if !cacheTTLWarned {
			cacheTTLWarned = true
			fmt.Fprintf(os.Stderr, "warning: SSCA_CACHE_TTL=%q is not a positive Go duration such as 24h; the default of %s is used\n", v, c.TTL)
		}
	}
	return c
}

// checkTarget rejects contradicting scope flags, a project directory that
// does not exist and an unknown --ecosystem as usage errors (exit code 3),
// before any analysis.
func (g *global) checkTarget(dir string) bool {
	if g.dev && g.runtime {
		fmt.Fprintln(os.Stderr, "error: --include-dev and --runtime-only exclude each other")
		return false
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", dir)
		return false
	}
	switch g.eco {
	case "", "npm", "pypi", "maven":
		return true
	}
	fmt.Fprintf(os.Stderr, "error: unknown ecosystem %q (npm, pypi or maven)\n", g.eco)
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `ssca - software supply-chain auditing suite

Usage:
  ssca scan [flags] [dir]        full audit with policy evaluation (M0-M6)
  ssca graph [flags] [dir]       print the dependency graph (M0)
  ssca sbom [flags] [dir]        write CycloneDX and SPDX SBOMs (M1)
  ssca diff [flags] A B          compare two SBOMs (M1)
  ssca typosquat [flags] NAME..  check package names for typosquatting (M4)
  ssca ci-audit [flags] [dir]    audit CI workflows and local actions (M5)
  ssca verify-artifact [flags]   verify a file against a Sigstore bundle (M3)
  ssca cache [flags] [seal]      show or seal the cache in $SSCA_CACHE or --cache
  ssca version, --version        print version
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		// "ssca help scan" is "ssca scan -h"
		if len(args) == 2 {
			if c, ok := commands[args[1]]; ok {
				return c([]string{"-h"})
			}
		}
		usage()
		if len(args) > 1 {
			// "ssca help bogus": not a command
			return exitUsage
		}
		return exitOK
	case "version", "--version", "-version":
		fmt.Println("ssca", Version)
		return exitOK
	}
	if c, ok := commands[args[0]]; ok {
		return c(args[1:])
	}
	usage()
	return exitUsage
}

// commands maps every subcommand to its implementation; each one is in its
// own file (scan.go, graph.go, sbom.go, diff.go, typosquat.go, ciaudit.go,
// verify.go, cache.go).
var commands = map[string]func([]string) int{
	"scan":            cmdScan,
	"graph":           cmdGraph,
	"sbom":            cmdSBOM,
	"diff":            cmdDiff,
	"typosquat":       cmdTyposquat,
	"ci-audit":        cmdCIAudit,
	"verify-artifact": cmdVerifyArtifact,
	"cache":           cmdCache,
}

// parseNow reads the --now flag of scan, sbom, diff and typosquat: an
// RFC 3339 time, or the zero time when the flag is empty (the time of the
// run is then used).
func parseNow(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: --now:", err)
		return time.Time{}, false
	}
	return t, true
}

// nowOr is t, or the current time when t is zero.
func nowOr(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

// graphOptions are the options of the graph builder for graph and sbom; net
// is the client through which it reads registry data.
func graphOptions(g *global, net *netx.Client) common.Options {
	return common.Options{Net: net, IncludeDev: !g.runtime, MaxRounds: 3, ForceResolve: g.resolve}
}

// selfCheck is false, after the message, if an offline run on a sealed data
// snapshot found a damaged seal manifest or read a file that is not the one
// that was sealed: the command then ends with exit code 4 and prints no
// result, as scan does. It is called after the command has read its data and
// before it prints or writes anything.
func selfCheck(net *netx.Client) bool {
	if net == nil {
		return true
	}
	if err := net.SealError(); err != nil {
		fmt.Fprintln(os.Stderr, "error: self-check failed:", err)
		return false
	}
	return true
}
