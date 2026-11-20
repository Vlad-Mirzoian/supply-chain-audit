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
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/risk"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/vuln"
)

// Exit codes of Table 3.13.
const (
	exitOK         = 0
	exitViolation  = 1
	exitIncomplete = 2
	exitUsage      = 3
	exitSelfCheck  = 4
)

// Version of the suite, set at build time with -ldflags.
var Version = "1.0.1"

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

func addGlobal(fs *flag.FlagSet) *global {
	g := &global{}
	def := os.Getenv("SSCA_CACHE")
	if def == "" {
		if d, err := os.UserCacheDir(); err == nil {
			def = filepath.Join(d, "ssca")
		}
	}
	fs.StringVar(&g.cacheDir, "cache", def, "metadata cache / data snapshot directory")
	fs.BoolVar(&g.offline, "offline", false, "use only the cached data snapshot (no network)")
	fs.StringVar(&g.eco, "ecosystem", "", "force ecosystem: npm, pypi or maven")
	fs.BoolVar(&g.dev, "include-dev", false, "also report vulnerabilities of development and test dependencies\n(they are always checked for known-malicious versions, integrity and malicious-package indicators)")
	fs.BoolVar(&g.runtime, "runtime-only", false, "analyse runtime dependencies only: development and test dependencies\nare left out of the graph, the SBOM and all checks")
	fs.BoolVar(&g.resolve, "resolve", false, "ignore lockfiles and resolve from manifests")
	return g
}

// parseArgs parses the flags of a subcommand; -h prints its usage and ends
// with exit code 0, a flag error with exit code 3.
func parseArgs(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	return exitOK, true
}

func (g *global) client() *netx.Client {
	c := netx.New(g.cacheDir, g.offline)
	// SSCA_CACHE_TTL (a Go duration) changes how long an online run reuses a
	// cached response; the experiments use a long TTL to add only the
	// responses that a frozen snapshot lacks, without refreshing the others
	if v := os.Getenv("SSCA_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			c.TTL = d
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
  ssca diff [flags] A B          compare two SBOMs (Algorithm 3.4)
  ssca typosquat [flags] NAME..  check package names offline (Algorithm 3.2)
  ssca ci-audit [dir]            audit CI workflows and local actions (M5)
  ssca verify-artifact [flags]   verify a file against a Sigstore bundle (M3)
  ssca cache [flags]             show the state of the cache in $SSCA_CACHE or --cache
  ssca version                   print version
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		usage()
		return exitOK
	case "version":
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

func commonOptions(g *global) common.Options {
	return common.Options{Net: g.client(), IncludeDev: !g.runtime, MaxRounds: 3, ForceResolve: g.resolve}
}
