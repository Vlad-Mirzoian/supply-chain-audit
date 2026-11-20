// cache: the state of an explicitly selected cache directory.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/integrity"
	"github.com/Vlad-Mirzoian/supply-chain-audit/internal/netx"
)

// cmdCache shows what a cache directory holds. The directory must be named
// (SSCA_CACHE or --cache): unlike the analysis commands it does not fall back
// to the default cache of the application.
func cmdCache(args []string) int {
	fs := flag.NewFlagSet("cache", flag.ContinueOnError)
	dir := fs.String("cache", os.Getenv("SSCA_CACHE"), "cache directory (default: $SSCA_CACHE)")
	asJSON := fs.Bool("json", false, "print the state as JSON")
	if code, ok := parseArgs(fs, args); !ok {
		return code
	}
	seal := fs.NArg() == 1 && fs.Arg(0) == "seal"
	if fs.NArg() > 0 && !seal {
		fmt.Fprintln(os.Stderr, "usage: ssca cache [--cache DIR] [--json] [seal]")
		return exitUsage
	}
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "error: no cache selected: set SSCA_CACHE or use --cache DIR (the default cache of the application is not shown)")
		return exitUsage
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %s is not a directory\n", *dir)
		return exitUsage
	}
	now := time.Now()
	if seal {
		// freeze the snapshot: offline runs check every file they read
		// against this manifest (exit code 4 on a difference)
		s, err := netx.SealCache(*dir, now)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return exitIncomplete
		}
		if *asJSON {
			printJSON(map[string]any{"seal": s.ID, "files": len(s.Files), "created": s.Created})
		} else {
			fmt.Printf("sealed %s: %d files, seal %s\n", *dir, len(s.Files), s.ID)
			fmt.Println("  offline runs on this cache check every file they read; a policy can require it (data_snapshot: " + s.ID + ")")
		}
		return exitOK
	}
	st, err := netx.InspectCache(*dir, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitIncomplete
	}
	root := integrity.SavedRoot(*dir, now)
	sl, serr := netx.LoadSeal(*dir)
	if *asJSON {
		out := map[string]any{"cache": st, "trusted_root_copy": root}
		if sl != nil {
			out["seal"] = sl.ID
		}
		printJSON(out)
	} else {
		printCache(os.Stdout, st, root)
		switch {
		case serr != nil:
			fmt.Println("  seal         invalid:", serr)
		case sl != nil:
			fmt.Printf("  seal         %s (%d files, %s)\n", sl.ID, len(sl.Files), sl.Created.Format("2006-01-02"))
		}
	}
	if serr != nil {
		return exitSelfCheck
	}
	if st.Unreadable > 0 {
		return exitIncomplete
	}
	return exitOK
}

// printCache is the text form of the state of a cache.
func printCache(w io.Writer, st *netx.CacheStats, root *integrity.RootCopy) {
	const day = "2006-01-02"
	if st.Responses == 0 {
		fmt.Fprintf(w, "cache %s: empty, no cached responses\n", st.Dir)
	} else {
		fmt.Fprintf(w, "cache %s: %s, %s, fetched %s to %s (UTC)\n", st.Dir, count(st.Responses, "response"), size(st.Bytes),
			st.Oldest.UTC().Format(day), st.Newest.UTC().Format(day))
		fmt.Fprintf(w, "  %-26s %9s %7s %9s %10s  %s\n", "source", "responses", "< 24 h", "not found", "size", "last fetched (UTC)")
		for _, h := range st.Hosts {
			fmt.Fprintf(w, "  %-26s %9d %7d %9d %10s  %s\n", h.Host, h.Responses, h.Fresh, h.NotFound, size(h.Bytes), h.Newest.UTC().Format("2006-01-02 15:04"))
		}
		if old := st.Responses - st.Fresh; old > 0 {
			fmt.Fprintf(w, "  %s older than 24 h: an online run fetches them again, --offline uses them as they are\n", count(old, "response is", "responses are"))
		}
	}
	if root != nil {
		fmt.Fprintln(w, "  Sigstore trusted root:", root)
	} else {
		fmt.Fprintln(w, "  Sigstore trusted root: no saved copy, --offline cannot verify signatures")
	}
	if st.Unreadable > 0 {
		fmt.Fprintf(w, "  unreadable: %s that are not valid cache entries\n", count(st.Unreadable, "file", "files"))
	}
}

// size is a number of bytes for people.
func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
