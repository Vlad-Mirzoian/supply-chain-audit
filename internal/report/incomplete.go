package report

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	offlineRe  = regexp.MustCompile(`not in offline snapshot: (\S+)$`)
	metaForRe  = regexp.MustCompile(`^metadata for (\S+) unavailable`)
	requiredRe = regexp.MustCompile(`^(\S+) "[^"]*" \(required by`)
	pomRe      = regexp.MustCompile(`POM ([^:\s]+):([^:\s]+):([^:\s]+): not in offline snapshot`)
	noRootRe   = regexp.MustCompile(`^provenance of \S+ could not be checked: trusted root: (.*)$`)
)

// CompactIncomplete prepares the reasons of an incomplete analysis for a
// summary that people read; report.json and graph --json keep the full list.
// Exact duplicates are dropped (a multi-module Maven project repeats them
// for every module), and the reasons that only say that some data is not in
// the offline snapshot are folded into one line that names the first show
// items. One unavailable Sigstore trusted root, which stops the check of every
// signature, is one line as well. The other reasons are kept in their order.
func CompactIncomplete(list []string, show int) []string {
	var out, missing []string
	seen, seenItem := map[string]bool{}, map[string]bool{}
	noRoot, rootErr := 0, ""
	for _, s := range list {
		if seen[s] {
			continue
		}
		seen[s] = true
		if m := noRootRe.FindStringSubmatch(s); m != nil {
			noRoot++
			rootErr = m[1]
			continue
		}
		m := offlineRe.FindStringSubmatch(s)
		if m == nil {
			out = append(out, s)
			continue
		}
		item := offlineItem(s, m[1])
		if !seenItem[item] {
			seenItem[item] = true
			missing = append(missing, item)
		}
	}
	if noRoot > 0 {
		out = append([]string{fmt.Sprintf("Sigstore trusted root unavailable, provenance of %d %s not checked: %s",
			noRoot, plural(noRoot, "package", "packages"), rootErr)}, out...)
	}
	if len(missing) == 0 {
		return out
	}
	names := missing
	more := ""
	if show > 0 && len(missing) > show {
		names, more = missing[:show], fmt.Sprintf(" and %d more", len(missing)-show)
	}
	line := fmt.Sprintf("%d %s not in the offline snapshot: %s%s (run without --offline to fetch %s, or use a data snapshot that holds %s)",
		len(missing), plural(len(missing), "item is", "items are"), strings.Join(names, ", "), more,
		plural(len(missing), "it", "them"), plural(len(missing), "it", "them"))
	return append([]string{line}, out...)
}

// offlineItem names what was missing: the package of the reason, else the
// last segment of the URL.
func offlineItem(reason, url string) string {
	if m := metaForRe.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	if m := requiredRe.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	if m := pomRe.FindStringSubmatch(reason); m != nil { // parent POM or BOM
		return m[1] + ":" + m[2] + "@" + m[3]
	}
	if i := strings.LastIndex(strings.TrimSuffix(url, "/"), "/"); i >= 0 {
		return strings.TrimSuffix(url, "/")[i+1:]
	}
	return url
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
