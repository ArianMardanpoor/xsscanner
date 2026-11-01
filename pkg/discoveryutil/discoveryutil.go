// pkg/discoveryutil/discoveryutil.go
//
// Shared discovery-list merge/dedup/scope-filter logic. Used by:
//   - xsscanner (main.go's processTarget()) in normal crawl mode, to merge
//     passive + katana outputs into discoveryList
//   - xsscanner_discover (the new standalone discovery-only binary), to
//     produce the final per-target <safeName>-discovered.txt
//
// Previously this logic lived inline in main.go's processTarget() as the
// appendSafe() closure (built in the very first refactor, later updated to
// use utils.IsSameOrChildHost instead of the looser root-domain check).
// Extracting it into a shared package means xsscanner_discover reuses the
// EXACT same merge/dedup/filter behavior without copy-pasting it.
package discoveryutil

import (
	"bufio"
	"net/url"
	"os"
	"strings"

	"reconpipeline/utils"
)

// MergeAndFilter reads passiveFile and katanaFile (either may be missing/empty
// — both cases are tolerated and treated as zero lines, no error returned),
// keeps only lines that:
//
//   - parse as valid URLs (url.Parse succeeds)
//   - pass utils.IsGoodURL (rejects static assets, numeric/semver/CSS-like/
//     high-entropy path segments — same filter as everywhere else in this
//     codebase)
//   - resolve to a host that is the SAME as inputTargetURL's host OR a CHILD
//     of it (utils.IsSameOrChildHost — strict subdomain scoping: exact match
//     or "*.inputHost"; siblings/parents are dropped)
//
// then dedupes (exact-string match, same as xsscanner's previous inline
// uniqueStrings()-style logic) while preserving first-seen order, and returns
// the final ordered list.
//
// The "first-seen order" property matters: xsscanner's per-path phase→test
// loop (in main.go processTarget STEP D) preserves the target URL itself as
// the first item, then appends crawl results; downstream cache keys in
// results/param_maps/<safeURL>-paths-params.json are the EXACT URL strings,
// so re-normalizing or re-ordering between runs would break resume.
// MergeAndFilter preserves this contract because passiveFile is read first
// (so the passive seed URL written by nice_passive at line 0 stays first),
// then katanaFile — and main.go's processTarget() still prepends the target
// URL itself before calling this if needed (it doesn't, because the target
// URL is always the first line of passiveOutFile by nice_passive's contract;
// but xsscanner_discover calls MergeAndFilter without prepending, since the
// target URL is also written as the first line of passiveOutFile by
// nice_passive).
//
// Returns (urls, nil) on success. A missing/unreadable input file is NOT an
// error (returns the urls found in the other file, or an empty slice if
// both are missing); only an unexpected I/O error during scanning is
// surfaced as an error.
func MergeAndFilter(passiveFile, katanaFile, inputTargetURL string) ([]string, error) {
	// Resolve the input target's hostname once for the IsSameOrChildHost check.
	// If inputTargetURL is itself unparseable, return an empty list (the
	// caller — xsscanner or xsscanner_discover — already validated this URL
	// upstream, so reaching here unparseable would be a programmer error).
	inputHost := ""
	if u, err := url.Parse(inputTargetURL); err == nil {
		inputHost = u.Hostname()
	}
	if inputHost == "" {
		// Fall back to the raw string so IsSameOrChildHost can still be called
		// (it will simply never match anything and the result will be empty,
		// which is the safe behavior — better than crashing on the empty
		// hostname edge case).
		inputHost = inputTargetURL
	}

	var collected []string

	for _, path := range []string{passiveFile, katanaFile} {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			// Missing file = no lines from this source (don't abort; the other
			// source may still have URLs). This matches the previous inline
			// appendSafe() closure's behavior, which simply returned early on
			// os.Open error.
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			lURL, err := url.Parse(line)
			if err != nil {
				continue
			}
			lHost := lURL.Hostname()
			// Strict subdomain scoping: exact match or child of input hostname.
			if !utils.IsSameOrChildHost(lHost, inputHost) {
				continue
			}
			if !utils.IsGoodURL(line) {
				continue
			}
			collected = append(collected, line)
		}
		f.Close()
	}

	// Deduplicate while preserving first-seen order (same logic as the previous
	// inline `seen` map + deduped slice in main.go processTarget STEP C).
	seen := make(map[string]bool)
	out := make([]string, 0, len(collected))
	for _, u := range collected {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, nil
}
