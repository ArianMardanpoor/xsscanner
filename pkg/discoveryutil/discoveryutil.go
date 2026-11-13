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
	"fmt"
	"net/url"
	"os"
	"os/exec"
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
// uniqueStrings()-style logic) while preserving first-seen order, and finally
// runs an additional uro-style semantic dedup pass (path + sorted param-name
// set) over the merged result — see uroDedup below — before returning the
// final ordered list.
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

	// Final uro-style semantic dedup pass. The exact-string dedup above cannot
	// collapse two URLs that share the same (scheme+host+path) but differ only
	// in query-param values (or in param order): passive and katana both run
	// uro on their OWN outputs, but each source is deduped in isolation, so
	// near-duplicates that appear in BOTH sources (or only in one of them,
	// post-filtering) survive the merge. uro collapses those by
	// (path + sorted param-name-set) and keeps one representative per group.
	//
	// uro is invoked the same way nice_passive/nice_katana invoke it
	// (uro -i <file> -o <file>), but over a TEMP file holding the in-memory
	// merged list (this function has no persistent file of its own). On any
	// failure (not in PATH, exec error, unreadable output) a warning goes to
	// stderr and the exact-string-deduped list is returned unchanged — this
	// helper never crashes the caller.
	out = uroDedup(out)

	return out, nil
}

// uroDedup runs `uro -i <tmp> -o <tmpOut>` over the given list and returns the
// uro-kept URLs in their ORIGINAL input order. uro's output ordering is not
// guaranteed to match the input's first-seen order, and first-seen order is a
// hard contract of MergeAndFilter (downstream cache keys in
// results/param_maps/<safeURL>-paths-params.json are the EXACT URL strings and
// the target URL must stay line 0), so the uro result is used as a KEEP-SET:
// every URL uro kept is re-emitted in the original pre-uro order. Identifying
// membership by exact string is safe because uro only removes lines, never
// rewrites them.
//
// If uro is unavailable or fails, the input is returned unchanged (with a
// stderr warning) — dedup quality degrades, correctness never does.
func uroDedup(urls []string) []string {
	if len(urls) < 2 {
		return urls
	}

	uroPath, err := exec.LookPath("uro")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: uro not found in PATH — skipping semantic (path+param-set) dedup, keeping exact-string dedup only: %v\n", err)
		return urls
	}

	tmpIn, err := os.CreateTemp("", "discoveryutil_uro_in_*.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: failed to create temp file for uro pass: %v (skipping semantic dedup)\n", err)
		return urls
	}
	inPath := tmpIn.Name()
	defer os.Remove(inPath)

	var b strings.Builder
	for _, u := range urls {
		b.WriteString(u)
		b.WriteString("\n")
	}
	if _, werr := tmpIn.WriteString(b.String()); werr != nil {
		tmpIn.Close()
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: failed to write temp file for uro pass: %v (skipping semantic dedup)\n", werr)
		return urls
	}
	if cerr := tmpIn.Close(); cerr != nil {
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: failed to close temp file for uro pass: %v (skipping semantic dedup)\n", cerr)
		return urls
	}

	// Output path next to the input temp file; both are removed on exit.
	outPath := inPath + ".uro"
	defer os.Remove(outPath)

	cmd := exec.Command(uroPath, "-i", inPath, "-o", outPath)
	if out, xerr := cmd.CombinedOutput(); xerr != nil {
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: uro final-pass failed: %v (continuing with exact-string-deduped output)%s\n",
			xerr, uroOutputSuffix(out))
		return urls
	}

	data, rerr := os.ReadFile(outPath)
	if rerr != nil {
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: failed to read uro output %s: %v (continuing with exact-string-deduped output)\n", outPath, rerr)
		return urls
	}

	// Build the keep-set from uro's output lines (trimmed; empty lines ignored).
	keep := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			keep[line] = true
		}
	}
	if len(keep) == 0 {
		// uro produced an empty result — treat as a failed pass rather than
		// silently dropping everything (a non-empty input can never legitimately
		// dedup to zero).
		fmt.Fprintf(os.Stderr, "[discoveryutil] WARN: uro returned an empty result for %d input URL(s) — continuing with exact-string-deduped output\n", len(urls))
		return urls
	}

	// Re-emit the kept URLs in the ORIGINAL first-seen order so the resume-cache
	// key contract (target URL first, stable order) is preserved exactly.
	filtered := make([]string, 0, len(urls))
	dropped := 0
	for _, u := range urls {
		if keep[u] {
			filtered = append(filtered, u)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "[discoveryutil] uro semantic dedup: dropped %d near-duplicate URL(s) (%d -> %d)\n", dropped, len(urls), len(filtered))
	}
	return filtered
}

// uroOutputSuffix formats uro's captured stderr/stdout for a warning line,
// returning "" when there is nothing to show.
func uroOutputSuffix(out []byte) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return ""
	}
	return " — uro output: " + s
}
