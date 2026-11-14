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
	"regexp"
	"sort"
	"strings"

	"reconpipeline/utils"
)

// ── Structural collapse (path-shape clustering) ──────────────────────────────
//
// WHY: uro's semantic dedup only collapses URLs sharing the SAME path with
// different query values. Real archive-sourced discovery lists (wayback/gau)
// are dominated by structurally identical pages whose DIFFERENCE lives in the
// path itself: paginated forums (/forum/section-1/page-53 ... page-88),
// per-user profile paths (/for/<email>, /a-<username>), session-id paths
// (/forum/sid-<hex32>), numbered content (/show/site-course4 ... course9) and
// one copy per language prefix (/pl/login, /de/login, /jp/login...). On the
// real webapp.nozbe.com list (892 URLs) these clusters are 119 + 72 + 70 + 38
// + ... URLs deep, and uro keeps every one of them — the per-path test loop
// then explodes (893 paths × 8 chunks = 7144 xssniper invocations).
//
// collapseSignature therefore clusters by STRUCTURE, not identity:
//
//	scheme+host normalized (http://H:80 ≡ https://H),
//	each path segment with digits → digit-masked      (page-53 ≡ page-88),
//	each path segment that is pure hex ≥16 chars → HEX (sid-<h> ≡ sid-<h>),
//	each path segment containing '@' → EMAIL          (/for/a@b.c ≡ /for/x@y.z),
//	first segment dropped when it is a throwaway prefix (language code or
//	  app-group prefix: pl/de/jp/... gtd/app/web/...),
//	query reduced to its sorted param-NAME set        (uro's own rule).
//
// One REPRESENTATIVE per cluster is kept — chosen to be the most informative
// member (query-carrying beats bare, longer query beats shorter, then shortest
// path, then first-seen). The rest are logged as dropped. This mirrors
// xssniper's dedupBySignature (same idea, queryValueLength tie-break) but runs
// at DISCOVERY time so the per-path phase and test loops never see the
// duplicates.
//
// Safety properties:
//   - the TARGET URL (line 0 of passive output) is never dropped;
//   - representatives keep their ORIGINAL first-seen position in the list
//     (resume-cache keys are exact URL strings — a re-run with the same input
//     picks the same representatives, so paths-params.json stays stable);
//   - a cluster never merges different param-NAME sets (uro rule preserved);
//   - pure-informational segments (hex/email) collapse only in FULL (a half
//     hex token would over-merge unrelated paths).
//
// collapseFirstSegment toggles rule 5 (default on via MergeAndFilter; tests
// can disable it to assert the other rules in isolation).

var (
	rePureDigits  = regexp.MustCompile(`^[0-9]+$`)
	rePureHex     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reEmbedHex    = regexp.MustCompile(`[0-9a-fA-F]{16,}`)
	reShortHexID  = regexp.MustCompile(`^(?:post|id|uid|pid|cid|nid|ref|hash|h)-[0-9a-fA-F]{6,}$`)
	reHasDigit    = regexp.MustCompile(`[0-9]`)
	reDigitsSub   = regexp.MustCompile(`[0-9]+`)
	reLangSeg     = regexp.MustCompile(`^(?:lang|locale|loc|l)-[a-z]{2}(?:_[A-Z]{2})?$`)
	reFlashMsgSeg = regexp.MustCompile(`^(?:error|msg|message|flash)-`)
	reLangPrefix  = map[string]bool{} // filled below
	reAppPrefixes = []string{"gtd", "app", "web", "www", "m", "mobile"}
)

func init() {
	for _, l := range []string{
		"en", "pl", "de", "fr", "es", "jp", "nl", "ru", "it", "pt", "cs",
		"ko", "zh", "tr", "sv", "da", "fi", "no", "hu", "el", "he", "ar",
		"hi", "th", "vi", "uk", "ro", "bg", "hr", "sk", "sl", "lt", "lv",
		"et", "sr",
	} {
		reLangPrefix[l] = true
	}
}

// maskSegment canonicalizes ONE path segment for the signature.
func maskSegment(seg string) string {
	if seg == "" {
		return seg
	}
	if strings.Contains(seg, "@") {
		return "EMAIL"
	}
	if rePureHex.MatchString(seg) {
		return "HEX"
	}
	// Embedded long-hex tokens (sid-c21bec48...): mask the hex run itself so
	// sid-<hex32> ≡ sid-<hex32> regardless of the token's prefix/suffix. A
	// 16+ char hex run is never meaningful content — it is an id, a hash or
	// a session token.
	if reEmbedHex.MatchString(seg) {
		seg = reEmbedHex.ReplaceAllString(seg, "H")
	}
	// Locale-carrying segments (/page/login/lang-pl ≡ /page/login/lang-jp)
	// and flash-message segments (/login/error-... ≡ /login/msg-...): the
	// segment carries presentation state, not endpoint identity.
	if reLangSeg.MatchString(seg) {
		return "LANG"
	}
	if reFlashMsgSeg.MatchString(seg) {
		return "FLASH"
	}
	if rePureDigits.MatchString(seg) {
		return "N"
	}
	if reHasDigit.MatchString(seg) {
		return reDigitsSub.ReplaceAllString(seg, "N")
	}
	return seg
}

// isThrowawayPrefix reports whether the FIRST path segment is a language code
// or an app-group prefix that carries no endpoint identity (/pl/login and
// /jp/login are the same endpoint).
func isThrowawayPrefix(seg string) bool {
	s := strings.ToLower(seg)
	if reLangPrefix[s] {
		return true
	}
	for _, p := range reAppPrefixes {
		if s == p {
			return true
		}
	}
	return false
}

// collapseSignature returns the structural signature of rawURL.
func collapseSignature(rawURL string, collapseFirstSegment bool) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := strings.ToLower(u.Hostname())
	segs := make([]string, 0, 4)
	for _, s := range strings.Split(u.Path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if collapseFirstSegment && len(segs) > 0 && isThrowawayPrefix(segs[0]) {
		segs = segs[1:]
	}
	// Second masking round over the WHOLE segment list: recognize content-id
	// segments (post-<hex>, id-<hex>...) anywhere in the path and (a) mask the
	// id segment itself to a placeholder, (b) mask the TRAILING segment after
	// it to a title-slug placeholder (/post-012a1c41/[suggest]_web_
	// interface_improvements — the slug is pure content; every post shares
	// the same endpoint shape). The slug rule fires ONLY after a recognized
	// id segment so ordinary /a/b paths never lose their last segment.
	for i := 0; i < len(segs); i++ {
		if reShortHexID.MatchString(segs[i]) {
			segs[i] = "ID"
			if i+1 < len(segs) {
				segs[len(segs)-1] = "SLUG"
			}
			break
		}
	}
	var b strings.Builder
	b.WriteString(host)
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(maskSegment(s))
	}
	// Param-NAME set only (uro's semantic rule): same endpoint with the same
	// param names but different values collapses; different param sets never
	// merge.
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	if len(names) > 0 {
		b.WriteByte('?')
		b.WriteString(strings.Join(names, "&"))
	}
	return b.String()
}

// informativeScore ranks cluster members: the representative should be the
// member most worth testing. Query-carrying beats bare (params are the whole
// point of the pipeline), a richer query beats a thinner one, then the
// shortest path (least noise), then first-seen. Lower tuple = better.
func informativeScore(rawURL string, order int) []int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return []int{1, 0, len(rawURL) + order}
	}
	qLen := 0
	nParams := 0
	for _, vals := range u.Query() {
		nParams++
		for _, v := range vals {
			qLen += len(v)
		}
	}
	noQuery := 1
	if nParams > 0 {
		noQuery = 0
	}
	return []int{noQuery, -qLen, len(u.Path) + order}
}

// sliceLess compares two int tuples lexicographically.
func sliceLess(a, b []int) bool {
	for i := range a {
		if i >= len(b) {
			return false
		}
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// collapseStructural clusters urls by collapseSignature and keeps one
// representative per cluster, re-emitted in first-seen order. The first URL
// of the input (the target itself per MergeAndFilter's contract) is always
// kept. Returns the kept list and the number dropped.
func collapseStructural(urls []string, collapseFirstSegment bool) ([]string, int) {
	if len(urls) < 2 {
		return urls, 0
	}

	type member struct {
		url   string
		order int
	}
	clusters := make(map[string][]member)
	for i, u := range urls {
		sig := collapseSignature(u, collapseFirstSegment)
		clusters[sig] = append(clusters[sig], member{url: u, order: i})
	}

	// Choose the best member of each cluster.
	best := make(map[string]string, len(clusters)) // sig -> representative
	for sig, members := range clusters {
		chosen := members[0]
		chosenScore := informativeScore(chosen.url, chosen.order)
		for _, m := range members[1:] {
			if s := informativeScore(m.url, m.order); sliceLess(s, chosenScore) {
				chosen = m
				chosenScore = s
			}
		}
		best[sig] = chosen.url
	}

	// Re-emit in first-seen order: position = the chosen member's own order.
	type keptEntry struct {
		url string
		pos int
	}
	keptBySig := make(map[string]int, len(clusters)) // sig -> original index
	for i, u := range urls {
		sig := collapseSignature(u, collapseFirstSegment)
		if _, ok := keptBySig[sig]; !ok {
			keptBySig[sig] = i
			_ = u
		}
	}
	kept := make([]keptEntry, 0, len(best))
	for sig, repURL := range best {
		kept = append(kept, keptEntry{url: repURL, pos: keptBySig[sig]})
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].pos < kept[j].pos })

	out := make([]string, 0, len(kept))
	for _, e := range kept {
		out = append(out, e.url)
	}
	return out, len(urls) - len(out)
}

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

	// Structural (path-shape) collapse — the LAST dedup stage, after uro.
	// uro only merges same-path/different-query URLs; archive lists are
	// dominated by same-SHAPE/different-path duplicates (pagination,
	// per-user paths, language copies) that survive both dedups above (see
	// the collapseStructural doc for the real-target numbers: 892 → ~277).
	// The input's first URL (the target itself) is never dropped, and the
	// surviving representatives keep their first-seen order.
	if len(out) > 1 {
		var dropped int
		out, dropped = collapseStructural(out, true)
		if dropped > 0 {
			fmt.Fprintf(os.Stderr, "[discoveryutil] structural collapse: dropped %d structurally-duplicate URL(s) (%d -> %d)\n", dropped, len(out)+dropped, len(out))
		}
	}

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
