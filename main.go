// main.go
package main

import (
        "bufio"
        "bytes"
        "crypto/sha1"
        "encoding/hex"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "mime/multipart"
        "net/http"
        "net/url"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "sort"
        "strings"
        "time"

        "reconpipeline/pkg/discoveryutil"
        "reconpipeline/pkg/reporter"
        "reconpipeline/pkg/spadetect"
        "reconpipeline/utils"
)

var logWriter io.Writer = os.Stdout // Defaults to Stdout before being overridden
var repLogger *reporter.Logger

const (
        M_gray   = "\033[90m"
        M_reset  = "\033[0m"
        M_purple = "\033[35m"
        M_bold   = "\033[1m"
        M_red    = "\033[31m"
        M_green  = "\033[32m"
        M_cyan   = "\033[36m"
)

var (
        globalOutputDir = "./results"
)

func logMsg(msg string, color string) {
        ts := time.Now().Format("15:04:05")
        fmt.Fprintf(logWriter, "%s[%s]%s %s[BRIDGE] %s%s\n", M_gray, ts, M_reset, color, msg, M_reset)
}

// Minimal loadEnv helper to mimic xssniper's standard local pattern
func loadEnv() {
        f, err := os.Open(".env")
        if err != nil {
                return
        }
        defer f.Close()
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                parts := strings.SplitN(line, "=", 2)
                if len(parts) == 2 {
                        os.Setenv(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
                }
        }
}

// sendTelegramDoc sends the log document as multipart/form-data
func sendTelegramDoc(token, chatID, filePath, caption string) error {
        file, err := os.Open(filePath)
        if err != nil {
                return err
        }
        defer file.Close()

        body := &bytes.Buffer{}
        writer := multipart.NewWriter(body)

        _ = writer.WriteField("chat_id", chatID)
        _ = writer.WriteField("caption", caption)

        part, err := writer.CreateFormFile("document", filepath.Base(filePath))
        if err != nil {
                return err
        }
        if _, err = io.Copy(part, file); err != nil {
                return err
        }
        if err := writer.Close(); err != nil {
                return err
        }

        urlStr := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token)
        req, err := http.NewRequest("POST", urlStr, body)
        if err != nil {
                return err
        }
        req.Header.Set("Content-Type", writer.FormDataContentType())

        client := &http.Client{Timeout: 30 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
                respBody, _ := io.ReadAll(resp.Body)
                return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
        }
        return nil
}

func runBinary(name string, args ...string) error {
        cmd := exec.Command(name, args...)
        cmd.Stdout = logWriter // Redirect stdout to multi-writer
        cmd.Stderr = logWriter // Redirect stderr to multi-writer
        return cmd.Run()
}

// headerList implements flag.Value for the repeatable -header flag.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
        *h = append(*h, v)
        return nil
}

// globalAuthArgs holds the parsed -cookie/-header values that get forwarded to
// every subprocess making live requests against the target (nice_katana,
// nice_params, xssniper — and from xssniper on down to curl_reflect_checker and
// dom_sink_checker). nice_passive is deliberately NEVER given these: it only
// queries third-party archive APIs (waybackurls/gau), never the target itself.
var globalAuthArgs []string

// withAuth appends the global auth args (if any) to a subprocess arg list.
func withAuth(args []string) []string {
        if len(globalAuthArgs) == 0 {
                return args
        }
        out := make([]string, 0, len(args)+len(globalAuthArgs))
        out = append(out, args...)
        out = append(out, globalAuthArgs...)
        return out
}

// fileExists is a small os.Stat wrapper used by the crawl-stage resume checks.
func fileExists(path string) bool {
        _, err := os.Stat(path)
        return err == nil
}

// writeDone writes the empty "<file>.done" sentinel marking a crawl stage as
// fully completed for this target (coarse crawl-stage resume). Best-effort:
// a failed write is logged, never fatal.
func writeDone(path string) {
        if err := os.WriteFile(path, []byte{}, 0644); err != nil {
                logMsg(fmt.Sprintf("Failed to write %s: %v", path, err), M_red)
        }
}

func getSafeName(u string) string {
        return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(u, "_")
}

func countLines(path string) int {
        f, err := os.Open(path)
        if err != nil {
                return 0
        }
        defer f.Close()
        n := 0
        sc := bufio.NewScanner(f)
        for sc.Scan() {
                if strings.TrimSpace(sc.Text()) != "" {
                        n++
                }
        }
        return n
}
func countLinesInDir(dir string) int {
        total := 0
        entries, err := os.ReadDir(dir)
        if err != nil {
                return 0
        }
        for _, e := range entries {
                if !e.IsDir() {
                        total += countLines(filepath.Join(dir, e.Name()))
                }
        }
        return total
}

// countPassiveURLsInDir counts the lines of ONLY the *.passive files in dir.
// The crawl_cache dir also holds katana outputs and .done sentinels, which
// must not be counted as passive URLs.
func countPassiveURLsInDir(dir string) int {
        total := 0
        entries, err := os.ReadDir(dir)
        if err != nil {
                return 0
        }
        for _, e := range entries {
                if !e.IsDir() && strings.HasSuffix(e.Name(), ".passive") {
                        total += countLines(filepath.Join(dir, e.Name()))
                }
        }
        return total
}

// ── Param validation (mirrors nice_params isValidParam for query-string merge) ──

var (
        reNumericMain = regexp.MustCompile(`^\d+$`)
        reCSSUnitMain = regexp.MustCompile(`\d+(px|em|rem|vh|vw|ms|fr)$`)
)

func isValidParamName(p string) bool {
        if len(p) < 2 || len(p) > 50 {
                return false
        }
        if reNumericMain.MatchString(p) {
                return false
        }
        if strings.HasPrefix(p, "--") {
                return false
        }
        if strings.ContainsAny(p, " \t\n\r") {
                return false
        }
        if reCSSUnitMain.MatchString(p) {
                return false
        }
        return true
}

// ── Per-path resume state (results/param_maps cache) ──────────────────────────
//
// Two per-target state files live in results/param_maps/ and persist across
// runs so a scan never redoes work a previous run already completed:
//
//      <safeName(target)>-paths-params.json  { "<path>": ["param", ...], ... }
//      <safeName(target)>-test-state.json    { "<path>": "own"|"all", ... }
//      <safeName(target)>-all-params.txt     aggregate union of all discovered
//                                            params for the target (one per line)
//
// Keys are the EXACT URL strings from the target's discovery list — never
// re-normalized or re-ordered between runs.

const (
        testScopeOwn = "own" // path tested using ONLY its own discovered params
        testScopeAll = "all" // path tested using the full merged param set (-allparam)
)

func paramMapsDir() string {
        return filepath.Join(globalOutputDir, "param_maps")
}

func pathsParamsFile(safeURL string) string {
        return filepath.Join(paramMapsDir(), safeURL+"-paths-params.json")
}

func testStateFile(safeURL string) string {
        return filepath.Join(paramMapsDir(), safeURL+"-test-state.json")
}

func allParamsListFile(safeURL string) string {
        return filepath.Join(paramMapsDir(), safeURL+"-all-params.txt")
}

// wafBlockedFile returns the path to the per-target persistent WAF/blocked
// record (results/param_maps/<safeName(target)>-waf-blocked.json). This file
// lives in the same directory as paths-params.json / test-state.json and
// follows the SAME error-tolerant "missing/corrupt = empty" load rule. It is
// on the cleanup step's "KEEP — never delete" list so it persists across runs
// exactly like the other resume state files.
//
// Format: a JSON object keyed by path string (the same key convention as
// pathParams/testState):
//
//   {
//     "https://sub1.target.com/admin": {
//       "stage": "test",            // "phase" or "test"
//       "scope": "own",              // "own"/"all" for stage="test"; "" for stage="phase"
//       "blockCounterEnd": 9,
//       "timestamp": "2026-11-01T12:00:00Z"
//     },
//     ...
//   }
//
// Loaded at the start of processTarget(); waf-blocked status is checked FIRST
// (before pathParams/testState skip-logic) when deciding whether to skip a
// path's phase or test step.
func wafBlockedFile(safeURL string) string {
        return filepath.Join(paramMapsDir(), safeURL+"-waf-blocked.json")
}

// wafBlockedEntry is one record inside waf-blocked.json.
type wafBlockedEntry struct {
        Stage           string `json:"stage"`             // "phase" or "test"
        Scope           string `json:"scope,omitempty"`    // "own"/"all" for stage="test"; "" for stage="phase"
        BlockCounterEnd int64  `json:"blockCounterEnd"`   // final consecutive-suspicious count
        Timestamp       string `json:"timestamp"`         // RFC3339
}

// loadWafBlocked loads the per-target waf-blocked.json. A missing, unreadable
// or malformed file never aborts the run: a warning is logged and an empty
// map is returned (same never-fail semantics as loadPathsParamsCache /
// loadTestStateCache).
func loadWafBlocked(path, target string) map[string]wafBlockedEntry {
        m := make(map[string]wafBlockedEntry)
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        logMsg(fmt.Sprintf("No cached waf-blocked record for %s (%s missing) — starting fresh", target, filepath.Base(path)), M_gray)
                } else {
                        logMsg(fmt.Sprintf("WARN: unreadable waf-blocked cache %s (%v) — starting fresh for this target", path, err), M_red)
                }
                return m
        }
        if err := json.Unmarshal(data, &m); err != nil {
                logMsg(fmt.Sprintf("WARN: corrupt waf-blocked cache %s (%v) — starting fresh for this target", path, err), M_red)
                return make(map[string]wafBlockedEntry)
        }
        return m
}

// writeWafBlockedAtomic writes the waf-blocked.json map atomically (via
// writeJSONAtomic). Best-effort: failures are logged, never fatal.
func writeWafBlockedAtomic(path string, m map[string]wafBlockedEntry) {
        if err := writeJSONAtomic(path, m); err != nil {
                logMsg(fmt.Sprintf("Failed to write %s: %v", path, err), M_red)
        }
}

// writeTextAtomic writes content to path via temp-file + rename so a process
// killed mid-write can never leave a truncated/corrupt cache file behind.
func writeTextAtomic(path, content string) error {
        if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
                return err
        }
        tmp := path + ".tmp"
        if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
                return err
        }
        return os.Rename(tmp, path)
}

func writeJSONAtomic(path string, v interface{}) error {
        data, err := json.MarshalIndent(v, "", "  ")
        if err != nil {
                return err
        }
        return writeTextAtomic(path, string(data)+"\n")
}

// loadPathsParamsCache loads a previously written paths-params.json. A missing,
// unreadable or malformed file never aborts the run: a warning is logged and
// this piece simply starts fresh (as if no cache existed).
func loadPathsParamsCache(path, target string) map[string][]string {
        m := make(map[string][]string)
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        logMsg(fmt.Sprintf("No cached path params for %s (%s missing) — starting fresh", target, filepath.Base(path)), M_gray)
                } else {
                        logMsg(fmt.Sprintf("WARN: unreadable path-params cache %s (%v) — starting fresh for this target", path, err), M_red)
                }
                return m
        }
        if err := json.Unmarshal(data, &m); err != nil {
                logMsg(fmt.Sprintf("WARN: corrupt path-params cache %s (%v) — starting fresh for this target", path, err), M_red)
                return make(map[string][]string)
        }
        // Defensive cleanup of a hand-edited cache: drop invalid/duplicate
        // param names so they cannot poison the merged set.
        for k, ps := range m {
                seen := make(map[string]bool)
                var kept []string
                for _, p := range ps {
                        cp := strings.TrimSpace(p)
                        if cp != "" && isValidParamName(cp) && !seen[cp] {
                                seen[cp] = true
                                kept = append(kept, cp)
                        }
                }
                m[k] = kept
        }
        return m
}

// loadTestStateCache loads a previously written test-state.json with the same
// never-fail semantics as loadPathsParamsCache. Entries whose value is not
// exactly "own" or "all" are dropped (treated as never tested, so the path is
// retested) with a warning.
func loadTestStateCache(path, target string) map[string]string {
        m := make(map[string]string)
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        logMsg(fmt.Sprintf("No cached test state for %s (%s missing) — starting fresh", target, filepath.Base(path)), M_gray)
                } else {
                        logMsg(fmt.Sprintf("WARN: unreadable test-state cache %s (%v) — starting fresh for this target", path, err), M_red)
                }
                return m
        }
        if err := json.Unmarshal(data, &m); err != nil {
                logMsg(fmt.Sprintf("WARN: corrupt test-state cache %s (%v) — starting fresh for this target", path, err), M_red)
                return make(map[string]string)
        }
        for k, v := range m {
                if v != testScopeOwn && v != testScopeAll {
                        logMsg(fmt.Sprintf("WARN: test-state entry for %s has unknown scope %q — treating as never tested", k, v), M_red)
                        delete(m, k)
                }
        }
        return m
}

// queryParamKeys returns the valid query-string parameter names carried by the
// URL itself (per-path equivalent of the old host-wide query-param merge).
func queryParamKeys(rawURL string) []string {
        parsed, err := url.Parse(rawURL)
        if err != nil {
                return nil
        }
        seen := make(map[string]bool)
        var keys []string
        for k := range parsed.Query() {
                if isValidParamName(k) && !seen[k] {
                        seen[k] = true
                        keys = append(keys, k)
                }
        }
        sort.Strings(keys)
        return keys
}

// mergeUnique concatenates a and b, dropping duplicates, order-preserving.
func mergeUnique(a, b []string) []string {
        seen := make(map[string]bool)
        var out []string
        for _, s := range a {
                if !seen[s] {
                        seen[s] = true
                        out = append(out, s)
                }
        }
        for _, s := range b {
                if !seen[s] {
                        seen[s] = true
                        out = append(out, s)
                }
        }
        return out
}

// phasePath runs nice_params against a single discovered path and returns
// the params discovered for exactly that path, via nice_params' -json-out
// channel: the RAW per-URL discoveries (res.X8Params + res.FallParams) exactly
// as that run found them for this URL — BEFORE writeHostParamFile()'s host-level
// merge/cap logic ever touches it. nice_params still writes its per-host
// <host>-param.txt side-effect file into the shared params dir (harmless —
// nothing in this flow reads it; cleanup removes it), but the per-path truth
// comes from the throwaway .tmp-<safe(path)>.json file alone.
//
// Returns (params, blockCounterEnd, blockDetected, ok):
//   - params: the cleaned, deduped per-URL params (nil if the run failed);
//     an empty []string with ok=true means "ran successfully, found zero".
//   - blockCounterEnd: the final consecutive-suspicious count after this
//     run's preflight check (read from -json-out's blockCounterEnd field);
//     carries the per-target counter forward across paths.
//   - blockDetected: true if the threshold was crossed during this run
//     (preflight pushed the count over); caller must mark the path as
//     waf-blocked (stage="phase") and abort the rest of the loop.
//   - ok: true when nice_params ran to completion (a run that finds zero
//     params legitimately returns an empty list with ok=true); false on
//     invocation failure — a failed phase is never cached, so the next
//     run retries it.
//
// The blockThreshold argument is forwarded to nice_params as -block-threshold;
// the blockCounterStart argument is forwarded as -block-counter-start and is
// what the caller (processTarget's per-path loop) carries forward across
// sequential subprocess calls within one target.
func phasePath(path string, blockCounterStart int64, blockThreshold int) ([]string, int64, bool, bool) {
        paramsDir := filepath.Join(globalOutputDir, "params")
        tmpJSON := filepath.Join(paramsDir, ".tmp-"+safeFileName(path)+".json")
        // Throwaway intermediate: removed right after use; the cleanup step
        // also sweeps any leftover results/params/.tmp-*.json defensively.
        defer os.Remove(tmpJSON)

        logMsg(fmt.Sprintf("[PHASE] nice_params → %s (block-counter-start=%d, threshold=%d)", path, blockCounterStart, blockThreshold), M_gray)
        args := withAuth([]string{
                "-u", path,
                "-d", paramsDir,
                "-json-out", tmpJSON,
                "-block-counter-start", fmt.Sprintf("%d", blockCounterStart),
                "-block-threshold", fmt.Sprintf("%d", blockThreshold),
        })
        if err := runBinary("./nice_params", args...); err != nil {
                logMsg(fmt.Sprintf("nice_params failed for %s: %v (not cached; will retry on next run)", path, err), M_red)
                return nil, blockCounterStart, false, false
        }

        data, err := os.ReadFile(tmpJSON)
        if err != nil {
                logMsg(fmt.Sprintf("Failed to read phase JSON for %s: %v (not cached; will retry on next run)", path, err), M_red)
                return nil, blockCounterStart, false, false
        }
        // Match the jsonOutEntry shape nice_params writes (now with the two
        // block-guard fields: blockCounterEnd and blockDetected).
        var entries []struct {
                URL              string   `json:"url"`
                Params           []string `json:"params"`
                BlockCounterEnd  int64    `json:"blockCounterEnd"`
                BlockDetected    bool     `json:"blockDetected"`
        }
        if err := json.Unmarshal(data, &entries); err != nil {
                logMsg(fmt.Sprintf("Malformed phase JSON for %s: %v (not cached; will retry on next run)", path, err), M_red)
                return nil, blockCounterStart, false, false
        }

        // Default counterEnd to blockCounterStart so a missing/empty
        // entries slice still preserves the running counter unchanged.
        counterEnd := blockCounterStart
        blockDetected := false
        if len(entries) > 0 {
                counterEnd = entries[0].BlockCounterEnd
                blockDetected = entries[0].BlockDetected
        }

        if blockDetected {
                // No real params to return — the preflight skipped x8/fallparams.
                // Caller records this path in waf-blocked.json (stage="phase")
                // and aborts the rest of the per-path loop.
                return nil, counterEnd, true, false
        }

        // Single-URL mode produces exactly one entry; union defensively with
        // the same rules nice_params already applied (never trust a subprocess
        // blindly — same defense the old harvest code used).
        seen := make(map[string]bool)
        var params []string
        for _, e := range entries {
                for _, p := range e.Params {
                        cp := strings.TrimSpace(p)
                        if cp != "" && isValidParamName(cp) && !seen[cp] {
                                seen[cp] = true
                                params = append(params, cp)
                        }
                }
        }
        sort.Strings(params)
        if params == nil {
                params = []string{} // distinguish "empty discovery" from "failed run"
        }
        return params, counterEnd, false, true
}

// shouldTestPath is the literal per-path test-skip table:
//
//      prev absent  → TEST                      (never tested before)
//      own  + own   → SKIP                      (scope unchanged)
//      own  + all   → TEST  (the ONE explicit exception: previously tested with
//                             only its own params, now must test with the full
//                             merged set; the record is upgraded to "all")
//      all  + own   → SKIP                      (a strictly broader set was
//                                             already tested)
//      all  + all   → SKIP                      (already fully tested)
//
// Kept literal per instruction: no "merged set may have grown since" heuristics
// — only the own→all transition ever triggers a retest.
func shouldTestPath(prevScope, currentScope string) (bool, string) {
        switch {
        case prevScope == "":
                return true, "never tested before"
        case prevScope == testScopeOwn && currentScope == testScopeOwn:
                return false, "already tested with its own params (own == own)"
        case prevScope == testScopeOwn && currentScope == testScopeAll:
                return true, "upgrade: previously tested with own params only — retesting with full merged param set (own → all)"
        case prevScope == testScopeAll && currentScope == testScopeOwn:
                return false, "already tested with the broader merged param set (all ⊇ own)"
        case prevScope == testScopeAll && currentScope == testScopeAll:
                return false, "already tested with the full merged param set (all == all)"
        }
        return true, "unknown previous scope — retesting"
}

// runPathTest invokes xssniper against a single discovered path, feeding it
// the param file appropriate for the current run's scope ("own" param file or
// the merged "all" param file).
//
// Returns (blockCounterEnd, blockDetected) — read from the -block-status-out
// tmp JSON file xssniper writes at the end of its main(). The caller carries
// blockCounterEnd forward to the next path's test call (or the next path's
// phase call in -allparam's two-loop mode); blockDetected=true means the
// threshold was crossed during this xssniper run and the caller must mark
// this path as waf-blocked (stage="test", scope=<"own"|"all">) and abort the
// rest of the per-path loop for this target.
func runPathTest(path, paramFile, xssniperOutDir string, skipSPA bool, phase int, domScan bool, workers, fastWorkers int, blockCounterStart int64, blockThreshold int, scope string) (int64, bool) {
        logMsg(fmt.Sprintf("[TEST] xssniper → %s (params: %s, scope: %s, block-counter-start=%d, threshold=%d)", path, filepath.Base(paramFile), scope, blockCounterStart, blockThreshold), M_cyan)

        // Throwaway file xssniper writes its block-status JSON into (at the
        // very end of its main()). Read + removed right after use.
        paramsDir := filepath.Join(globalOutputDir, "params")
        tmpBlockStatus := filepath.Join(paramsDir, ".tmp-block-"+safeFileName(path)+".json")
        defer os.Remove(tmpBlockStatus)

        args := []string{
                "-u", path,
                "-p", paramFile,
                "-w", fmt.Sprintf("%d", workers),
                "-fast-workers", fmt.Sprintf("%d", fastWorkers),
                "-o", xssniperOutDir,
                "-block-counter-start", fmt.Sprintf("%d", blockCounterStart),
                "-block-threshold", fmt.Sprintf("%d", blockThreshold),
                "-block-status-out", tmpBlockStatus,
        }
        if skipSPA {
                args = append(args, "-skip-spa")
        }
        args = append(args, "-phase", fmt.Sprintf("%d", phase))
        if domScan {
                args = append(args, "-dom-scan")
        }
        // Forward the global -cookie/-header auth flags to xssniper (it merges
        // them into every live curl request and passes them on to
        // curl_reflect_checker / dom_sink_checker).
        args = withAuth(args)
        if err := runBinary("./xssniper", args...); err != nil {
                // The test call still completed (xssniper ran and returned);
                // the caller records the scope either way, mirroring the
                // pipeline's historic fire-and-forget handling of xssniper
                // failures. We still try to read the block-status JSON below
                // — xssniper writes it at the END of main() even on a
                // non-zero exit (the only failure modes that miss it are a
                // SIGKILL mid-run or a missing -block-status-out flag, both
                // already handled by the defaults below).
                logMsg(fmt.Sprintf("xssniper failed for %s: %v", path, err), M_red)
        }

        // Read the block-status JSON xssniper wrote. Missing/unreadable =
        // assume no block signal (preserve blockCounterStart unchanged).
        data, err := os.ReadFile(tmpBlockStatus)
        if err != nil {
                // No file written — preserve the incoming counter unchanged
                // and assume not blocked. This matches xssniper's behavior
                // when -block-threshold was 0 (or when the subprocess was
                // killed before writing).
                return blockCounterStart, false
        }
        var status struct {
                BlockDetected   bool  `json:"blockDetected"`
                BlockCounterEnd int64 `json:"blockCounterEnd"`
        }
        if err := json.Unmarshal(data, &status); err != nil {
                logMsg(fmt.Sprintf("Malformed block-status JSON for %s: %v (assuming not blocked)", path, err), M_red)
                return blockCounterStart, false
        }
        return status.BlockCounterEnd, status.BlockDetected
}

// safeFileName turns a URL into a stable, filesystem-safe, length-capped stem
// for per-path intermediate files (own-scope param files).
func safeFileName(u string) string {
        s := getSafeName(u)
        if len(s) <= 160 {
                return s
        }
        sum := sha1.Sum([]byte(u))
        return s[:144] + "-" + hex.EncodeToString(sum[:8])
}

func writeParamFile(path string, params []string) error {
        content := ""
        if len(params) > 0 {
                content = strings.Join(params, "\n") + "\n"
        }
        return os.WriteFile(path, []byte(content), 0644)
}

func sortedKeys(set map[string]bool) []string {
        out := make([]string, 0, len(set))
        for k := range set {
                out = append(out, k)
        }
        sort.Strings(out)
        return out
}

// buildPathFileURLs reads a -path-file (one RELATIVE path per line, with or
// without query strings) and joins every line onto the -u base target's
// scheme+host. Lines that already carry a full http(s):// URL are accepted
// verbatim. Empty lines and #-comments are skipped; the result is deduped in
// file order. The -u target's own path/query is ignored — only scheme+host
// form the base. The -u target itself is NOT added to the list: if the user
// wants the root scanned, it has to be a line in the file.
func buildPathFileURLs(baseTarget, pathFile string) (paths []string, base string, err error) {
        bu, perr := url.Parse(baseTarget)
        if perr != nil || bu.Scheme == "" || bu.Host == "" {
                return nil, "", fmt.Errorf("-u must be a full URL with scheme and host (e.g. https://sub1.target.com), got %q", baseTarget)
        }
        base = bu.Scheme + "://" + bu.Host

        f, oerr := os.Open(pathFile)
        if oerr != nil {
                return nil, base, oerr
        }
        defer f.Close()

        seen := make(map[string]bool)
        sc := bufio.NewScanner(f)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                full := ""
                if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
                        full = line // absolute line: used verbatim
                } else {
                        if !strings.HasPrefix(line, "/") {
                                line = "/" + line
                        }
                        full = base + line
                }
                if !seen[full] {
                        seen[full] = true
                        paths = append(paths, full)
                }
        }
        if serr := sc.Err(); serr != nil {
                return nil, base, serr
        }
        if len(paths) == 0 {
                return nil, base, fmt.Errorf("no usable paths in %s (empty file, or only blank/# lines?)", pathFile)
        }
        return paths, base, nil
}

// buildDiscoveryFileURLs reads a -discovery-file (one FULL URL per line) and
// returns the URLs that pass a DEFENSIVE re-check (parseable, IsGoodURL, and
// IsSameOrChildHost of baseTarget's host) — drops + log-warns any line that
// fails, since the file may have been hand-edited or sourced from somewhere
// else between the two tool runs (e.g. produced by xsscanner_discover, then
// modified, then fed back into xsscanner via -discovery-file).
//
// This mirrors discoveryutil.MergeAndFilter's filter rules (same IsGoodURL +
// IsSameOrChildHost) so the input to xsscanner's per-path phase→test loop is
// ALWAYS scope-clean regardless of where discoveryList came from. Empty lines
// and #-comments are skipped.
//
// Returns (urls, nil) on success. Returns an error only if the file itself
// can't be opened/read (a programmer error in the caller — bad path). A file
// that exists but contains zero usable URLs is NOT an error here: the caller
// (main.go) treats it the same as -path-file's "no usable paths" case and
// aborts the run with a clear message.
func buildDiscoveryFileURLs(baseTarget, discoveryFile string) (urls []string, err error) {
        bu, perr := url.Parse(baseTarget)
        if perr != nil || bu.Scheme == "" || bu.Host == "" {
                return nil, fmt.Errorf("-u must be a full URL with scheme and host (e.g. https://sub1.target.com), got %q", baseTarget)
        }
        baseHost := bu.Hostname()

        f, oerr := os.Open(discoveryFile)
        if oerr != nil {
                return nil, oerr
        }
        defer f.Close()

        seen := make(map[string]bool)
        sc := bufio.NewScanner(f)
        dropped := 0
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                // Defensive re-check: same checks discoveryutil.MergeAndFilter
                // applies inside xsscanner_discover. A hand-edited file may
                // have introduced an out-of-scope URL (e.g. a sibling
                // subdomain); drop it with a warning rather than silently
                // including it in discoveryList.
                u, parseErr := url.Parse(line)
                if parseErr != nil {
                        logMsg(fmt.Sprintf("[DISCOVERY-FILE] dropping unparseable line %q: %v", line, parseErr), M_red)
                        dropped++
                        continue
                }
                lHost := u.Hostname()
                if !utils.IsSameOrChildHost(lHost, baseHost) {
                        logMsg(fmt.Sprintf("[DISCOVERY-FILE] dropping out-of-scope URL %q (host %q is not %s or a child of it)", line, lHost, baseHost), M_red)
                        dropped++
                        continue
                }
                if !utils.IsGoodURL(line) {
                        logMsg(fmt.Sprintf("[DISCOVERY-FILE] dropping URL %q (failed utils.IsGoodURL: static asset / numeric / semver / high-entropy segment)", line), M_red)
                        dropped++
                        continue
                }
                if !seen[line] {
                        seen[line] = true
                        urls = append(urls, line)
                }
        }
        if serr := sc.Err(); serr != nil {
                return nil, serr
        }
        if dropped > 0 {
                logMsg(fmt.Sprintf("[DISCOVERY-FILE] %d line(s) dropped from %s after defensive scope re-check against %s", dropped, discoveryFile, baseHost), M_red)
        }
        return urls, nil
}

// ── Cleanup audit types ────────────────────────────────────────────────────────

type CleanupAuditEntry struct {
        Timestamp   string   `json:"timestamp"`
        Target      string   `json:"target"`
        Path        string   `json:"path"`
        Type        string   `json:"type"` // "file" or "dir"
        FileCount   int      `json:"file_count,omitempty"`
        TotalBytes  int64    `json:"total_bytes,omitempty"`
        Removed     bool     `json:"removed"`
        Error       string   `json:"error,omitempty"`
        SampleFiles []string `json:"sample_files,omitempty"`
}

func auditLog(entry CleanupAuditEntry) {
        auditFile := filepath.Join(globalOutputDir, "cleanup_audit.jsonl")
        if f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
                if b, errMarshal := json.Marshal(entry); errMarshal == nil {
                        f.Write(append(b, '\n'))
                }
                f.Close()
        }
}

func removeFile(target, path string) {
        info, err := os.Stat(path)
        if os.IsNotExist(err) {
                return
        }
        removeErr := os.Remove(path)
        entry := CleanupAuditEntry{
                Timestamp: time.Now().Format(time.RFC3339),
                Target:    target,
                Path:      path,
                Type:      "file",
                Removed:   removeErr == nil,
        }
        if info != nil {
                entry.TotalBytes = info.Size()
        }
        if removeErr != nil {
                entry.Error = removeErr.Error()
        }
        auditLog(entry)
}

func removeDir(target, dirPath string) {
        var fileCount int
        var totalBytes int64
        var sampleFiles []string

        _ = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
                if err != nil {
                        return nil
                }
                if !info.IsDir() {
                        fileCount++
                        totalBytes += info.Size()
                        if len(sampleFiles) < 10 {
                                sampleFiles = append(sampleFiles, info.Name())
                        }
                }
                return nil
        })

        removeErr := os.RemoveAll(dirPath)
        entry := CleanupAuditEntry{
                Timestamp:   time.Now().Format(time.RFC3339),
                Target:      target,
                Path:        dirPath,
                Type:        "dir",
                FileCount:   fileCount,
                TotalBytes:  totalBytes,
                Removed:     removeErr == nil,
                SampleFiles: sampleFiles,
        }
        if removeErr != nil {
                entry.Error = removeErr.Error()
        }
        auditLog(entry)

        if removeErr == nil && fileCount > 0 {
                mb := float64(totalBytes) / (1024 * 1024)
                logMsg(fmt.Sprintf("Cleanup: removed %d files (%.2f MB) from %s", fileCount, mb, dirPath), M_green)
        } else if removeErr != nil {
                logMsg(fmt.Sprintf("Cleanup FAILED for %s: %v", dirPath, removeErr), M_red)
        }
}

// preserveVulnerabilityJSONs moves the per-target vulnerability JSON files that
// xssniper writes into its working dir (<xssniperOutDir>/vulnerabilities/*.json)
// over to the final output location (results/vulnerabilities/*.json). It must run
// BEFORE cleanupIntermediateFiles, otherwise the final output artifacts would be
// deleted together with the intermediate probe/attack files.
func preserveVulnerabilityJSONs(target, xssniperOutDir string) {
        srcDir := filepath.Join(xssniperOutDir, "vulnerabilities")
        entries, err := os.ReadDir(srcDir)
        if err != nil {
                return // no vulnerability files produced for this target
        }

        dstDir := filepath.Join(globalOutputDir, "vulnerabilities")
        if err := os.MkdirAll(dstDir, 0755); err != nil {
                logMsg(fmt.Sprintf("Failed to create %s: %v", dstDir, err), M_red)
                return
        }

        moved := 0
        for _, e := range entries {
                if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
                        continue
                }
                src := filepath.Join(srcDir, e.Name())
                dst := filepath.Join(dstDir, e.Name())
                if err := os.Rename(src, dst); err != nil {
                        // Rename failed (e.g. destination exists): fall back to copy+remove.
                        if data, readErr := os.ReadFile(src); readErr == nil {
                                if writeErr := os.WriteFile(dst, data, 0644); writeErr == nil {
                                        os.Remove(src)
                                        moved++
                                } else {
                                        logMsg(fmt.Sprintf("Failed to preserve %s: %v", src, writeErr), M_red)
                                }
                        }
                        continue
                }
                moved++
        }
        os.Remove(srcDir) // remove now-empty source dir

        if moved > 0 {
                logMsg(fmt.Sprintf("Preserved %d vulnerability report(s) to %s for %s", moved, dstDir, target), M_green)
        }
}

func removeDirIfEmpty(target, dirPath string) {
        entries, err := os.ReadDir(dirPath)
        if err != nil || len(entries) > 0 {
                return // missing or still holds data (e.g. other targets in a batch)
        }
        removeErr := os.Remove(dirPath)
        auditLog(CleanupAuditEntry{
                Timestamp: time.Now().Format(time.RFC3339),
                Target:    target,
                Path:      dirPath,
                Type:      "dir",
                Removed:   removeErr == nil,
        })
}

// cleanupIntermediateFiles removes all intermediate artifacts for a target after
// xssniper finishes. Keeps only final output: raw_findings.jsonl, TARGET_REPORT.md,
// vulnerabilities/*.json.
//
// KEEP — never delete (per-target resume state; these MUST persist across runs
// so interrupted or repeated scans can skip already-completed work, per the
// resume/skip-cache behavior):
//
//      results/param_maps/<safeURL>-paths-params.json
//      results/param_maps/<safeURL>-test-state.json
//      results/param_maps/<safeURL>-all-params.txt
//      results/param_maps/<safeURL>-waf-blocked.json       (WAF/block-guard record)
//      results/crawl_cache/<hostname>.passive            (+ .passive.done sentinel)
//      results/crawl_cache/<safeURL>-katana.txt          (+ .katana.txt.done sentinel)
//
// The coarse crawl-stage resume (.done sentinels) reuses these on re-runs;
// they are only ever rebuilt by an explicit -force run. The ONLY file inside
// crawl_cache this cleanup may remove is the transient katana staging file
// (katana_batch_output.txt) — never the .passive/-katana.txt outputs and
// never the .done sentinels. The waf-blocked.json file is NEVER deleted
// (it records which paths the WAF/block guard gave up on so a normal
// future run skips them and -retry-blocked re-attempts them explicitly).
//
// This function deliberately never touches results/param_maps/ or
// results/crawl_cache/ themselves (and never prunes them via removeDirIfEmpty)
// — both directories only ever grow per target and are fully rebuilt only by
// an explicit -force run. (The old empty results/passive|katana/ dirs are
// still pruned below for legacy runs.)
func cleanupIntermediateFiles(target, hostname, safeURL, jobFile string, discoveredHosts []string) {
        logMsg(fmt.Sprintf("Cleaning up intermediate files for %s", target), M_gray)

        // The .passive / -katana.txt outputs now live in results/crawl_cache/ and
        // are NEVER removed here (they are the crawl-stage resume state — see the
        // KEEP list above). Only the transient katana staging file is removed.
        katanaBatchFile := filepath.Join(globalOutputDir, "crawl_cache", "katana_batch_output.txt")
        paramFile := filepath.Join(globalOutputDir, "params", hostname+"-param.txt")
        paramsInputFile := filepath.Join(globalOutputDir, "params", safeURL+"-params-input.txt")
        xssniperOutDir := filepath.Join(globalOutputDir, "xssniper_out", safeURL)
        allCrawledFile := filepath.Join(globalOutputDir, "all_crawled_discovery.txt")

        removeFile(target, katanaBatchFile)
        removeFile(target, paramFile)
        // nice_params bulk mode writes one <HOST>-param.txt per unique host present
        // in the discovery list (child subdomains produce their own files) — remove
        // those too so no intermediate param files are left behind.
        for _, h := range discoveredHosts {
                if h == "" || h == hostname {
                        continue
                }
                removeFile(target, filepath.Join(globalOutputDir, "params", h+"-param.txt"))
        }
        removeFile(target, paramsInputFile)
        if jobFile != "" {
                removeFile(target, jobFile)
        }
        removeFile(target, allCrawledFile)

        // Defensive sweeps for the per-path flow's throwaway intermediates.
        // Each is normally deleted right after use; these catch stragglers
        // from crashed or interrupted runs:
        //   (a) leftover per-path nice_params -json-out temp files
        if tmps, gerr := filepath.Glob(filepath.Join(globalOutputDir, "params", ".tmp-*")); gerr == nil {
                for _, t := range tmps {
                        removeFile(target, t)
                }
        }
        //   (b) every <HOST>-param.txt side-effect file written by
        //       writeHostParamFile — a superset of the explicit removals above,
        //       so hosts that appear only via -path-file lines are covered too
        if hostParamFiles, gerr := filepath.Glob(filepath.Join(globalOutputDir, "params", "*-param.txt")); gerr == nil {
                for _, hf := range hostParamFiles {
                        removeFile(target, hf)
                }
        }
        //   (c) per-path own-scope temp param files + the shared all-scope
        //       merged param file used by -allparam's test loop
        if ownFiles, gerr := filepath.Glob(filepath.Join(xssniperOutDir, "param_own_*")); gerr == nil {
                for _, of := range ownFiles {
                        removeFile(target, of)
                }
        }
        removeFile(target, filepath.Join(xssniperOutDir, "param_all.txt"))

        removeDir(target, xssniperOutDir)

        // Prune now-empty working directories (best-effort; safe in batch mode
        // because processTarget re-creates them for the next target).
        removeDirIfEmpty(target, filepath.Join(globalOutputDir, "passive"))
        removeDirIfEmpty(target, filepath.Join(globalOutputDir, "katana"))
        removeDirIfEmpty(target, filepath.Join(globalOutputDir, "params"))
        removeDirIfEmpty(target, filepath.Join(globalOutputDir, "xssniper_out"))
}

// ── Target processing (Sequential Waterfall + per-path phase→test loop) ──────

// processTarget runs the pipeline for one target:
//
//      STEP A  nice_passive        (passive URL discovery)
//      STEP B  nice_katana         (crawl of passive results)
//      STEP C  build discoveryList (scope-filtered, deduped, exact URL strings)
//      STEP D  per-path phase→test loop with resume/skip-cache:
//                - default:   interleaved — phase a path with nice_params, then
//                             immediately test it with xssniper using ONLY its own
//                             discovered params (scope "own")
//                - -allparam: two-phase — first phase EVERY path, then test every
//                             path with the full merged param set (scope "all")
//      STEP E  persist resume state (paths-params.json / test-state.json /
//                all-params.txt) — also written incrementally during STEP D
//
// Scan modes (exactly one of these shapes the discovery list; see STEP D):
//
//      normal           crawl (nice_passive + nice_katana) + scope-filtered merge
//      -only            no crawl at all; the discovery list is just the target URL
//                       itself (a 1-item list; with -i every line is its own
//                       independent single-URL target)
//      -path-file       no crawl; the discovery list is the file's relative paths
//                       joined onto the -u base scheme+host — the -u target itself
//                       is NOT auto-included (it is scanned only if it is a line in
//                       the file)
//      -discovery-file  no crawl; the discovery list comes from a file produced by
//                       the standalone xsscanner_discover binary (or hand-edited
//                       equivalent) — one FULL URL per line, scope-re-checked on
//                       load by buildDiscoveryFileURLs (drop + log-warn on any line
//                       that fails IsGoodURL or IsSameOrChildHost). The -u target
//                       itself is NOT auto-included (it is scanned only if it is a
//                       line in the file). Same downstream pipeline as -path-file.
//
// Resume behavior (unless -force): paths with cached params in
// results/param_maps/<safeURL>-paths-params.json are never re-phased, and
// paths whose test-state record already covers the current run's scope are
// never re-tested. The ONLY transition that triggers a retest is
// "own" → "all" (a path previously tested with just its own params must be
// retested once with the full merged set when -allparam is used).
func processTarget(target string, skipSPA bool, noCrawl bool, phase int, domScan bool, useKatana bool, workers int, fastWorkers int, allParam bool, force bool, only bool, pathFileURLs []string, discoveryFileURLs []string, blockThreshold int, retryBlocked bool) {
        logMsg(fmt.Sprintf("--- Starting: %s ---", target), M_purple+M_bold)

        u, err := url.Parse(target)
        if err != nil {
                logMsg(fmt.Sprintf("Invalid URL: %s", target), M_red)
                return
        }
        hostname := u.Hostname()
        if hostname == "" {
                hostname = target
        }
        safeURL := getSafeName(target)

        // Crawl-stage resume cache (D): the passive/katana outputs moved from
        // results/passive|katana/ into results/crawl_cache/, next to their
        // .done sentinels. Everything in there is resume state — cleanup never
        // deletes it (see the KEEP list on cleanupIntermediateFiles).
        crawlCacheDir := filepath.Join(globalOutputDir, "crawl_cache")
        paramsDir := filepath.Join(globalOutputDir, "params")

        xssniperOutDir := filepath.Join(globalOutputDir, "xssniper_out", safeURL)
        os.MkdirAll(xssniperOutDir, 0755)

        os.MkdirAll(crawlCacheDir, 0755)
        os.MkdirAll(paramsDir, 0755)

        passiveOutFile := filepath.Join(crawlCacheDir, hostname+".passive")
        katanaOutFile := filepath.Join(crawlCacheDir, safeURL+"-katana.txt")

        // Collected discovery URLs (scope-filtered) for this target
        var discoveredURLs []string

        if !noCrawl && !only && pathFileURLs == nil && discoveryFileURLs == nil {
                // STEP A: Passive discovery — with coarse crawl-stage resume:
                // if a previous run already completed nice_passive for this host
                // (output file AND .done sentinel present, -force not set), the
                // cached file is reused as-is and the subprocess is skipped.
                if fileExists(passiveOutFile) && fileExists(passiveOutFile+".done") && !force {
                        logMsg(fmt.Sprintf("[CACHE-SKIP passive] %s — nice_passive already completed for this host, reusing %s", hostname, filepath.Base(passiveOutFile)), M_green)
                } else {
                        logMsg(fmt.Sprintf("[1/3] Running nice_passive for %s", target), M_gray)
                        // NOTE: nice_passive itself gets NO -cookie/-header (scope
                        // note: it only queries third-party archives, never the
                        // target — and it defines no such flags).
                        if err := runBinary("./nice_passive", "-o", crawlCacheDir, hostname); err != nil {
                                // No .done on failure (and no deletion of whatever
                                // partial file exists): the next run retries from scratch.
                                logMsg(fmt.Sprintf("nice_passive failed for %s: %v (no .done written; next run retries)", target, err), M_red)
                        } else if countLines(passiveOutFile) > 0 {
                                // .done ONLY on: subprocess success AND non-empty output.
                                // (nice_passive itself gets no -cookie/-header: it only
                                // queries third-party archives, never the target.)
                                writeDone(passiveOutFile + ".done")
                        }
                }

                // STEP B: Katana crawl (default ON; pass -use-katana=false to
                // disable), with the same coarse resume pattern via its own
                // .done sentinel. If useKatana is false neither the run nor the
                // .done check happens (unchanged gating).
                if useKatana {
                        // Katana now crawls from ONLY the original input target URL (once),
                        // not from the passive-discovery output. Passive discovery and
                        // active katana discovery are two independent, parallel sources
                        // that both feed into the SAME discoveryList afterward (see
                        // STEP C below: appendSafe(passiveOutFile) + appendSafe(katanaOutFile)),
                        // not sequential inputs to each other. (Previously this fed
                        // passiveOutFile as katana's seed list, which re-crawled every
                        // passively-discovered endpoint as a starting point — wrong.)
                        if spadetect.IsSPA(target) {
                                logMsg(fmt.Sprintf("[SKIP-SPA] %s: SPA detected, skipping katana crawl", target), M_cyan)
                        } else if fileExists(katanaOutFile) && fileExists(katanaOutFile+".done") && !force {
                                logMsg(fmt.Sprintf("[CACHE-SKIP katana] %s — nice_katana already completed for this target, reusing %s", target, filepath.Base(katanaOutFile)), M_green)
                        } else {
                                logMsg(fmt.Sprintf("[2/3] Running nice_katana on input target for %s", target), M_gray)
                                if err := runBinary("./nice_katana", withAuth([]string{"-o", crawlCacheDir, target})...); err != nil {
                                        // No .done on failure: the next run re-crawls.
                                        logMsg(fmt.Sprintf("nice_katana failed for %s: %v (no .done written; next run retries)", target, err), M_red)
                                } else {
                                        // nice_katana writes its crawl output to a shared
                                        // "katana_batch_output.txt" staging file. Move it to this
                                        // target's dedicated output file (inside the same
                                        // crawl_cache dir now) so the discovery-merge step below
                                        // (and later cleanup) can consume it deterministically.
                                        batchFile := filepath.Join(crawlCacheDir, "katana_batch_output.txt")
                                        if _, statErr := os.Stat(batchFile); statErr == nil {
                                                if renameErr := os.Rename(batchFile, katanaOutFile); renameErr != nil {
                                                        logMsg(fmt.Sprintf("Failed to move katana batch output to %s: %v (no .done written; next run retries)", katanaOutFile, renameErr), M_red)
                                                } else if countLines(katanaOutFile) > 0 {
                                                        // .done ONLY on: subprocess success AND non-empty output file,
                                                        // matching the spec's "ONLY on ... output file exists and is non-empty".
                                                        writeDone(katanaOutFile + ".done")
                                                } else {
                                                        logMsg(fmt.Sprintf("nice_katana succeeded for %s but %s is empty — no .done written (next run retries)", target, filepath.Base(katanaOutFile)), M_gray)
                                                }
                                        } else {
                                                // Subprocess succeeded but wrote no staging file at
                                                // all (a crawl that finished with zero results).
                                                // Treat identically to the empty-output case: no .done
                                                // written, next run retries (an empty katana file
                                                // contributes zero URLs to the discovery merge either
                                                // way, so re-running is harmless).
                                                logMsg(fmt.Sprintf("nice_katana succeeded for %s but produced no staging file — no .done written (next run retries)", target), M_gray)
                                        }
                                }
                        }
                } else {
                        logMsg(fmt.Sprintf("Katana disabled (-use-katana=false), skipping crawl for %s", target), M_gray)
                }

                // STEP C: Build unified, scope-filtered discovery list.
                // The merge/dedup/scope-filter logic now lives in the shared
                // pkg/discoveryutil package so the new standalone xsscanner_discover
                // binary reuses the EXACT same logic without copy-pasting it.
                // Behavior is identical to the previous inline appendSafe() closure +
                // dedup loop:
                //   - read passiveOutFile then katanaOutFile (either may be missing)
                //   - drop lines that don't parse as URLs, fail utils.IsGoodURL,
                //     or aren't the same host or a child of `hostname`
                //   - dedupe by exact URL string, preserve first-seen order
                var errMerge error
                discoveredURLs, errMerge = discoveryutil.MergeAndFilter(passiveOutFile, katanaOutFile, target)
                if errMerge != nil {
                        // MergeAndFilter tolerates missing/unreadable input files
                        // (treats them as zero lines), so reaching this branch
                        // means a real I/O error mid-scan. Log and continue with
                        // whatever was collected (best-effort, same error-tolerance
                        // pattern as elsewhere in this pipeline).
                        logMsg(fmt.Sprintf("WARN: discoveryutil.MergeAndFilter error for %s: %v (continuing with %d URLs)", target, errMerge, len(discoveredURLs)), M_red)
                }

                logMsg(fmt.Sprintf("Discovery: %d unique scope-filtered URLs for %s", len(discoveredURLs), target), M_cyan)
        } else if only {
                logMsg(fmt.Sprintf("[ONLY] %s: nice_passive/nice_katana skipped; discovery list is just this one URL", target), M_cyan)
        } else if pathFileURLs != nil {
                logMsg(fmt.Sprintf("[PATH-FILE] %s: crawl skipped; discovery list comes from the path file", target), M_cyan)
        } else if discoveryFileURLs != nil {
                logMsg(fmt.Sprintf("[DISCOVERY-FILE] %s: crawl skipped; discovery list comes from the -discovery-file (already scope-filtered at discovery time, with a defensive re-check on load)", target), M_cyan)
        }

        // ── STEP D: per-path phase→test loop (with resume/skip-cache) ─────────
        //
        // discoveryList holds the EXACT URL strings that double as cache keys
        // in results/param_maps/<safeURL>-paths-params.json and
        // <safeURL>-test-state.json. They are used verbatim — never
        // re-normalized or re-ordered — so keys match exactly between runs.
        //
        // List source by scan mode:
        //      normal          the target itself first (the old job-file behavior
        //                      preserved: the scanned root always gets phased and
        //                      tested), then the crawl's scope-filtered URLs
        //      -only           just the target URL itself (1-item list)
        //      -path-file      ONLY the file's paths joined onto the -u base — the
        //                      -u target itself is NOT auto-included (it is scanned
        //                      only if it is a line in the file)
        //      -discovery-file the file's full URLs (one per line, scope-re-checked
        //                      by buildDiscoveryFileURLs on load) — the -u target
        //                      itself is NOT auto-included (it is scanned only if
        //                      it is a line in the file)
        var discoveryList []string
        if pathFileURLs != nil {
                discoveryList = pathFileURLs
        } else if discoveryFileURLs != nil {
                discoveryList = discoveryFileURLs
        } else {
                discoveryList = []string{target}
                seenPaths := map[string]bool{target: true}
                for _, du := range discoveredURLs {
                        if !seenPaths[du] {
                                seenPaths[du] = true
                                discoveryList = append(discoveryList, du)
                        }
                }
        }
        listSource := "crawl"
        if pathFileURLs != nil {
                listSource = "path-file"
        } else if discoveryFileURLs != nil {
                listSource = "discovery-file"
        } else if only {
                listSource = "only"
        }

        mode := "interleaved default (own params per path)"
        if allParam {
                mode = "two-phase -allparam (full merged param set)"
        }
        logMsg(fmt.Sprintf("Per-path pipeline for %s: %d path(s) in discovery list, mode: %s, list source: %s", target, len(discoveryList), mode, listSource), M_cyan)

        // Load resume state unless -force is set. -force treats both files as
        // nonexistent/empty (even if present on disk) and rebuilds them from
        // this run's fresh results — stale entries for paths no longer in
        // discoveryList are NOT kept.
        pathParams := make(map[string][]string)
        testState := make(map[string]string)
        allDiscoveredParams := make(map[string]bool)
        wafBlocked := make(map[string]wafBlockedEntry)
        if force {
                logMsg(fmt.Sprintf("[FORCE] -force set for %s: ignoring existing state files (incl. waf-blocked.json); cache will be rebuilt fresh from this run", target), M_cyan)
        } else {
                pathParams = loadPathsParamsCache(pathsParamsFile(safeURL), target)
                for _, ps := range pathParams {
                        for _, p := range ps {
                                allDiscoveredParams[p] = true
                        }
                }
                testState = loadTestStateCache(testStateFile(safeURL), target)
                wafBlocked = loadWafBlocked(wafBlockedFile(safeURL), target)
                if len(pathParams) > 0 || len(testState) > 0 || len(wafBlocked) > 0 {
                        logMsg(fmt.Sprintf("[CACHE] Resume state loaded for %s: %d path(s) with cached params, %d test record(s), %d waf-blocked path(s)", target, len(pathParams), len(testState), len(wafBlocked)), M_green)
                }
        }

        // currentScope is what THIS run intends to test each path with.
        currentScope := testScopeOwn
        if allParam {
                currentScope = testScopeAll
        }

        // WAF/block guard: the per-target running counter persists across every
        // path within this target's per-path loop — this is the "shared
        // sequential handoff" mechanism since subprocesses can't share memory
        // directly. It is forwarded to nice_params and xssniper as
        // -block-counter-start; each subprocess returns its final value via
        // -json-out (phase) or -block-status-out (test) and we carry it
        // forward to the next call.
        var blockCounter int64 = 0

        // Incremental persistence: state files are rewritten after every fresh
        // phase and every actual test, so killing the process mid-target still
        // leaves a usable partial cache for the next run.
        persistParamsState := func() {
                if err := writeJSONAtomic(pathsParamsFile(safeURL), pathParams); err != nil {
                        logMsg(fmt.Sprintf("Failed to write %s: %v", pathsParamsFile(safeURL), err), M_red)
                }
        }
        persistTestState := func() {
                if err := writeJSONAtomic(testStateFile(safeURL), testState); err != nil {
                        logMsg(fmt.Sprintf("Failed to write %s: %v", testStateFile(safeURL), err), M_red)
                }
        }
        persistAllParams := func() {
                lines := sortedKeys(allDiscoveredParams)
                content := ""
                if len(lines) > 0 {
                        content = strings.Join(lines, "\n") + "\n"
                }
                if err := writeTextAtomic(allParamsListFile(safeURL), content); err != nil {
                        logMsg(fmt.Sprintf("Failed to write %s: %v", allParamsListFile(safeURL), err), M_red)
                }
        }
        persistWafBlocked := func() {
                writeWafBlockedAtomic(wafBlockedFile(safeURL), wafBlocked)
        }

        // recordWafBlocked marks a path as blocked (stage="phase" or
        // stage="test") in wafBlocked, persists the file, and returns true so
        // the caller can break out of the loop. Scope is required for
        // stage="test" (one of "own"/"all"); "" for stage="phase".
        recordWafBlocked := func(path, stage, scope string) {
                wafBlocked[path] = wafBlockedEntry{
                        Stage:           stage,
                        Scope:           scope,
                        BlockCounterEnd: blockCounter,
                        Timestamp:       time.Now().Format(time.RFC3339),
                }
                persistWafBlocked()
                logMsg(fmt.Sprintf("[WAF/BLOCK DETECTED] %s: %s stage blocked at %s (counterEnd=%d, threshold=%d) — recording in waf-blocked.json and aborting the rest of this target's per-path loop", target, stage, path, blockCounter, blockThreshold), M_red)
        }

        // isPhaseBlocked returns true if path is marked as waf-blocked with
        // stage="phase" AND -retry-blocked is NOT set (-force bypasses all
        // of wafBlocked entirely; -retry-blocked treats entries as absent
        // only for the duration of this run).
        isPhaseBlocked := func(path string) bool {
                if force || retryBlocked {
                        return false
                }
                if e, ok := wafBlocked[path]; ok && e.Stage == "phase" {
                        return true
                }
                return false
        }
        // isTestBlocked: ANY existing "test" blocked record for this path skips
        // testing this run (simplest: no scope matching needed).
        isTestBlocked := func(path string) bool {
                if force || retryBlocked {
                        return false
                }
                if e, ok := wafBlocked[path]; ok && e.Stage == "test" {
                        return true
                }
                return false
        }

        // phaseOnePath phases a single path unless it is already cached (then
        // the cached list is reused as-is and still feeds allDiscoveredParams).
        // Returns true if WAF/block was detected during this phase (caller
        // must abort the rest of the per-path loop). Returns false otherwise.
        phaseOnePath := func(path string) bool {
                // WAF/block-guard takes priority over the normal pathParams
                // skip-logic — checked FIRST.
                if isPhaseBlocked(path) {
                        logMsg(fmt.Sprintf("[WAF-BLOCKED-SKIP phase] %s — previously marked blocked (stage=phase) and -retry-blocked not set; skipping nice_params", path), M_cyan)
                        return false
                }
                if !force {
                        if cached, ok := pathParams[path]; ok {
                                logMsg(fmt.Sprintf("[CACHE-SKIP phase] %s — %d param(s) cached from previous run, skipping nice_params", path, len(cached)), M_cyan)
                                for _, p := range cached {
                                        allDiscoveredParams[p] = true
                                }
                                return false
                        }
                }

                var own []string
                ranOK := false
                if noCrawl {
                        // -no-crawl skips network param discovery entirely;
                        // the path's own query-string keys are all we know.
                        own = queryParamKeys(path)
                        ranOK = true
                } else {
                        harvested, counterEnd, blocked, ran := phasePath(path, blockCounter, blockThreshold)
                        // Carry the counter forward regardless of outcome.
                        blockCounter = counterEnd
                        if blocked {
                                // Record in waf-blocked.json (stage="phase"),
                                // remove any partial/empty pathParams[path]
                                // entry, persist, and signal the caller to
                                // abort the rest of the per-path loop.
                                delete(pathParams, path)
                                recordWafBlocked(path, "phase", "")
                                return true
                        }
                        ranOK = ran
                        own = mergeUnique(harvested, queryParamKeys(path))
                }

                // Params join this run's merged set regardless of phase
                // success (query-string keys are facts about the path).
                for _, p := range own {
                        allDiscoveredParams[p] = true
                }
                if !ranOK {
                        // Failed phase is not cached — next run retries it.
                        return false
                }
                if own == nil {
                        own = []string{} // marshal as [] rather than null in the cache JSON
                }
                pathParams[path] = own
                persistParamsState()
                logMsg(fmt.Sprintf("[PHASE] %s → %d own param(s) discovered and cached (blockCounter=%d)", path, len(own), blockCounter), M_gray)
                return false
        }

        // decideTest applies the literal skip table against the previously
        // recorded scope (absent when -force is set).
        decideTest := func(path string) (bool, string) {
                prev := ""
                if !force {
                        prev = testState[path]
                }
                return shouldTestPath(prev, currentScope)
        }

        // testOnePath returns true if WAF/block was detected during this test
        // (caller must abort the rest of the per-path loop). Returns false
        // otherwise.
        testOnePath := func(path, scope, paramFile string) bool {
                counterEnd, blocked := runPathTest(path, paramFile, xssniperOutDir, skipSPA, phase, domScan, workers, fastWorkers, blockCounter, blockThreshold, scope)
                // Carry the counter forward regardless of outcome.
                blockCounter = counterEnd
                if blocked {
                        // Do NOT write testState[path] for it (the test
                        // didn't legitimately complete).
                        recordWafBlocked(path, "test", scope)
                        return true
                }
                testState[path] = scope
                persistTestState()
                // Successful retry of a previously-blocked path: remove its
                // waf-blocked entry now (it tests clean this run).
                if retryBlocked {
                        if _, ok := wafBlocked[path]; ok {
                                delete(wafBlocked, path)
                                persistWafBlocked()
                                logMsg(fmt.Sprintf("[RETRY-BLOCKED] %s: previously blocked, succeeded this run — removed from waf-blocked.json", path), M_green)
                        }
                }
                return false
        }

        // abortRestOfLoop is the shared early-return path for both the
        // default interleaved mode and -allparam's two-loop mode. It still
        // runs STEP E (final authoritative writes of the per-target state)
        // so the partial cache left behind is usable by the next run.
        abortRestOfLoop := func(reason string) {
                logMsg(fmt.Sprintf("[BLOCK-ABORT] %s: %s — aborting the rest of this target's per-path loop (remaining paths untouched, no cache entries written for them)", target, reason), M_red)
        }

        if allParam {
                // Two-phase mode: phase EVERY path first, then test every path
                // against the full merged param set.
                abort := false
                for _, path := range discoveryList {
                        if phaseOnePath(path) {
                                abort = true
                                break
                        }
                }

                if abort {
                        abortRestOfLoop("block threshold reached during phase loop")
                } else {
                        // The aggregate list reflects allDiscoveredParams once phasing
                        // is complete (params reused from cache included).
                        persistAllParams()

                        allFile := filepath.Join(xssniperOutDir, "param_all.txt")
                        if err := writeParamFile(allFile, sortedKeys(allDiscoveredParams)); err != nil {
                                logMsg(fmt.Sprintf("Failed to write merged param file %s: %v", allFile, err), M_red)
                        }

                        for _, path := range discoveryList {
                                if isTestBlocked(path) {
                                        logMsg(fmt.Sprintf("[WAF-BLOCKED-SKIP test] %s — previously marked blocked (stage=test) and -retry-blocked not set; skipping xssniper", path), M_cyan)
                                        continue
                                }
                                if doTest, reason := decideTest(path); doTest {
                                        if testOnePath(path, testScopeAll, allFile) {
                                                abort = true
                                                break
                                        }
                                } else {
                                        logMsg(fmt.Sprintf("[CACHE-SKIP test] %s — %s", path, reason), M_cyan)
                                }
                        }
                        // The merged param file is a single shared throwaway: built
                        // ONCE after the phase loop, reused by every test call, and
                        // deleted now that the test loop is done (cleanup also sweeps
                        // stragglers defensively).
                        os.Remove(allFile)

                        if abort {
                                abortRestOfLoop("block threshold reached during test loop")
                        }
                }
                persistAllParams()
        } else {
                // Default interleaved mode: phase a path, then immediately test
                // it with ONLY its own discovered params.
                abort := false
                for _, path := range discoveryList {
                        if phaseOnePath(path) {
                                abort = true
                                break
                        }
                        if isTestBlocked(path) {
                                logMsg(fmt.Sprintf("[WAF-BLOCKED-SKIP test] %s — previously marked blocked (stage=test) and -retry-blocked not set; skipping xssniper", path), M_cyan)
                                continue
                        }
                        if doTest, reason := decideTest(path); doTest {
                                ownFile := filepath.Join(xssniperOutDir, "param_own_"+safeFileName(path)+".txt")
                                if err := writeParamFile(ownFile, pathParams[path]); err != nil {
                                        logMsg(fmt.Sprintf("Failed to write own param file %s: %v", ownFile, err), M_red)
                                }
                                if testOnePath(path, testScopeOwn, ownFile) {
                                        abort = true
                                        // Per-path temp param file: deleted right after
                                        // its xssniper call returns, BEFORE the next
                                        // path's phase step.
                                        os.Remove(ownFile)
                                        break
                                }
                                // Per-path temp param file: deleted right after
                                // its xssniper call returns, BEFORE the next
                                // path's phase step.
                                os.Remove(ownFile)
                        } else {
                                logMsg(fmt.Sprintf("[CACHE-SKIP test] %s — %s", path, reason), M_cyan)
                        }
                }
                if abort {
                        abortRestOfLoop("block threshold reached during interleaved per-path loop")
                }
                persistAllParams()
        }

        // ── STEP E: final authoritative writes of the per-target state ─────────
        persistParamsState()
        persistTestState()
        persistAllParams()
        logMsg(fmt.Sprintf("State saved for %s: %d path(s) in paths-params.json, %d test record(s) in test-state.json, %d aggregate param(s) in all-params.txt",
                target, len(pathParams), len(testState), len(allDiscoveredParams)), M_green)

        // Collect every host seen in the discovery list (input host + any child
        // subdomains). Legacy bulk nice_params wrote one <HOST>-param.txt per
        // unique host; cleanup still removes any such leftovers (including
        // from older runs) so no intermediate param files are left behind.
        var discoveredHosts []string
        seenHosts := make(map[string]bool)
        for _, u := range discoveredURLs {
                if p, pErr := url.Parse(u); pErr == nil {
                        if h := p.Hostname(); h != "" && !seenHosts[h] {
                                seenHosts[h] = true
                                discoveredHosts = append(discoveredHosts, h)
                        }
                }
        }

        // Preserve final output (per-target vulnerability JSON reports) BEFORE
        // wiping the xssniper working directory.
        preserveVulnerabilityJSONs(target, xssniperOutDir)

        // Unconditional cleanup of intermediate files (no job file is created
        // anymore — the per-path loop invokes xssniper directly with -u).
        cleanupIntermediateFiles(target, hostname, safeURL, "", discoveredHosts)
}

func main() {
        inputFile := flag.String("i", "", "Input file with targets (one URL per line)")
        targetURL := flag.String("u", "", "Single target URL to scan")
        skipSPA := flag.Bool("skip-spa", true, "Skip SPA detection (if true, do not check for SPA)")
        noCrawl := flag.Bool("no-crawl", false, "Skip passive and katana crawling entirely")
        phase := flag.Int("phase", 4, "Pipeline phase to stop at (2, 3, or 4)")
        domScan := flag.Bool("dom-scan", false, "Enable DOM/headless sink checks (passed through to xssniper; slow, off by default)")
        useKatana := flag.Bool("use-katana", true, "Run nice_katana crawl step (on by default; pass -use-katana=false to disable)")
        allParam := flag.Bool("allparam", false, "Two-phase mode: phase ALL discovered paths first, then test every path with the full merged parameter set (default: interleaved per-path testing with each path's OWN params only)")
        force := flag.Bool("force", false, "Bypass the per-path resume cache: re-phase and re-test every path regardless of existing state files, and rebuild the state files fresh (stale entries are dropped, not merged)")
        only := flag.Bool("only", false, "Scan ONLY the input target URL itself: skip nice_passive and nice_katana entirely; each target's discovery list is just that one URL (still phased with nice_params and tested with xssniper). With -i, every line is its own independent single-URL target")
        pathFile := flag.String("path-file", "", "File of manually-curated RELATIVE paths (one per line, with or without query strings, e.g. /search?search=test); each line is joined with the -u scheme+host to build the discovery list (a full http(s):// line is used verbatim). Skips crawling entirely. Requires -u; mutually exclusive with -only; any -i is ignored with a warning (targets come from -u only)")
        discoveryFile := flag.String("discovery-file", "", "File of pre-discovered FULL URLs (one per line), typically produced by the standalone xsscanner_discover binary. Skips nice_passive/nice_katana entirely and feeds the per-path phase→test loop directly — same downstream pipeline as -path-file. Requires -u; mutually exclusive with -only, -path-file, and -i. Each line is defensively re-checked (IsGoodURL + IsSameOrChildHost of -u's host) on load and dropped with a warning if it fails — so a hand-edited file with an out-of-scope sibling subdomain gets that line dropped, not silently included")
        cookie := flag.String("cookie", "", "Raw Cookie header value forwarded to every live request against the target (nice_katana crawl, nice_params/x8 probes, xssniper and its curl_reflect_checker/dom_sink_checker subprocesses), e.g. \"session=abc123; other=val\"")
        var headers headerList
        flag.Var(&headers, "header", "Extra HTTP header forwarded to every live request against the target, format \"Name: Value\" (repeatable, order preserved)")

        // WAF/block guard: per-target consecutive-suspicious threshold. Each
        // subprocess call (nice_params phase, xssniper test) is given this
        // threshold AND the running counter via -block-counter-start; the
        // counter is carried forward across sequential subprocess calls within
        // a single target so 5 suspicious responses from path1's phase + 4
        // more from path2's phase = block detected at path2 (even though
        // neither alone hit 9). When the threshold is crossed mid-target the
        // rest of the per-path loop is aborted (paths not yet reached are
        // left untouched — no cache entries anywhere — so a future run
        // attempts them fresh).
        blockThreshold := flag.Int("block-threshold", 9, "Consecutive-suspicious-response threshold at which xsscanner marks the current target as WAF/blocked and aborts the rest of its per-path loop. Forwarded to nice_params and xssniper as -block-threshold. Default 9")
        // -retry-blocked: when set, paths present in waf-blocked.json are
        // treated as NOT blocked for this run's skip-checks (their phase/test
        // are attempted normally per the existing pathParams/testState rules,
        // as if the waf-blocked record didn't exist). The block-counter
        // pass-through + threshold-abort logic STILL applies: if the path
        // blocks again this run, its waf-blocked entry is updated and the
        // rest of the loop is still aborted. On a successful retry the entry
        // is removed from waf-blocked.json. -force still bypasses everything
        // (including waf-blocked).
        retryBlocked := flag.Bool("retry-blocked", false, "Re-attempt paths previously marked WAF/blocked in <target>-waf-blocked.json (those are normally SKIPPED on subsequent runs). On success the entry is removed; on renewed blocking it is updated and the rest of the loop is still aborted. -force still bypasses everything (including waf-blocked)")

        var workers int
        flag.IntVar(&workers, "w", 3, "Value passed as -w to xssniper subprocess")
        var fastWorkers int
        flag.IntVar(&fastWorkers, "fast-workers", 15, "Value passed as -fast-workers to xssniper subprocess")
        var paramsWorkers int
        flag.IntVar(&paramsWorkers, "params-workers", 5, "Legacy: per-path param phasing is sequential, so this worker count is currently unused (kept for CLI compatibility)")

        flag.Parse()

        // Global auth args (-cookie / repeatable -header): built once here and
        // appended by withAuth() to every subprocess that hits the target live.
        // nice_passive is never given them (third-party archives only).
        if *cookie != "" {
                globalAuthArgs = append(globalAuthArgs, "-cookie", *cookie)
        }
        for _, h := range headers {
                globalAuthArgs = append(globalAuthArgs, "-header", h)
        }

        // -path-file validation must come before the generic -u/-i check below
        // so these combinations fail with specific, actionable messages:
        //   -path-file without -u           → hard error (no base host to join to)
        //   -path-file together with -only  → hard error (mutually exclusive)
        //   -path-file together with -i     → -i is loudly ignored (documented):
        //                                      -path-file implies a single base
        //                                      target via -u, consistent with -u's
        //                                      existing precedence over -i
        if *pathFile != "" {
                if *targetURL == "" {
                        fmt.Fprintf(os.Stderr, "Error: -path-file requires -u (the base scheme+host every relative path is joined with)\n")
                        os.Exit(1)
                }
                if *only {
                        fmt.Fprintf(os.Stderr, "Error: -path-file and -only are mutually exclusive (-only = just the -u target itself; -path-file = the file's paths joined to the -u base)\n")
                        os.Exit(1)
                }
                if *inputFile != "" {
                        fmt.Fprintf(os.Stderr, "Warning: -i is ignored in -path-file mode (targets come from -u + the path file only)\n")
                }
        }

        // -discovery-file validation: parallel to -path-file's checks above.
        //   -discovery-file without -u                        → hard error
        //   -discovery-file together with -only               → hard error (mutually exclusive)
        //   -discovery-file together with -path-file          → hard error (mutually exclusive)
        //   -discovery-file together with -i                  → hard error (mutually exclusive)
        //
        // The -i case is a HARD error here (not the "ignored with warning" pattern
        // -path-file uses) because -discovery-file is itself a list of full URLs —
        // there is no consistent way to combine a list of full URLs from -i with a
        // list of full URLs from -discovery-file under a single -u. -i + -u without
        // -discovery-file is fine (every -i line is its own target).
        if *discoveryFile != "" {
                if *targetURL == "" {
                        fmt.Fprintf(os.Stderr, "Error: -discovery-file requires -u (the host that scope re-checks every line in the discovery file must be a child of)\n")
                        os.Exit(1)
                }
                if *only {
                        fmt.Fprintf(os.Stderr, "Error: -discovery-file and -only are mutually exclusive (-only = just the -u target itself; -discovery-file = the file's full URLs as the discovery list)\n")
                        os.Exit(1)
                }
                if *pathFile != "" {
                        fmt.Fprintf(os.Stderr, "Error: -discovery-file and -path-file are mutually exclusive (both supply a discovery list directly; pick one)\n")
                        os.Exit(1)
                }
                if *inputFile != "" {
                        fmt.Fprintf(os.Stderr, "Error: -discovery-file and -i are mutually exclusive (-discovery-file already supplies a list of full URLs under a single -u base; -i would supply a list of targets with no base)\n")
                        os.Exit(1)
                }
        }

        // Input validation must happen before any file/network activity: the only
        // two accepted target sources are -u (single URL) and -i (file, one URL per
        // line). There is no API fallback anymore.
        if *targetURL == "" && *inputFile == "" {
                flag.Usage()
                os.Exit(1)
        }

        // Capture terminal output to temp file explicitly via logWriter
        logFilePath := filepath.Join(os.TempDir(), fmt.Sprintf("scan_log_%d.txt", time.Now().Unix()))
        logFile, err := os.Create(logFilePath)
        if err == nil {
                logWriter = io.MultiWriter(os.Stdout, logFile)
                defer os.Remove(logFilePath)
                defer logFile.Close()
        }

        var errLogger error
        repLogger, errLogger = reporter.NewLogger("results/raw_findings.jsonl")
        if errLogger != nil {
                logMsg(fmt.Sprintf("reporter init failed: %v", errLogger), M_red)
                if logFile != nil {
                        logFile.Close()
                        os.Remove(logFilePath)
                }
                os.Exit(1)
        }
        startTime := time.Now()

        // Build target list from -u or -i only (no API). In -path-file mode the
        // single target is always the -u base URL (any -i was already warned
        // about above); the file's paths are built here once and passed down
        // to processTarget as that target's discovery-list override. The same
        // applies to -discovery-file mode (parallel slot, parallel behavior).
        var targets []string
        var pathFileURLs []string       // non-nil only in -path-file mode
        var discoveryFileURLs []string  // non-nil only in -discovery-file mode

        if *targetURL != "" {
                targets = []string{*targetURL}
                if *pathFile != "" {
                        paths, base, perr := buildPathFileURLs(*targetURL, *pathFile)
                        if perr != nil {
                                logMsg(fmt.Sprintf("Error reading -path-file %s: %v", *pathFile, perr), M_red)
                                return
                        }
                        pathFileURLs = paths
                        logMsg(fmt.Sprintf("Single target mode: %s — path-file: %d path(s) from %s joined to base %s (the -u target itself is not auto-scanned; add it as a line in the file if you want it)", *targetURL, len(paths), *pathFile, base), M_cyan)
                } else if *discoveryFile != "" {
                        urls, derr := buildDiscoveryFileURLs(*targetURL, *discoveryFile)
                        if derr != nil {
                                logMsg(fmt.Sprintf("Error reading -discovery-file %s: %v", *discoveryFile, derr), M_red)
                                return
                        }
                        if len(urls) == 0 {
                                logMsg(fmt.Sprintf("Error: -discovery-file %s contained no usable URLs after defensive scope re-check against %s (empty file, or every line failed IsGoodURL/IsSameOrChildHost)", *discoveryFile, *targetURL), M_red)
                                return
                        }
                        discoveryFileURLs = urls
                        logMsg(fmt.Sprintf("Single target mode: %s — discovery-file: %d URL(s) from %s (defensively re-checked against %s on load; the -u target itself is not auto-scanned — add it as a line in the file if you want it)", *targetURL, len(urls), *discoveryFile, *targetURL), M_cyan)
                } else {
                        logMsg(fmt.Sprintf("Single target mode: %s", *targetURL), M_cyan)
                }
        } else if *inputFile != "" {
                file, err := os.Open(*inputFile)
                if err != nil {
                        logMsg(fmt.Sprintf("Error opening input file: %v", err), M_red)
                        return
                }
                scanner := bufio.NewScanner(file)
                for scanner.Scan() {
                        if t := strings.TrimSpace(scanner.Text()); t != "" {
                                targets = append(targets, t)
                        }
                }
                file.Close()
        }

        if len(targets) == 0 {
                logMsg("No targets to process.", M_green)
                return
        }

        logMsg(fmt.Sprintf("Ready to process %d targets.", len(targets)), M_cyan)
        for _, target := range targets {
                processTarget(target, *skipSPA, *noCrawl, *phase, *domScan, *useKatana, workers, fastWorkers, *allParam, *force, *only, pathFileURLs, discoveryFileURLs, *blockThreshold, *retryBlocked)
        }

        mdPath := "results/TARGET_REPORT.md"
        if err := reporter.GenerateMarkdownReport("results/raw_findings.jsonl", mdPath); err != nil {
                logMsg(fmt.Sprintf("report generation failed: %v", err), M_red)
        }

        // WAF/block-guard: append a "⛔ WAF/Blocked — Not Fully Tested" section
        // to the report so a "0 vulnerabilities found" result for a blocked
        // target is never silently misread as "target is clean". Best-effort:
        // a write failure is logged, never fatal.
        if err := reporter.AppendWafBlockedSection(mdPath, paramMapsDir()); err != nil {
                logMsg(fmt.Sprintf("waf-blocked section append failed: %v", err), M_red)
        }

        findings, _ := reporter.ReadFindings("results/raw_findings.jsonl")
        vulnCount := 0
        for _, f := range findings {
                if strings.EqualFold(f.Confidence, "HIGH") {
                        vulnCount++
                }
        }

        reporter.PrintDashboard(reporter.DashboardStats{
                TargetsScanned:   len(targets),
                PassiveURLs:      countPassiveURLsInDir(filepath.Join(globalOutputDir, "crawl_cache")),
                ParamsDiscovered: len(findings),
                VulnsFound:       vulnCount,
                ReportPath:       mdPath,
                Elapsed:          time.Since(startTime),
        })

        // Upload log to Telegram
        loadEnv()
        botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
        chatID := os.Getenv("TELEGRAM_CHAT_ID")

        if botToken != "" && chatID != "" {
                if logFile != nil {
                        logFile.Sync()
                }

                caption := fmt.Sprintf("Targets: %d\nElapsed: %s\nVulns Found: %d",
                        len(targets), time.Since(startTime).Round(time.Second).String(), vulnCount)

                if err := sendTelegramDoc(botToken, chatID, logFilePath, caption); err != nil {
                        logMsg(fmt.Sprintf("Failed to send log to Telegram: %v", err), M_red)
                } else {
                        logMsg("Successfully sent log file to Telegram.", M_green)
                }
        }
}