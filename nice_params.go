package main

import (
        "bufio"
        "bytes"
        "context"
        "encoding/json"
        "flag"
        "fmt"
        "net/url"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "regexp"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"

        "reconpipeline/pkg/blockguard"
        "reconpipeline/pkg/reporter"
)

var repLogger *reporter.Logger

// ─── ANSI Colors ───────────────────────────────────────────────────────────────

const (
        PR_boldGreen  = "\033[1;32m"
        PR_boldYellow = "\033[1;33m"
        PR_boldRed    = "\033[1;31m"
        PR_boldBlue   = "\033[1;34m"
        PR_boldCyan   = "\033[1;36m"
        PR_boldWhite  = "\033[1;37m"
        PR_dimWhite   = "\033[2;37m"
        PR_reset      = "\033[0m"
)

// ─── Regexes ───────────────────────────────────────────────────────────────────

var (
        x8ParamRegex = regexp.MustCompile(`(?:GET|POST)\s+\S+\s+%\s+(.+)`)
        cleanupRegex = regexp.MustCompile(`%+$`)
        x8FoundRegex = regexp.MustCompile(`\[\+\]\s+(\w[\w\-.]*)`)

        reNumeric = regexp.MustCompile(`^\d+$`)
        reCSSUnit = regexp.MustCompile(`\d+(px|em|rem|vh|vw|ms|fr)$`)
)

// ─── Config & State ────────────────────────────────────────────────────────────

type Config struct {
        URL       string
        URLFile   string
        OutDir    string // Directory to save HOST-param.txt files
        Wordlist  string
        Silent    bool
        KeepTemp  bool
        Threads   int
        Timeout   int
        NoX8      bool
        NoFall    bool
        MaxParams int
        JSONOut   string // Optional: additionally write RAW per-URL discoveries as a JSON array (-json-out; both -u and -f modes)
        Crawl     bool   // فلگ جدید برای اجرای crawl در fallparams
        ReqFile   string // فایل حاوی کل درخواست خام HTTP برای x8 (-r)
        Cookie    string // -cookie: raw Cookie header value forwarded to x8's (and fallparams') requests
        Headers   []string // -header entries forwarded to x8's (and fallparams') requests

        // WAF/block guard (only meaningful/used in -u single-URL mode; no-op in
        // -f bulk mode — the per-path orchestration lives in main.go which calls
        // nice_params once per path with -u).
        BlockCounterStart int64 // incoming consecutive-suspicious count from main.go
        BlockThreshold    int64 // threshold at which this run should report "blocked" and skip x8/fallparams
}

// headerList implements flag.Value for the repeatable -header flag.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
        *h = append(*h, v)
        return nil
}

// ─── fallparams custom-header support probe ──────────────────────────────
//
// fallparams is invoked with only -u (and -crawl) today. We never guess a
// flag name: if the installed fallparams does not advertise a custom-header
// flag (-H/-header/--header) in its help output, a one-time warning is logged
// and its invocation stays exactly as before (auth-gated pages may then be
// under-discovered by fallparams specifically — x8 still carries the headers).

var (
        fallparamsAuthOnce sync.Once
        fallparamsHasHdr   bool
        fallparamsWarnOnce sync.Once
)

// fallparamsSupportsHeaderFlag inspects the installed binary's help output
// (once per process). `fallparams -h` may exit non-zero; the captured output
// still lists the flags, which is all we need.
func fallparamsSupportsHeaderFlag() bool {
        fallparamsAuthOnce.Do(func() {
                out, _ := exec.Command("fallparams", "-h").CombinedOutput()
                text := string(out)
                hasFlag := func(name string) bool {
                        re := regexp.MustCompile(`(?m)(?:^|\s)` + regexp.QuoteMeta(name) + `(?:\s|=|$)`)
                        return re.MatchString(text)
                }
                fallparamsHasHdr = hasFlag("-H") || hasFlag("-header") || hasFlag("--header")
        })
        return fallparamsHasHdr
}

var (
        tempFiles []string
        tempMu    sync.Mutex
        printMu   sync.Mutex
        logMu     sync.Mutex // New mutex for logging in silent mode
)

// ─── Cleanup ───────────────────────────────────────────────────────────────────

func registerTemp(path string) {
        tempMu.Lock()
        tempFiles = append(tempFiles, path)
        tempMu.Unlock()
}

func cleanup() {
        tempMu.Lock()
        defer tempMu.Unlock()
        for _, f := range tempFiles {
                os.RemoveAll(f)
        }
}

// ─── Printing & Logging ────────────────────────────────────────────────────────

func printf(format string, args ...interface{}) {
        printMu.Lock()
        fmt.Printf(format, args...)
        printMu.Unlock()
}

func logErrorMsg(msg string) {
        logMu.Lock()
        defer logMu.Unlock()
        fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}

func printInfo(msg string)    { printf("%s[*]%s %s\n", PR_boldBlue, PR_reset, msg) }
func printSuccess(msg string) { printf("%s[+]%s %s\n", PR_boldGreen, PR_reset, msg) }
func printWarning(msg string) { printf("%s[!]%s %s\n", PR_boldYellow, PR_reset, msg) }
func printError(msg string)   { printf("%s[-]%s %s\n", PR_boldRed, PR_reset, msg) }
func printStep(msg string)    { printf("%s[>]%s %s\n", PR_boldBlue, PR_reset, msg) }

func printSep() {
        printf("%s%s%s\n", PR_dimWhite, strings.Repeat("─", 50), PR_reset)
}

// ─── Output File Naming ────────────────────────────────────────────────────────

func getHostFilename(rawURL, outDir string) string {
        parsed, err := url.Parse(rawURL)
        var host string
        if err == nil && parsed.Hostname() != "" {
                host = parsed.Hostname()
        } else {
                // Fallback for weird URLs
                host = strings.ReplaceAll(rawURL, "https://", "")
                host = strings.ReplaceAll(host, "http://", "")
                host = strings.Split(host, "/")[0]
        }

        // Example: asda.com-param.txt
        filename := host + "-param.txt"
        return filepath.Join(outDir, filename)
}

// ─── Param Helpers ─────────────────────────────────────────────────────────────

func cleanParam(p string) string {
        p = cleanupRegex.ReplaceAllString(p, "")
        p = strings.ReplaceAll(p, "payload%", "payload")
        p = strings.TrimSpace(p)
        return p
}

func isValidParam(p string) bool {
        // Length window 2-50
        if len(p) < 2 || len(p) > 50 {
                return false
        }
        // Reject pure numeric
        if reNumeric.MatchString(p) {
                return false
        }
        // Reject CSS variables
        if strings.HasPrefix(p, "--") {
                return false
        }
        // Reject whitespace
        if strings.ContainsAny(p, " \t\n\r") {
                return false
        }
        // Reject CSS units
        if reCSSUnit.MatchString(p) {
                return false
        }
        return true
}

func readParams(filename string) ([]string, error) {
        content, err := os.ReadFile(filename)
        if err != nil {
                return nil, err
        }
        seen := make(map[string]bool)
        var out []string
        sc := bufio.NewScanner(strings.NewReader(string(content)))
        for sc.Scan() {
                p := cleanParam(sc.Text())
                if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
                        seen[p] = true
                        out = append(out, p)
                }
        }
        return out, nil
}

var fileMu sync.Mutex

func writeHostParamFile(outFile string, x8Params []string, fallParams []string, maxParams int) (int, error) {
        fileMu.Lock()
        defer fileMu.Unlock()

        existing, err := readParams(outFile)
        if err != nil && !os.IsNotExist(err) {
                logErrorMsg(fmt.Sprintf("failed to read existing params from %s: %v", outFile, err))
        }

        seen := make(map[string]bool)
        var final []string

        // 1. Prioritize existing content
        for _, p := range existing {
                if !seen[p] && len(final) < maxParams {
                        seen[p] = true
                        final = append(final, p)
                }
        }

        // 2. Prioritize X8 parameters
        x8Dropped := 0
        for _, p := range x8Params {
                p = cleanParam(p)
                if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
                        if len(final) < maxParams {
                                seen[p] = true
                                final = append(final, p)
                        } else {
                                x8Dropped++
                        }
                }
        }

        // 3. Finally Fallparams
        fallDropped := 0
        for _, p := range fallParams {
                p = cleanParam(p)
                if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
                        if len(final) < maxParams {
                                seen[p] = true
                                final = append(final, p)
                        } else {
                                fallDropped++
                        }
                }
        }

        if x8Dropped > 0 || fallDropped > 0 {
                msg := fmt.Sprintf("Max params (%d) reached for %s. Dropped %d x8 and %d fallparams.", maxParams, filepath.Base(outFile), x8Dropped, fallDropped)
                printWarning(msg)
        }

        if len(final) == len(existing) {
                return 0, nil
        }

        host := strings.TrimSuffix(filepath.Base(outFile), "-param.txt")
        for _, p := range final[len(existing):] {
                repLogger.Log(reporter.NewFinding(
                        host, outFile, p, "fallparams/x8", "MEDIUM", "parameter_discovered",
                        reporter.Context{Location: "discovered parameter list"},
                ))
        }

        f, err := os.Create(outFile)
        if err != nil {
                return 0, err
        }
        defer f.Close()
        for _, p := range final {
                fmt.Fprintln(f, p)
        }
        return len(final) - len(existing), nil
}

// ─── -json-out: RAW per-URL discoveries ────────────────────────────────────────
//
// When -json-out <file> is set (works in BOTH -u and -f modes), nice_params
// additionally records, for every URL it processes, the RAW per-URL
// discoveries — exactly what that specific run found for that specific URL
// (res.X8Params + res.FallParams), BEFORE writeHostParamFile()'s host-level
// merge/cap logic touches it. Each URL's list is cleaned/deduped with the
// same cleanParam()/isValidParam() rules used everywhere else in this file.
// The existing <HOST>-param.txt mechanism keeps running alongside, unchanged.

type jsonOutEntry struct {
        URL    string   `json:"url"`
        Params []string `json:"params"`
        // WAF/block guard (single-URL mode only): the final consecutive-suspicious
        // counter value after this run's preflight check (and, if the threshold
        // was crossed, x8/fallparams were skipped), and whether the threshold
        // was crossed during this run. main.go reads these to carry the counter
        // forward to the next path's phase/test call.
        BlockCounterEnd int64 `json:"blockCounterEnd"`
        BlockDetected   bool  `json:"blockDetected"`
}

// rawPerURLParams unions a URL's raw discoveries (x8 first, then fallparams —
// the same priority writeHostParamFile uses) under the standard cleaning rules.
func rawPerURLParams(x8Params, fallParams []string) []string {
        seen := make(map[string]bool)
        var out []string
        add := func(p string) {
                p = cleanParam(p)
                if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || !isValidParam(p) || seen[p] {
                        return
                }
                seen[p] = true
                out = append(out, p)
        }
        for _, p := range x8Params {
                add(p)
        }
        for _, p := range fallParams {
                add(p)
        }
        if out == nil {
                out = []string{} // marshal as [] rather than null
        }
        return out
}

// appendJSONOutEntry records one URL's raw discoveries; URLs whose processing
// failed (res.Err != nil) are never recorded, mirroring the host-file path
// (which likewise skips them). The block-counter fields are always carried
// through so main.go can read them from -json-out and carry the counter
// forward to the next path's phase call (and detect threshold breaches).
func appendJSONOutEntry(entries *[]jsonOutEntry, res Result) {
        if res.Err != nil {
                return
        }
        *entries = append(*entries, jsonOutEntry{
                URL:              res.URL,
                Params:           rawPerURLParams(res.X8Params, res.FallParams),
                BlockCounterEnd:  res.BlockCounterEnd,
                BlockDetected:    res.BlockDetected,
        })
}

// writeJSONOutFile writes the collected entries as a JSON array. A nil slice
// is normalized to [] so an empty run still produces valid JSON.
func writeJSONOutFile(path string, entries []jsonOutEntry) error {
        if entries == nil {
                entries = []jsonOutEntry{}
        }
        if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
                return err
        }
        data, err := json.MarshalIndent(entries, "", "  ")
        if err != nil {
                return err
        }
        return os.WriteFile(path, append(data, '\n'), 0644)
}

// ─── Tool Check ────────────────────────────────────────────────────────────────

func checkTool(toolName string) error {
        _, err := exec.LookPath(toolName)
        if err != nil {
                return fmt.Errorf("%s not found in PATH. Please install it to use this feature.", toolName)
        }
        return nil
}

// ─── fallparams — Contextual Wordlist Generator ────────────────────────────────

func isCandidateWord(w string) bool {
        if w == "" || len(w) > 100 {
                return false
        }
        if strings.ContainsAny(w, " \t\n\r") {
                return false
        }
        if strings.HasPrefix(w, "/") || strings.HasPrefix(w, "\\") {
                return false
        }
        return true
}

func runFallparams(ctx context.Context, rawURL string, silent bool, crawl bool, authCookie string, authHeaders []string) ([]string, error) {
        if err := checkTool("fallparams"); err != nil {
                return nil, err
        }

        if !silent {
                printStep(fmt.Sprintf("fallparams → %s (contextual wordlist gen)", rawURL))
        }

        runDir, err := os.MkdirTemp("", "fall_isolate_*")
        if err != nil {
                return nil, fmt.Errorf("failed to create temp directory for fallparams: %v", err)
        }
        registerTemp(runDir)

        // تعریف آرگومان‌ها به صورت پویا با توجه به crawl
        args := []string{"-u", rawURL}
        if crawl {
                args = append(args, "-crawl")
        }

        // Global auth headers (-cookie/-header): forwarded the same way as
        // katana/x8 (extra -H entries) IF the installed fallparams advertises a
        // custom-header flag; otherwise a one-time warning and no change to the
        // invocation (never guess a flag name, never fail the run over this).
        if authCookie != "" || len(authHeaders) > 0 {
                if fallparamsSupportsHeaderFlag() {
                        if authCookie != "" {
                                args = append(args, "-H", "Cookie: "+authCookie)
                        }
                        for _, h := range authHeaders {
                                args = append(args, "-H", h)
                        }
                } else {
                        fallparamsWarnOnce.Do(func() {
                                const w = "[nice_params] fallparams does not appear to support custom headers/cookies — auth-gated pages may be under-discovered by fallparams specifically"
                                if !silent {
                                        printWarning(w)
                                } else {
                                        logErrorMsg(w)
                                }
                        })
                }
        }

        cmd := exec.CommandContext(ctx, "fallparams", args...)
        cmd.Dir = runDir

        _, _ = cmd.CombinedOutput()

        fallOutPath := filepath.Join(runDir, "parameters.txt")
        content, err := os.ReadFile(fallOutPath)
        if err != nil {
                if !silent {
                        printInfo("fallparams: no output file found")
                }
                return nil, nil
        }

        var candidates []string
        seen := make(map[string]bool)
        sc := bufio.NewScanner(strings.NewReader(string(content)))
        for sc.Scan() {
                w := strings.TrimSpace(sc.Text())
                w = cleanParam(w)
                if isCandidateWord(w) && !seen[w] {
                        seen[w] = true
                        candidates = append(candidates, w)
                }
        }

        if !silent {
                if len(candidates) > 0 {
                        printSuccess(fmt.Sprintf("fallparams: %d candidate words extracted (feeding to x8 wordlist)", len(candidates)))
                } else {
                        printInfo("fallparams: no candidate words found")
                }
        }
        return candidates, nil
}

// ─── Wordlist Merging ──────────────────────────────────────────────────────────

func buildCombinedWordlist(baseWordlist string, candidates []string) (string, int, error) {
        base, err := os.ReadFile(baseWordlist)
        if err != nil {
                return "", 0, fmt.Errorf("failed to read base wordlist %s: %v", baseWordlist, err)
        }

        seen := make(map[string]bool)
        var lines []string

        sc := bufio.NewScanner(strings.NewReader(string(base)))
        buf := make([]byte, 0, 64*1024)
        sc.Buffer(buf, 1024*1024)
        for sc.Scan() {
                w := strings.TrimSpace(sc.Text())
                if w == "" || seen[w] {
                        continue
                }
                seen[w] = true
                lines = append(lines, w)
        }

        added := 0
        for _, w := range candidates {
                if seen[w] {
                        continue
                }
                seen[w] = true
                lines = append(lines, w)
                added++
        }

        tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("combined_wordlist_%d_%d.txt", os.Getpid(), time.Now().UnixNano()))
        f, err := os.Create(tmpFile)
        if err != nil {
                return "", 0, fmt.Errorf("failed to create combined wordlist %s: %v", tmpFile, err)
        }
        for _, w := range lines {
                fmt.Fprintln(f, w)
        }
        f.Close()

        return tmpFile, added, nil
}

// ─── x8 ───────────────────────────────────────────────────────────────────────

func extractX8Params(content string) []string {
        seen := make(map[string]bool)
        var out []string

        addParam := func(p string) {
                p = cleanParam(p)
                if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && isValidParam(p) && !seen[p] {
                        seen[p] = true
                        out = append(out, p)
                }
        }

        sc := bufio.NewScanner(strings.NewReader(content))
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" {
                        continue
                }

                if m := x8ParamRegex.FindStringSubmatch(line); len(m) > 1 {
                        for _, part := range strings.Split(m[1], ",") {
                                addParam(strings.TrimSpace(part))
                        }
                        continue
                }
                if m := x8FoundRegex.FindStringSubmatch(line); len(m) > 1 {
                        addParam(m[1])
                        continue
                }

                if !strings.ContainsAny(line, " [:]") {
                        addParam(line)
                }
        }
        return out
}

func runX8(ctx context.Context, rawURL, wordlist, reqFile string, silent bool, authCookie string, authHeaders []string) ([]string, error) {
        if err := checkTool("x8"); err != nil {
                return nil, err
        }

        if reqFile != "" {
                if _, err := os.Stat(reqFile); err != nil {
                        return nil, fmt.Errorf("request file not found: %s", reqFile)
                }
                if !silent {
                        printStep(fmt.Sprintf("x8 → %s (-r %s)", rawURL, reqFile))
                }
        } else if !silent {
                printStep(fmt.Sprintf("x8 → %s", rawURL))
        }

        if _, err := os.Stat(wordlist); os.IsNotExist(err) {
                return nil, fmt.Errorf("wordlist not found: %s", wordlist)
        }

        tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("x8_%d_%d.txt", os.Getpid(), time.Now().UnixNano()))
        registerTemp(tmpFile)

        // وقتی -r (فایل درخواست خام) داده شده، x8 باید از -r استفاده کنه، نه -u.
        // طبق مستندات x8، این دو سوییچ با هم استفاده نمی‌شن.
        var target []string
        if reqFile != "" {
                target = []string{"-r", reqFile}
        } else {
                target = []string{"-u", rawURL}
        }

        args := append([]string{}, target...)
        args = append(args,
                "-w", wordlist,
                "-o", tmpFile,
                "-c", "5", // کانکارنسی ۵ بسیار عالی و چراغ‌خاموش است
                "--delay", "1000", // اصلاح شد: ۱۰۰۰ میلی‌ثانیه معادل ۱ ثانیه تاخیر واقعی
                "--timeout", "15",
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )

        // Global auth headers (-cookie/-header): extra -H entries alongside the
        // existing User-Agent -H line (same pattern as nice_katana).
        if authCookie != "" {
                args = append(args, "-H", "Cookie: "+authCookie)
        }
        for _, h := range authHeaders {
                args = append(args, "-H", h)
        }

        cmd := exec.CommandContext(ctx, "x8", args...)

        out, err := cmd.CombinedOutput()
        if err != nil {
                msg := fmt.Sprintf("x8 exited non-zero (%v). Output: %s", err, string(out))
                if !silent {
                        printWarning(msg)
                } else {
                        logErrorMsg(msg)
                }
        }

        content, readErr := os.ReadFile(tmpFile)
        if readErr != nil {
                return nil, fmt.Errorf("failed to read x8 output file %s: %v", tmpFile, readErr)
        }

        params := extractX8Params(string(content))

        if !silent {
                if len(params) > 0 {
                        printSuccess(fmt.Sprintf("x8: %d params found", len(params)))
                } else {
                        printInfo("x8: no params found")
                }
        }
        return params, nil
}

// ─── URL Processor ─────────────────────────────────────────────────────────────

type Result struct {
        URL        string
        OutFile    string
        X8Params   []string
        FallParams []string
        Err        error

        // WAF/block guard outputs (single-URL mode only; always populated by
        // processURL so appendJSONOutEntry can record them into the -json-out
        // single-entry object).
        BlockCounterEnd int64
        BlockDetected    bool
}

// preflightBlockCheck issues ONE lightweight curl-based GET to rawURL and
// classifies the response via blockguard.IsSuspiciousResponse. Maintains a
// local counter starting at cfg.BlockCounterStart:
//   - if suspicious → counter++
//   - if not suspicious → counter = 0
//
// If counter >= cfg.BlockThreshold at any point, returns blockDetected=true
// so processURL can SKIP calling fallparams/x8 for this URL (no point
// burning more requests against an already-blocking host). Mirrors the
// curlRequestAttempt-style pattern already used elsewhere in this codebase
// (e.g. in xssniper.go/corscheck.go) — does NOT reinvent a different HTTP
// client. Global auth headers (-cookie/-header from cfg) are forwarded to
// the preflight so the request looks like a real probe, not a bare curl.
func preflightBlockCheck(rawURL, cookie string, headers []string, counterStart, threshold int64) (counterEnd int64, detected bool) {
        counterEnd = counterStart
        if threshold <= 0 {
                return counterEnd, false // not configured — no-op
        }

        // Build curl args mirroring xssniper.go's curlRequestAttempt pattern
        // (curl-exec'd to avoid JA3 fingerprinting; -i for headers; HTTPSTATUS
        // marker appended to stdout). A short timeout keeps the preflight cheap.
        args := []string{
                "-s", "-L", "-i",
                "--max-time", "10",
                "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                "-w", "\\nHTTPSTATUS:%{http_code}",
        }
        if cookie != "" {
                args = append(args, "-H", "Cookie: "+cookie)
        }
        for _, h := range headers {
                args = append(args, "-H", h)
        }
        args = append(args, rawURL)

        cmdCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
        defer cancel()

        cmd := exec.CommandContext(cmdCtx, "curl", args...)
        out, _ := cmd.Output() // ignore exit code: a 403/429 response still has a body

        marker := []byte("\nHTTPSTATUS:")
        idx := bytes.LastIndex(out, marker)
        if idx < 0 {
                // Network failure / unparseable — not a block signal on its own
                // (the existing DEAD-MIDSCAN logic in xssniper handles retries).
                return counterEnd, false
        }
        statusStr := strings.TrimSpace(string(out[idx+len(marker):]))
        statusCode, err := strconv.Atoi(statusStr)
        if err != nil || statusCode == 0 {
                return counterEnd, false
        }
        body := out[:idx]

        if blockguard.IsSuspiciousResponse(statusCode, body) {
                counterEnd++
                if counterEnd >= threshold {
                        return counterEnd, true
                }
        } else {
                counterEnd = 0
        }
        return counterEnd, false
}

func processURL(ctx context.Context, rawURL string, cfg *Config) Result {
        if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
                return Result{URL: rawURL, Err: fmt.Errorf("invalid URL (must start with http:// or https://)")}
        }

        outFile := getHostFilename(rawURL, cfg.OutDir)
        toolCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
        defer cancel()

        var res Result
        res.URL = rawURL
        res.OutFile = outFile

        // WAF/block guard: ONE preflight GET to this URL, classified via
        // blockguard.IsSuspiciousResponse. Maintain a local counter starting at
        // cfg.BlockCounterStart; if the threshold is crossed, set blockDetected
        // and SKIP fallparams/x8 entirely for this URL (no point burning more
        // requests against an already-blocking host). res.X8Params/res.FallParams
        // stay empty in that case.
        counterEnd, blocked := preflightBlockCheck(rawURL, cfg.Cookie, cfg.Headers, cfg.BlockCounterStart, cfg.BlockThreshold)
        res.BlockCounterEnd = counterEnd
        res.BlockDetected = blocked
        if blocked {
                const msg = "[nice_params] WAF/BLOCK DETECTED (preflight consecutive-suspicious=%d, threshold=%d) — skipping fallparams/x8 for %s"
                if !cfg.Silent {
                        printWarning(fmt.Sprintf(msg, counterEnd, cfg.BlockThreshold, rawURL))
                } else {
                        logErrorMsg(fmt.Sprintf(msg, counterEnd, cfg.BlockThreshold, rawURL))
                }
                return res
        }

        var fallErr, x8Err error
        var candidates []string

        if !cfg.NoFall {
                // اضافه شدن cfg.Crawl به عنوان پارامتر ورودی
                words, err := runFallparams(toolCtx, rawURL, cfg.Silent, cfg.Crawl, cfg.Cookie, cfg.Headers)
                if err != nil {
                        fallErr = fmt.Errorf("fallparams error for %s: %v", rawURL, err)
                        if !cfg.Silent {
                                printError(fallErr.Error())
                        } else {
                                logErrorMsg(fallErr.Error())
                        }
                } else {
                        candidates = words
                }
        }

        if !cfg.NoX8 {
                x8Wordlist := cfg.Wordlist

                if len(candidates) > 0 {
                        combinedPath, added, buildErr := buildCombinedWordlist(cfg.Wordlist, candidates)
                        if buildErr != nil {
                                msg := fmt.Sprintf("failed to build combined wordlist for %s (falling back to base wordlist): %v", rawURL, buildErr)
                                if !cfg.Silent {
                                        printWarning(msg)
                                } else {
                                        logErrorMsg(msg)
                                }
                        } else {
                                x8Wordlist = combinedPath
                                registerTemp(combinedPath)
                                defer func() {
                                        if !cfg.KeepTemp {
                                                os.Remove(combinedPath)
                                        }
                                }()
                                if !cfg.Silent {
                                        printInfo(fmt.Sprintf("merged %d fallparams candidates into combined wordlist for x8", added))
                                }
                        }
                }

                params, err := runX8(toolCtx, rawURL, x8Wordlist, cfg.ReqFile, cfg.Silent, cfg.Cookie, cfg.Headers)
                if err != nil {
                        x8Err = fmt.Errorf("x8 error for %s: %v", rawURL, err)
                        if !cfg.Silent {
                                printError(x8Err.Error())
                        } else {
                                logErrorMsg(x8Err.Error())
                        }
                } else {
                        res.X8Params = params
                }
        } else if len(candidates) > 0 {
                res.FallParams = candidates
        }

        if fallErr != nil && x8Err != nil {
                res.Err = fmt.Errorf("%v; %v", fallErr, x8Err)
        } else if fallErr != nil {
                res.Err = fallErr
        } else if x8Err != nil {
                res.Err = x8Err
        }

        return res
}

// ─── Multi-URL with worker pool ────────────────────────────────────────────────

func processURLFile(ctx context.Context, cfg *Config) error {
        f, err := os.Open(cfg.URLFile)
        if err != nil {
                return fmt.Errorf("cannot open URL file: %v", err)
        }
        defer f.Close()

        var urls []string
        sc := bufio.NewScanner(f)
        for sc.Scan() {
                u := strings.TrimSpace(sc.Text())
                if u == "" || strings.HasPrefix(u, "#") {
                        continue
                }
                if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
                        u = "https://" + u
                }
                urls = append(urls, u)
        }
        if err := sc.Err(); err != nil {
                return fmt.Errorf("reading URL file: %v", err)
        }
        if len(urls) == 0 {
                return fmt.Errorf("no valid URLs found in %s", cfg.URLFile)
        }

        if !cfg.Silent {
                printInfo(fmt.Sprintf("Loaded %d URLs — %d worker(s) — saving to %s/", len(urls), cfg.Threads, cfg.OutDir))
                printSep()
        }

        jobs := make(chan string, len(urls))
        results := make(chan Result, len(urls))
        var successCount int64
        var totalFound int64

        var wg sync.WaitGroup
        for i := 0; i < cfg.Threads; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for u := range jobs {
                                results <- processURL(ctx, u, cfg)
                        }
                }()
        }

        for _, u := range urls {
                jobs <- u
        }
        close(jobs)

        go func() {
                wg.Wait()
                close(results)
        }()

        processed := 0
        var jsonEntries []jsonOutEntry // collected for -json-out (successful URLs only)
        for res := range results {
                processed++
                if !cfg.Silent {
                        printSep()
                        printf("%s[%d/%d]%s %s\n", PR_boldWhite, processed, len(urls), PR_reset, res.URL)
                }
                if res.Err != nil {
                        if !cfg.Silent {
                                printError(res.Err.Error())
                        } else {
                                logErrorMsg(res.Err.Error())
                        }
                        continue
                }

                atomic.AddInt64(&successCount, 1)

                if cfg.JSONOut != "" {
                        appendJSONOutEntry(&jsonEntries, res) // res.Err was handled by the continue above
                }

                if len(res.X8Params) > 0 || len(res.FallParams) > 0 {
                        added, _ := writeHostParamFile(res.OutFile, res.X8Params, res.FallParams, cfg.MaxParams)
                        atomic.AddInt64(&totalFound, int64(added))
                        if !cfg.Silent {
                                if added > 0 {
                                        printSuccess(fmt.Sprintf("%d new unique params saved to %s", added, res.OutFile))
                                } else {
                                        printInfo(fmt.Sprintf("Params found, but already existed or cap reached in %s", res.OutFile))
                                }
                        }
                } else if !cfg.Silent {
                        printInfo("no params found")
                }
        }

        if !cfg.Silent {
                printSep()
                printf("\n")
                printSuccess(fmt.Sprintf("Done! %d/%d URLs succeeded", successCount, len(urls)))
                printSuccess(fmt.Sprintf("Total unique parameters found: %d", totalFound))
        }

        // -json-out (bulk mode): one entry per successfully processed URL. The
        // <HOST>-param.txt side effect in the loop above stays exactly as it was.
        if cfg.JSONOut != "" {
                if jerr := writeJSONOutFile(cfg.JSONOut, jsonEntries); jerr != nil {
                        return fmt.Errorf("failed to write -json-out file %s: %v", cfg.JSONOut, jerr)
                }
                if !cfg.Silent {
                        printSuccess(fmt.Sprintf("RAW per-URL JSON written to %s (%d URL(s))", cfg.JSONOut, len(jsonEntries)))
                }
        }
        return nil
}

// ─── Main ──────────────────────────────────────────────────────────────────────

func main() {
        cfg := &Config{}

        flag.StringVar(&cfg.URL, "u", "", "Target URL (single)")
        flag.StringVar(&cfg.URL, "url", "", "Target URL (single, alias)")
        flag.StringVar(&cfg.URLFile, "f", "", "File with list of URLs (one per line)")
        flag.StringVar(&cfg.URLFile, "file", "", "File with list of URLs (alias)")
        flag.StringVar(&cfg.OutDir, "d", "results/params", "Output directory to save <HOST>-param.txt files")
        flag.StringVar(&cfg.OutDir, "dir", "results/params", "Output directory (alias)")
        flag.StringVar(&cfg.Wordlist, "w", "", "Wordlist for x8 (default: param.txt next to nice_params)")
        flag.BoolVar(&cfg.Silent, "silent", false, "No terminal output (machine-friendly)")
        flag.BoolVar(&cfg.KeepTemp, "keep-temp", false, "Keep temporary files after exit")
        flag.IntVar(&cfg.Threads, "t", 5, "Concurrent workers (for -f mode)")
        flag.IntVar(&cfg.Timeout, "timeout", 300, "Per-tool timeout in seconds")
        flag.BoolVar(&cfg.NoX8, "no-x8", false, "Skip x8 (fallparams only)")
        flag.BoolVar(&cfg.NoFall, "no-fall", false, "Skip fallparams (x8 only)")
        flag.IntVar(&cfg.MaxParams, "max-params", 200, "Maximum number of parameters to keep per host")
        flag.BoolVar(&cfg.Crawl, "crawl", false, "Use Katana to crawl links with fallparams") // فلگ جدید
        flag.StringVar(&cfg.ReqFile, "r", "", "Raw HTTP request file for x8 (x8 uses -r + this file instead of -u; fallparams still uses -u)")
        flag.StringVar(&cfg.JSONOut, "json-out", "", "Additionally write RAW per-URL discoveries as a JSON array [{\"url\":…,\"params\":[…]}] (both -u and -f modes; unaffected by the <HOST>-param.txt merge/cap)")
        flag.StringVar(&cfg.Cookie, "cookie", "", "Raw Cookie header value forwarded to x8's (and fallparams') live requests, e.g. \"session=abc123; other=val\"")
        var headerFlags headerList
        flag.Var(&headerFlags, "header", "Extra HTTP header forwarded to x8's (and fallparams') live requests, format \"Name: Value\" (repeatable)")

        // WAF/block guard (only meaningful/used in -u single-URL mode; no-op
        // in -f bulk mode — the per-path orchestration lives in main.go which
        // calls nice_params once per path with -u). A single preflight GET to
        // the target URL is classified via blockguard.IsSuspiciousResponse;
        // if the consecutive-suspicious count (carried in from main.go via
        // -block-counter-start) crosses -block-threshold, fallparams/x8 are
        // skipped for this URL. The final counter value + detected flag are
        // emitted in the -json-out single-entry object so main.go can read
        // them back and carry the counter forward to the next path.
        flag.Int64Var(&cfg.BlockCounterStart, "block-counter-start", 0, "Incoming consecutive-suspicious count handed off by xsscanner main.go (single-URL -u mode only; no-op in -f bulk mode)")
        flag.Int64Var(&cfg.BlockThreshold, "block-threshold", 9, "Threshold at which this run should report \"blocked\" and skip fallparams/x8 for the target URL (single-URL -u mode only)")

        flag.Usage = func() {
                printf("%sUsage:%s\n", PR_boldYellow, PR_reset)
                printf("  nice_params -u <URL>                        Single URL\n")
                printf("  nice_params -f <file>                       Bulk URLs from file\n")
                printf("  nice_params -u <URL> -w <wordlist>          Custom wordlist for x8\n")
                printf("  nice_params -f urls.txt -d results/         Save host-param.txt files to custom dir\n")
                printf("  nice_params -f urls.txt -t 10               10 concurrent workers\n")
                printf("  nice_params -u <URL> -crawl                 Use Katana crawl for fallparams\n")
                printf("  nice_params -u <URL> -r req.txt             fallparams uses -u, x8 uses -r req.txt instead of -u\n") // راهنمای جدید
                printf("  nice_params -u <URL> -cookie \"session=x\" -header \"Authorization: Bearer y\"   Auth-gated targets (forwarded to x8/fallparams)\n")
                printf("  nice_params -f urls.txt -json-out raw.json  Additionally dump RAW per-URL params as JSON\n\n")
                printf("%sOutput:%s\n", PR_boldYellow, PR_reset)
                printf("  Files are automatically named <HOST>-param.txt (e.g. asda.com-param.txt)\n\n")
                printf("%sFlags:%s\n", PR_boldYellow, PR_reset)
                flag.PrintDefaults()
        }

        flag.Parse()
        cfg.Headers = headerFlags
        var err error
        repLogger, err = reporter.NewLogger("results/raw_findings.jsonl")
        if err != nil {
                printError(fmt.Sprintf("reporter init failed: %v", err))
                os.Exit(1)
        }

        // Replace the existing logic inside main() under "if cfg.Wordlist == """ with:

        if cfg.Wordlist == "" {
                // 1. Check Environment Variable
                if envPath := os.Getenv("X8_WORDLIST_PATH"); envPath != "" {
                        cfg.Wordlist = envPath
                        fmt.Fprintf(os.Stderr, "[DEBUG] Using wordlist from env: %s\n", cfg.Wordlist)
                }

                // 2. Fallback to exe-relative
                if cfg.Wordlist == "" {
                        exePath, err := os.Executable()
                        if err == nil {
                                target := filepath.Join(filepath.Dir(exePath), "param.txt")
                                if _, err := os.Stat(target); err == nil {
                                        cfg.Wordlist = target
                                        fmt.Fprintf(os.Stderr, "[DEBUG] Using wordlist relative to binary: %s\n", cfg.Wordlist)
                                }
                        }
                }

                // 3. Fallback to CWD
                if cfg.Wordlist == "" {
                        cfg.Wordlist = "param.txt"
                        fmt.Fprintf(os.Stderr, "[DEBUG] Falling back to CWD: %s\n", cfg.Wordlist)
                }
        }

        if cfg.URL != "" && cfg.URLFile != "" {
                printError("use either -u or -f, not both")
                os.Exit(1)
        }

        if cfg.URL == "" && cfg.URLFile == "" {
                printError("specify -u <URL> or -f <file>")
                flag.Usage()
                os.Exit(1)
        }

        if cfg.ReqFile != "" {
                if cfg.URLFile != "" {
                        printError("-r (raw request file) can only be used with -u, not with -f (one request file cannot map to multiple URLs)")
                        os.Exit(1)
                }
                if _, err := os.Stat(cfg.ReqFile); err != nil {
                        printError(fmt.Sprintf("request file not found: %s", cfg.ReqFile))
                        os.Exit(1)
                }
        }

        if cfg.Threads < 1 {
                cfg.Threads = 1
        }

        if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
                printError(fmt.Sprintf("failed to create output directory: %v", err))
                os.Exit(1)
        }

        ctx, cancel := context.WithCancel(context.Background())
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
        go func() {
                <-sigCh
                if !cfg.Silent {
                        printf("\n%s[!]%s Interrupted — cleaning up…\n", PR_boldYellow, PR_reset)
                }
                cancel()
        }()

        if !cfg.KeepTemp {
                defer cleanup()
        }

        if !cfg.NoFall {
                if err := checkTool("fallparams"); err != nil {
                        printError(err.Error())
                        os.Exit(1)
                }
        }
        if !cfg.NoX8 {
                if err := checkTool("x8"); err != nil {
                        printError(err.Error())
                        os.Exit(1)
                }
        }

        if cfg.URL != "" {
                res := processURL(ctx, cfg.URL, cfg)
                if res.Err != nil {
                        printError(res.Err.Error())
                        os.Exit(1)
                }

                if len(res.X8Params) > 0 || len(res.FallParams) > 0 {
                        added, _ := writeHostParamFile(res.OutFile, res.X8Params, res.FallParams, cfg.MaxParams)
                        if !cfg.Silent {
                                printSep()
                                total := len(res.X8Params) + len(res.FallParams)
                                printSuccess(fmt.Sprintf("Found %d unique params (saved %d new to %s)", total, added, res.OutFile))
                        }
                } else if !cfg.Silent {
                        printSep()
                        printInfo("No params found")
                }

                // -json-out (single-URL mode): record this URL's RAW discoveries. The
                // <HOST>-param.txt side effect above stays exactly as it was.
                if cfg.JSONOut != "" {
                        var entries []jsonOutEntry
                        appendJSONOutEntry(&entries, res) // res.Err == nil is guaranteed above
                        if jerr := writeJSONOutFile(cfg.JSONOut, entries); jerr != nil {
                                printError(fmt.Sprintf("failed to write -json-out file %s: %v", cfg.JSONOut, jerr))
                                os.Exit(1)
                        }
                        if !cfg.Silent {
                                printSuccess(fmt.Sprintf("RAW per-URL JSON written to %s (%d URL(s))", cfg.JSONOut, len(entries)))
                        }
                }
                return
        }

        if cfg.URLFile != "" {
                if err := processURLFile(ctx, cfg); err != nil {
                        printError(err.Error())
                        os.Exit(1)
                }
        }
}
