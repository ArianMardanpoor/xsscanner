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
//
// NOTE: x8 is GONE from this tool. The old x8ParamRegex/x8FoundRegex and the
// %-suffix cleanup regex (cleanupRegex, which existed only to scrub x8's
// output format) were removed together with runX8/extractX8Params. cleanParam
// keeps the trim + payload% normalization because fallparams lines can still
// carry stray whitespace after extraction.

var (
	reNumeric = regexp.MustCompile(`^\d+$`)
	reCSSUnit = regexp.MustCompile(`\d+(px|em|rem|vh|vw|ms|fr)$`)
)

// ─── Config & State ────────────────────────────────────────────────────────────

type Config struct {
	URL       string
	URLFile   string
	OutDir    string // Directory to save HOST-param.txt files
	Silent    bool
	KeepTemp  bool
	Threads   int
	Timeout   int
	NoFall    bool
	MaxParams int
	JSONOut   string // Optional: additionally write RAW per-URL discoveries as a JSON array (-json-out; both -u and -f modes)

	// fallparams knobs. -crawl defaults to FALSE: by default nice_params asks
	// fallparams to analyze only the exact URL given (its params, forms, JS on
	// that single page) without crawling to other pages. This keeps the
	// discovered parameter list tightly scoped to what's actually reachable on
	// that page, instead of pulling in hundreds of unrelated JS identifiers and
	// strings from every crawled page (which crawl mode does — see the
	// webapp.nozbe.com test where -crawl returned 300+ candidates vs a handful
	// of real form/query params without it). Pass -crawl=true explicitly for
	// broader (but much noisier) discovery.
	// Depth/duration are exposed so xsscanner can forward its top-level
	// -fallparams-depth / -fallparams-crawl-duration flags (same pattern
	// as -block-threshold).
	Crawl         bool // default false (scoped to the given URL only); true enables fallparams' -crawl flag for broader discovery
	CrawlDepth    int  // forwarded as fallparams -d (default 2 = fallparams' own default, passed explicitly)
	CrawlDuration int  // forwarded as fallparams -ct seconds (default 120 = 2 minutes; 0 = omit the flag and use fallparams' default)

	Cookie  string   // -cookie: raw Cookie header value forwarded to fallparams' requests
	Headers []string // -header entries forwarded to fallparams' requests

	// WAF/block guard (only meaningful/used in -u single-URL mode; no-op in
	// -f bulk mode — the per-path orchestration lives in main.go which calls
	// nice_params once per path with -u).
	BlockCounterStart int64 // incoming consecutive-suspicious count from main.go
	BlockThreshold    int64 // threshold at which this run should report "blocked" and skip fallparams
}

// headerList implements flag.Value for the repeatable -header flag.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// ─── fallparams custom-header support probe ──────────────────────────────────
//
// fallparams is invoked with -u -silent -crawl -d -ct today. We never guess a
// flag name: if the installed fallparams does not advertise a custom-header
// flag (-H/-header/--header) in its help output, a one-time warning is logged
// and its invocation stays exactly as before (auth-gated pages may then be
// under-discovered by fallparams specifically).

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

// writeHostParamFile merges this run's fallparams discoveries into the host's
// <HOST>-param.txt file. With x8 removed, fallParams is the ONLY input; the
// old x8Params argument (and its higher merge priority) is gone.
func writeHostParamFile(outFile string, fallParams []string, maxParams int) (int, error) {
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

	// 2. Then fallparams
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

	if fallDropped > 0 {
		printWarning(fmt.Sprintf("Max params (%d) reached for %s. Dropped %d fallparams.", maxParams, filepath.Base(outFile), fallDropped))
	}

	if len(final) == len(existing) {
		return 0, nil
	}

	host := strings.TrimSuffix(filepath.Base(outFile), "-param.txt")
	for _, p := range final[len(existing):] {
		repLogger.Log(reporter.NewFinding(
			host, outFile, p, "fallparams", "MEDIUM", "parameter_discovered",
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
// (res.FallParams — the only source since x8 was removed), BEFORE
// writeHostParamFile()'s host-level merge/cap logic touches it. Each URL's
// list is cleaned/deduped with the same cleanParam()/isValidParam() rules used
// everywhere else in this file. The existing <HOST>-param.txt mechanism keeps
// running alongside, unchanged.

type jsonOutEntry struct {
	URL    string   `json:"url"`
	Params []string `json:"params"`
	// WAF/block guard (single-URL mode only): the final consecutive-suspicious
	// counter value after this run's preflight check (and, if the threshold
	// was crossed, fallparams was skipped), and whether the threshold
	// was crossed during this run. main.go reads these to carry the counter
	// forward to the next path's phase/test call.
	BlockCounterEnd int64 `json:"blockCounterEnd"`
	BlockDetected   bool  `json:"blockDetected"`
}

// rawPerURLParams dedups a URL's raw fallparams discoveries under the standard
// cleaning rules (the old x8Params-first priority is gone — there is only one
// source now).
func rawPerURLParams(fallParams []string) []string {
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
		URL:             res.URL,
		Params:          rawPerURLParams(res.FallParams),
		BlockCounterEnd: res.BlockCounterEnd,
		BlockDetected:   res.BlockDetected,
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

// ─── fallparams — the ONLY param-discovery engine ─────────────────────────────

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

// runFallparams discovers parameters for rawURL via fallparams.
//
// x8 (and the whole combined-wordlist flow: base param.txt wordlist,
// buildCombinedWordlist, X8_WORDLIST_PATH, the -w/-r/-no-x8 flags) was removed
// completely — fallparams is now the only server-side param-discovery engine,
// so its output is NOT a wordlist to feed anywhere: the returned candidates
// ARE the discovered parameters for this URL.
//
// Flags passed (with the reasoning, per the redesign):
//   - -silent: ALWAYS passed. fallparams v1.0.12 panics in ShowBanner
//     (index out of range) when the banner is printed in this environment;
//     -silent skips the banner and the tool works.
//   - -crawl: OFF by default now. The default behavior scopes fallparams'
//     analysis to exactly the given URL (its own params/forms/JS), avoiding
//     the large volume of unrelated JS-identifier noise crawl mode produces
//     (e.g. 300+ candidates on a single target vs a handful of real
//     params). Pass -crawl=true (cfg.Crawl) for broader multi-page discovery
//     when that's explicitly wanted.
//   - -d <CrawlDepth>: explicit crawl depth, default 2 (fallparams' own
//     default — passed explicitly so it is visible/overridable from the CLI).
//   - -ct <CrawlDuration>s: crawl duration cap, default 120s (2 minutes).
//     fallparams is lighter than the old x8 flow, but its crawl can still run
//     long; two minutes bounds the per-URL phase cost while leaving enough
//     time for a depth-2 crawl. 0 disables the flag (fallparams default).
//   - -o <runDir>/parameters.txt: output file, passed EXPLICITLY. fallparams
//     documents -o/-output in its -h ("File to write output to", default
//     "parameters.txt"). This is load-bearing: fallparams v1.0.12's runner
//     (funcs/run/runner.go) only appends to the output file when
//     OutputFile != "parameters.txt" || !SilentMode — with -silent and the
//     DEFAULT filename it prints params to stdout only and NEVER writes the
//     file. The old code read a hardcoded runDir/parameters.txt without
//     passing -o, so in -silent mode (always passed here) the file never
//     existed and runFallparams silently returned zero params for EVERY
//     target. Passing -o explicitly pins the exact path we then read, and
//     makes the file channel work even in -silent mode.
//
// Output capture (the Bug 1 fix): fallparams' output channel depends on its
// flags/version. Instead of assuming one channel, BOTH are captured and
// merged (deduped, first-seen order):
//   1. the -o output file (read from the exact path we passed);
//   2. fallparams' combined stdout+stderr (CombinedOutput) — one candidate
//      per line, same line-oriented format as the file channel.
// If BOTH channels are empty the function logs a LOUD warning (even in
// silent mode, via stderr) so "the tool produced nothing" is always
// distinguishable in the logs from "the target has no parameters".
//
// Global auth headers (-cookie/-header) are forwarded IF the installed
// fallparams advertises a custom-header flag; otherwise a one-time warning and
// no change to the invocation (never guess a flag name, never fail the run).
func runFallparams(ctx context.Context, rawURL string, silent bool, crawl bool, crawlDepth, crawlDuration int, authCookie string, authHeaders []string) ([]string, error) {
	if err := checkTool("fallparams"); err != nil {
		return nil, err
	}

	if !silent {
		printStep(fmt.Sprintf("fallparams → %s (crawl=%t, depth=%d, duration=%ds)", rawURL, crawl, crawlDepth, crawlDuration))
	}

	runDir, err := os.MkdirTemp("", "fall_isolate_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory for fallparams: %v", err)
	}
	registerTemp(runDir)

	// The exact output path we tell fallparams to write (-o). Never assume a
	// hardcoded default filename — we pass the flag and read this same path.
	fallOutPath := filepath.Join(runDir, "parameters.txt")

	// -silent: bypasses the ShowBanner panic in fallparams v1.0.12
	args := []string{"-u", rawURL, "-silent", "-o", fallOutPath}
	if crawl {
		// Always-on in production: crawl is the discovery engine.
		args = append(args, "-crawl")
	}
	if crawlDepth > 0 {
		args = append(args, "-d", strconv.Itoa(crawlDepth))
	}
	if crawlDuration > 0 {
		args = append(args, "-ct", strconv.Itoa(crawlDuration))
	}

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

	out, runErr := cmd.CombinedOutput()
	if runErr != nil && !silent {
		printWarning(fmt.Sprintf("fallparams exited with error: %v\n%s", runErr, string(out)))
	}

	// ── Channel 1: the -o output file (authoritative when present) ──────────
	var fileCandidates []string
	fileContent, fileErr := os.ReadFile(fallOutPath)
	if fileErr == nil {
		fileCandidates = extractCandidates(string(fileContent))
	} else if !os.IsNotExist(fileErr) {
		// Exists but unreadable is a real I/O problem worth surfacing.
		if !silent {
			printWarning(fmt.Sprintf("fallparams: output file %s unreadable: %v", fallOutPath, fileErr))
		}
	}

	// ── Channel 2: fallparams' stdout+stderr (CombinedOutput) ────────────────
	// With -silent, fallparams prints one parameter per line to stdout (its
	// documented -silent behavior). The same line-oriented extraction applies.
	stdoutCandidates := extractCandidates(string(out))

	// Union both channels, deduped, first-seen order (file channel first —
	// it is the channel we explicitly requested via -o).
	candidates := mergeCandidateLists(fileCandidates, stdoutCandidates)

	// ── Loud no-output warning ────────────────────────────────────────────────
	// A silent "no params found" is indistinguishable from "we parsed the
	// tool's output wrong". If BOTH channels yielded nothing AND the file was
	// never written, make the distinction loud — even in otherwise-silent
	// runs (stderr is the machine-friendly channel nice_params reserves for
	// exactly this kind of operational diagnostic).
	if len(candidates) == 0 {
		w := fmt.Sprintf("[nice_params] WARNING: fallparams produced NO output for %s — neither the -o file (%s; exists=%t) nor stdout had any parameter lines", rawURL, fallOutPath, fileErr == nil)
		if runErr != nil {
			w += fmt.Sprintf("; fallparams exited with error: %v", runErr)
		}
		if !silent {
			printWarning(w)
		} else {
			logErrorMsg(w)
		}
	}

	if !silent {
		if len(candidates) > 0 {
			printSuccess(fmt.Sprintf("fallparams: %d parameter(s) discovered (file channel: %d, stdout channel: %d)", len(candidates), len(fileCandidates), len(stdoutCandidates)))
		} else {
			printInfo("fallparams: no parameters found")
		}
	}
	return candidates, nil
}

// extractCandidates parses one-candidate-per-line text (a fallparams output
// channel — file or stdout) into a cleaned, deduped candidate list. This is
// the same per-line cleaning the old code applied to file contents only; it
// now backs BOTH channels.
func extractCandidates(content string) []string {
	var candidates []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		w := strings.TrimSpace(sc.Text())
		w = cleanParam(w)
		if isCandidateWord(w) && !seen[w] {
			seen[w] = true
			candidates = append(candidates, w)
		}
	}
	return candidates
}

// mergeCandidateLists unions two candidate lists, deduped, first-seen order.
func mergeCandidateLists(a, b []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range [][]string{a, b} {
		for _, w := range list {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

// ─── URL Processor ─────────────────────────────────────────────────────────────

type Result struct {
	URL        string
	OutFile    string
	FallParams []string
	Err        error

	// WAF/block guard outputs (single-URL mode only; always populated by
	// processURL so appendJSONOutEntry can record them into the -json-out
	// single-entry object).
	BlockCounterEnd int64
	BlockDetected   bool
}

// preflightBlockCheck issues ONE lightweight curl-based GET to rawURL and
// classifies the response via blockguard.IsSuspiciousResponse. Maintains a
// local counter starting at cfg.BlockCounterStart:
//   - if suspicious → counter++
//   - if not suspicious → counter = 0
//
// If counter >= cfg.BlockThreshold at any point, returns blockDetected=true
// so processURL can SKIP calling fallparams for this URL (no point burning
// more requests against an already-blocking host). Mirrors the
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

// processURL discovers parameters for one URL via fallparams only. There is no
// x8 stage anymore and no wordlist merging — fallparams' output IS the result.
// The WAF/block preflight check is unchanged (it is independent of which
// discovery engine runs after it).
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
	// and SKIP fallparams entirely for this URL (no point burning more
	// requests against an already-blocking host). res.FallParams stays
	// empty in that case.
	counterEnd, blocked := preflightBlockCheck(rawURL, cfg.Cookie, cfg.Headers, cfg.BlockCounterStart, cfg.BlockThreshold)
	res.BlockCounterEnd = counterEnd
	res.BlockDetected = blocked
	if blocked {
		const msg = "[nice_params] WAF/BLOCK DETECTED (preflight consecutive-suspicious=%d, threshold=%d) — skipping fallparams for %s"
		if !cfg.Silent {
			printWarning(fmt.Sprintf(msg, counterEnd, cfg.BlockThreshold, rawURL))
		} else {
			logErrorMsg(fmt.Sprintf(msg, counterEnd, cfg.BlockThreshold, rawURL))
		}
		return res
	}

	if !cfg.NoFall {
		params, err := runFallparams(toolCtx, rawURL, cfg.Silent, cfg.Crawl, cfg.CrawlDepth, cfg.CrawlDuration, cfg.Cookie, cfg.Headers)
		if err != nil {
			res.Err = fmt.Errorf("fallparams error for %s: %v", rawURL, err)
			if !cfg.Silent {
				printError(res.Err.Error())
			} else {
				logErrorMsg(res.Err.Error())
			}
		} else {
			res.FallParams = params
		}
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

		if len(res.FallParams) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.FallParams, cfg.MaxParams)
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
	flag.BoolVar(&cfg.Silent, "silent", false, "No terminal output (machine-friendly)")
	flag.BoolVar(&cfg.KeepTemp, "keep-temp", false, "Keep temporary files after exit")
	flag.IntVar(&cfg.Threads, "t", 5, "Concurrent workers (for -f mode)")
	flag.IntVar(&cfg.Timeout, "timeout", 300, "Per-tool timeout in seconds")
	flag.BoolVar(&cfg.NoFall, "no-fall", false, "Skip fallparams (debug: the only discovery engine — no params will be found)")
	flag.IntVar(&cfg.MaxParams, "max-params", 200, "Maximum number of parameters to keep per host")
flag.BoolVar(&cfg.Crawl, "crawl", false, "Pass -crawl to fallparams (default FALSE — scans only the given URL itself without crawling linked pages; pass -crawl=true to enable crawl mode for broader-but-noisier discovery)")
	flag.IntVar(&cfg.CrawlDepth, "fallparams-depth", 2, "Crawl depth forwarded to fallparams as -d (fallparams' own default, passed explicitly so it is overridable)")
	flag.IntVar(&cfg.CrawlDuration, "fallparams-crawl-duration", 120, "Crawl duration cap in seconds forwarded to fallparams as -ct (bounds the per-URL phase cost; 0 = omit and use fallparams' default)")
	flag.StringVar(&cfg.JSONOut, "json-out", "", "Additionally write RAW per-URL discoveries as a JSON array [{\"url\":…,\"params\":[…]}] (both -u and -f modes; unaffected by the <HOST>-param.txt merge/cap)")
	flag.StringVar(&cfg.Cookie, "cookie", "", "Raw Cookie header value forwarded to fallparams' live requests, e.g. \"session=abc123; other=val\"")
	var headerFlags headerList
	flag.Var(&headerFlags, "header", "Extra HTTP header forwarded to fallparams' live requests, format \"Name: Value\" (repeatable)")

	// WAF/block guard (only meaningful/used in -u single-URL mode; no-op
	// in -f bulk mode — the per-path orchestration lives in main.go which
	// calls nice_params once per path with -u). A single preflight GET to
	// the target URL is classified via blockguard.IsSuspiciousResponse;
	// if the consecutive-suspicious count (carried in from main.go via
	// -block-counter-start) crosses -block-threshold, fallparams is
	// skipped for this URL. The final counter value + detected flag are
	// emitted in the -json-out single-entry object so main.go can read
	// them back and carry the counter forward to the next path.
	flag.Int64Var(&cfg.BlockCounterStart, "block-counter-start", 0, "Incoming consecutive-suspicious count handed off by xsscanner main.go (single-URL -u mode only; no-op in -f bulk mode)")
	flag.Int64Var(&cfg.BlockThreshold, "block-threshold", 9, "Threshold at which this run should report \"blocked\" and skip fallparams for the target URL (single-URL -u mode only)")

	flag.Usage = func() {
		printf("%sUsage:%s\n", PR_boldYellow, PR_reset)
		printf("  nice_params -u <URL>                        Single URL\n")
		printf("  nice_params -f <file>                       Bulk URLs from file\n")
		printf("  nice_params -f urls.txt -d results/         Save host-param.txt files to custom dir\n")
		printf("  nice_params -f urls.txt -t 10               10 concurrent workers\n")
		printf("  nice_params -u <URL> -fallparams-depth 3          fallparams crawl depth (-d)\n")
		printf("  nice_params -u <URL> -fallparams-crawl-duration 60 fallparams crawl cap in seconds (-ct)\n")
		printf("  nice_params -u <URL> -cookie \"session=x\" -header \"Authorization: Bearer y\"   Auth-gated targets (forwarded to fallparams)\n")
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

	if cfg.URL != "" && cfg.URLFile != "" {
		printError("use either -u or -f, not both")
		os.Exit(1)
	}

	if cfg.URL == "" && cfg.URLFile == "" {
		printError("specify -u <URL> or -f <file>")
		flag.Usage()
		os.Exit(1)
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

	if cfg.URL != "" {
		res := processURL(ctx, cfg.URL, cfg)
		if res.Err != nil {
			printError(res.Err.Error())
			os.Exit(1)
		}

		if len(res.FallParams) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.FallParams, cfg.MaxParams)
			if !cfg.Silent {
				printSep()
				printSuccess(fmt.Sprintf("Found %d unique params (saved %d new to %s)", len(res.FallParams), added, res.OutFile))
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