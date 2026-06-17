package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

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
)

// ─── Config & State ────────────────────────────────────────────────────────────

type Config struct {
	URL      string
	URLFile  string
	OutDir   string // Directory to save HOST-param.txt files
	Wordlist string
	Silent   bool
	KeepTemp bool
	Threads  int
	Timeout  int
	NoX8     bool
	NoFall   bool
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
	// In a real application, you might write to a log file here.
	// For this example, we'll just print to stderr.
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
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

var fileMu sync.Mutex

func writeHostParamFile(outFile string, newParams []string) (int, error) {
	fileMu.Lock()
	defer fileMu.Unlock()

	existing, err := readParams(outFile)
	if err != nil && !os.IsNotExist(err) {
		// Log error if file exists but cannot be read, but continue if file doesn't exist
		logErrorMsg(fmt.Sprintf("failed to read existing params from %s: %v", outFile, err))
	}

	seen := make(map[string]bool, len(existing))
	for _, p := range existing {
		seen[p] = true
	}

	var fresh []string
	for _, p := range newParams {
		p = cleanParam(p)
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && !seen[p] {
			seen[p] = true
			fresh = append(fresh, p)
		}
	}

	if len(fresh) == 0 {
		return 0, nil
	}

	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	for _, p := range fresh {
		fmt.Fprintln(f, p)
	}
	return len(fresh), nil
}

// ─── Tool Check ────────────────────────────────────────────────────────────────

func checkTool(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("%s not found in PATH. Please install it to use this feature.", toolName)
	}
	return nil
}

// ─── fallparams ────────────────────────────────────────────────────────────────

func runFallparams(ctx context.Context, rawURL string, silent bool) ([]string, error) {
	if err := checkTool("fallparams"); err != nil {
		return nil, err
	}

	if !silent {
		printStep(fmt.Sprintf("fallparams → %s", rawURL))
	}

	runDir, err := os.MkdirTemp("", "fall_isolate_*")
	if err != nil {
		logErrorMsg(fmt.Sprintf("failed to create temp directory for fallparams: %v", err))
		return nil, fmt.Errorf("failed to create temp directory for fallparams: %v", err)
	}
	registerTemp(runDir)

	cmd := exec.CommandContext(ctx, "fallparams", "-u", rawURL)
	cmd.Dir = runDir // Always set Dir to runDir for isolation

	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		msg := fmt.Sprintf("fallparams returned non-zero: %v\nOutput: %s", runErr, string(out))
		if !silent {
			printWarning(msg)
		} else {
			logErrorMsg(msg)
		}
		// Continue processing even if fallparams fails, it might still produce output
	}

	var params []string
	fallOutPath := filepath.Join(runDir, "parameters.txt")

	if _, statErr := os.Stat(fallOutPath); statErr == nil {
		readParamsResult, readParamsErr := readParams(fallOutPath)
		if readParamsErr != nil {
			logErrorMsg(fmt.Sprintf("failed to read fallparams output file %s: %v", fallOutPath, readParamsErr))
		} else {
			params = readParamsResult
		}
		os.Remove(fallOutPath)
	}

	if !silent {
		if len(params) > 0 {
			printSuccess(fmt.Sprintf("fallparams: %d params found", len(params)))
		} else {
			printInfo("fallparams: no params found")
		}
	}
	return params, nil
}

// ─── x8 ───────────────────────────────────────────────────────────────────────

func extractX8Params(content string) []string {
	seen := make(map[string]bool)
	var out []string

	addParam := func(p string) {
		p = cleanParam(p)
		if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") && !seen[p] {
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

		// This part seems to be for raw params in output, but might be too broad.
		// Consider if this is intended to capture params not matched by regexes.
		if !strings.ContainsAny(line, " [:]") {
			addParam(line)
		}
	}
	return out
}

func runX8(ctx context.Context, rawURL, wordlist string, silent bool) ([]string, error) {
	if err := checkTool("x8"); err != nil {
		return nil, err
	}

	if !silent {
		printStep(fmt.Sprintf("x8 → %s", rawURL))
	}

	if _, err := os.Stat(wordlist); os.IsNotExist(err) {
		return nil, fmt.Errorf("wordlist not found: %s", wordlist)
	}

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("x8_%d_%d.txt", os.Getpid(), time.Now().UnixNano()))
	registerTemp(tmpFile)

	args := []string{"-u", rawURL, "-w", wordlist, "-o", tmpFile}
	cmd := exec.CommandContext(ctx, "x8", args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := fmt.Sprintf("x8 exited non-zero (%v). Output: %s", err, string(out))
		if !silent {
			printWarning(msg)
		} else {
			logErrorMsg(msg)
		}
		// Continue processing even if x8 fails, it might still produce output
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
	URL     string
	OutFile string
	Params  []string
	Err     error
}

func processURL(ctx context.Context, rawURL string, cfg *Config) Result {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return Result{URL: rawURL, Err: fmt.Errorf("invalid URL (must start with http:// or https://)")}
	}

	outFile := getHostFilename(rawURL, cfg.OutDir)
	toolCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	var allParams []string
	seen := make(map[string]bool)

	add := func(params []string) {
		for _, p := range params {
			if !seen[p] {
				seen[p] = true
				allParams = append(allParams, p)
			}
		}
	}

	var fallErr, x8Err error

	if !cfg.NoFall {
		params, err := runFallparams(toolCtx, rawURL, cfg.Silent)
		if err != nil {
			fallErr = fmt.Errorf("fallparams error for %s: %v", rawURL, err)
			if !cfg.Silent {
				printError(fallErr.Error())
			} else {
				logErrorMsg(fallErr.Error())
			}
		} else {
			add(params)
		}
	}

	if !cfg.NoX8 {
		params, err := runX8(toolCtx, rawURL, cfg.Wordlist, cfg.Silent)
		if err != nil {
			x8Err = fmt.Errorf("x8 error for %s: %v", rawURL, err)
			if !cfg.Silent {
				printError(x8Err.Error())
			} else {
				logErrorMsg(x8Err.Error())
			}
		} else {
			add(params)
		}
	}

	// Aggregate errors if both tools failed
	var overallErr error
	if fallErr != nil && x8Err != nil {
		overallErr = fmt.Errorf("%v; %v", fallErr, x8Err)
	} else if fallErr != nil {
		overallErr = fallErr
	} else if x8Err != nil {
		overallErr = x8Err
	}

	return Result{URL: rawURL, OutFile: outFile, Params: allParams, Err: overallErr}
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
			u = "https://" + u // Default to https if not specified
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

		if len(res.Params) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.Params)
			atomic.AddInt64(&totalFound, int64(added))
			if !cfg.Silent {
				if added > 0 {
					printSuccess(fmt.Sprintf("%d new unique params saved to %s", added, res.OutFile))
				} else {
					printInfo(fmt.Sprintf("Params found, but already existed in %s", res.OutFile))
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
	flag.StringVar(&cfg.Wordlist, "w", "", "Wordlist for x8 (default: ~/wordlist/param.txt)")
	flag.BoolVar(&cfg.Silent, "silent", false, "No terminal output (machine-friendly)")
	flag.BoolVar(&cfg.KeepTemp, "keep-temp", false, "Keep temporary files after exit")
	flag.IntVar(&cfg.Threads, "t", 5, "Concurrent workers (for -f mode)")
	flag.IntVar(&cfg.Timeout, "timeout", 300, "Per-tool timeout in seconds")
	flag.BoolVar(&cfg.NoX8, "no-x8", false, "Skip x8 (fallparams only)")
	flag.BoolVar(&cfg.NoFall, "no-fall", false, "Skip fallparams (x8 only)")

	flag.Usage = func() {
		printf("%sUsage:%s\n", PR_boldYellow, PR_reset)
		printf("  nice_params -u <URL>                        Single URL\n")
		printf("  nice_params -f <file>                       Bulk URLs from file\n")
		printf("  nice_params -u <URL> -w <wordlist>          Custom wordlist for x8\n")
		printf("  nice_params -f urls.txt -d results/         Save host-param.txt files to custom dir\n")
		printf("  nice_params -f urls.txt -t 10               10 concurrent workers\n\n")
		printf("%sOutput:%s\n", PR_boldYellow, PR_reset)
		printf("  Files are automatically named <HOST>-param.txt (e.g. asda.com-param.txt)\n\n")
		printf("%sFlags:%s\n", PR_boldYellow, PR_reset)
		flag.PrintDefaults()
	}

	flag.Parse()

	if cfg.Wordlist == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			printError("cannot determine home directory")
			os.Exit(1)
		}
		cfg.Wordlist = filepath.Join(home, "wordlist", "param.txt")
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

	// Create output directory if it doesn't exist
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

	// Check for required tools only if they are not skipped
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

		if len(res.Params) > 0 {
			added, _ := writeHostParamFile(res.OutFile, res.Params)
			if !cfg.Silent {
				printSep()
				printSuccess(fmt.Sprintf("Found %d unique params (saved %d new to %s)", len(res.Params), added, res.OutFile))
				printSuccess(fmt.Sprintf("Params: %s", strings.Join(res.Params, ", ")))
			}
		} else if !cfg.Silent {
			printSep()
			printInfo("No params found")
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
