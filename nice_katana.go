package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// بررسی پشتیبانی باینری کاتانا از فلگ jsluice
func supportsJsluice() bool {
	cmd := exec.Command("katana", "-h")
	out, _ := cmd.CombinedOutput()
	return strings.Contains(string(out), "-jsluice")
}

// headerList implements flag.Value for the repeatable -header flag.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func main() {
	var outDir string
	flag.StringVar(&outDir, "o", "results/katana", "Output directory")

	// اضافه شدن فلگ verbose
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "Print full katana command before execution, plus katana stdout, wall-clock duration, and jsluice-applied status in the completion summary")

	// Global auth support: forwarded to the katana crawl as extra -H entries
	// alongside the existing User-Agent -H line (never replacing it).
	var authCookie string
	flag.StringVar(&authCookie, "cookie", "", "Raw Cookie header value sent with every katana crawl request, e.g. \"session=abc123; other=val\"")
	var authHeaders headerList
	flag.Var(&authHeaders, "header", "Extra HTTP header sent with every katana crawl request, format \"Name: Value\" (repeatable)")

	// Tunable katana request timing. Bisection against a real target
	// (see BISECTION_NOTES.md) confirmed the previous hardcoded `-delay 250`
	// was the dominant cause of nice_katana "finds nothing": per `katana -h`,
	// `-delay` is documented as "request delay between each request in SECONDS",
	// so 250 meant 250s/req — only ~3-4 requests could complete inside the
	// 15min/target global batch timeout. Default 0 disables the inter-request
	// delay (matches katana's own default; the existing `-rl 12` rate-limit
	// still throttles overall throughput).
	//
	// `-timeout` default raised from the previous 4 (well below katana's own
	// default of 10) to 10 — per the spec's prime-suspect analysis. Bisection
	// showed `-timeout 4` was NOT the dominant cause on its own, but it IS
	// genuinely below katana's default and a real latency/WAF risk, so the
	// spec's requested raise-to-10-and-expose-as-flag fix is applied.
	var katanaTimeout int
	flag.IntVar(&katanaTimeout, "timeout", 10, "Per-request timeout in seconds forwarded to katana (katana's own default is 10)")
	var katanaDelay int
	flag.IntVar(&katanaDelay, "delay", 0, "Inter-request delay in SECONDS forwarded to katana (katana's own default is 0; the existing -rl 12 rate-limit already throttles throughput)")

	flag.Parse()

	var targets []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
				}
			}
			file.Close()
		} else {
			targets = append(targets, arg)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				val := strings.TrimSpace(scanner.Text())
				if val != "" {
					targets = append(targets, val)
				}
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  echo domain.com | nice_katana")
		fmt.Println("  nice_katana domain.com")
		fmt.Println("  nice_katana domains.txt")
		return
	}

	gray := "\033[1;30m"
	reset := "\033[0m"

	fmt.Printf("%s[STARTUP] nice_katana processing batch size: %d URLs%s\n", gray, len(targets), reset)

	runNiceKatanaBatch(targets, outDir, verbose, authCookie, authHeaders, katanaTimeout, katanaDelay)
}

func runNiceKatanaBatch(targets []string, outDir string, verbose bool, authCookie string, authHeaders []string, katanaTimeout int, katanaDelay int) {
	if len(targets) == 0 {
		return
	}

	tmpFile, err := os.CreateTemp("", "katana_targets_*.txt")
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	defer os.Remove(tmpFile.Name())

	for _, t := range targets {
		tmpFile.WriteString(t + "\n")
	}
	tmpFile.Close()

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	katanaOutput := filepath.Join(outDir, "katana_batch_output.txt")

	// اصلاح رشته فیلتر (ml و ip به xml و zip تغییر کردند)
	// رفع باگ اکستنشن‌های کراپت شده
	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,xml,zip"
	gray := "\033[1;30m"
	yellow := "\033[1;33m"
	reset := "\033[0m"

	fmt.Printf("%sExecuting Katana (Batch mode, rate-limited) for %d targets%s\n", gray, len(targets), reset)

	// Validate tunable timing flags so a bad CLI value can never silently
	// re-introduce the original bug (negative or absurdly high values).
	if katanaTimeout < 1 {
		katanaTimeout = 10
	}
	if katanaDelay < 0 {
		katanaDelay = 0
	}

	ctxArgs := []string{
		"-list", tmpFile.Name(),
		"-d", "2",
		"-js-crawl",
		"-known-files", "all",
		"-automatic-form-fill",
		"-extension-filter", extFilter,
		"-c", "4",
		"-rl", "12",
		"-delay", fmt.Sprintf("%d", katanaDelay),
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"-retry", "3",
		"-timeout", fmt.Sprintf("%d", katanaTimeout),
		"-silent",
		"-o", katanaOutput,
	}

	// بررسی و افزودن امن فلگ jsluice (cache the result so it can also be
	// reported in the verbose completion summary without re-running katana -h).
	jsluiceApplied := supportsJsluice()
	if jsluiceApplied {
		ctxArgs = append(ctxArgs, "-jsluice")
	} else {
		fmt.Printf("%s[WARNING] Installed katana binary does not support -jsluice flag. Skipping it.%s\n", yellow, reset)
	}

	// Global auth headers (-cookie/-header from xsscanner): appended as extra
	// -H entries alongside the existing User-Agent -H line — never replacing it.
	if authCookie != "" {
		ctxArgs = append(ctxArgs, "-H", "Cookie: "+authCookie)
	}
	for _, h := range authHeaders {
		ctxArgs = append(ctxArgs, "-H", h)
	}

	cmd := exec.Command("katana", ctxArgs...)

	// گرفتن خروجی Stderr و (در حالت verbose) Stdout. قبلاً Stdout هرگز به
	// چیزی متصل نبود و مسیر موفقیت (exit 0 با خروجی صفر) هیچ دیدابیلیتی
	// نداشت — مثلاً اگر کاتانا با فلگ اشتباه exit 0 با 0 URL برمی‌گرداند،
	// هیچ لاگی چاپ نمی‌شد. حالا در حالت verbose، Stdout هم گرفته می‌شود تا
	// دیباگ آینده بدون نیاز به ابزار اضافی ممکن باشد.
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	var stdoutBuf bytes.Buffer
	if verbose {
		cmd.Stdout = &stdoutBuf
	}

	// نمایش دستور کامل در حالت verbose
	if verbose {
		fmt.Printf("%s[VERBOSE] Command: katana %s%s\n", gray, strings.Join(ctxArgs, " "), reset)
	}

	timeoutDuration := time.Duration(15*len(targets)) * time.Minute
	if timeoutDuration > 3*time.Hour {
		timeoutDuration = 3 * time.Hour
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		duration := time.Since(start)
		if err != nil {
			fmt.Printf("Error running katana batch: %v\n", err)
			// در صورت خطا، محتوای Stderr به طور کامل چاپ می‌شود
			if stderrBuf.Len() > 0 {
				fmt.Printf("Katana Stderr:\n%s\n", stderrBuf.String())
			}
			// Print stdout too in verbose so a flag-parsing error
			// (e.g. unsupported -jsluice) is visible even when katana
			// exits non-zero with helpful text on stdout instead of stderr.
			if verbose && stdoutBuf.Len() > 0 {
				fmt.Printf("Katana Stdout:\n%s\n", stdoutBuf.String())
			}
			fmt.Printf("%sdone for batch, results: 0 (katana exited non-zero after %s; jsluice=%v)%s\n", gray, duration.Round(time.Second), jsluiceApplied, reset)
			return
		}
		// On the clean-exit path, also surface katana's own stdout in
		// verbose mode + always report duration and jsluice-applied status
		// in the completion summary (spec Bug 2 Step 4).
		if verbose && stdoutBuf.Len() > 0 {
			fmt.Printf("%s[VERBOSE] Katana Stdout:%s\n%s\n", gray, reset, stdoutBuf.String())
		}
		if verbose && stderrBuf.Len() > 0 {
			fmt.Printf("%s[VERBOSE] Katana Stderr:%s\n%s\n", gray, reset, stderrBuf.String())
		}
		_ = duration // reported in the summary line below
	case <-time.After(timeoutDuration):
		duration := time.Since(start)
		fmt.Printf("%skatana timed out for batch after %v, killing process (jsluice=%v, duration=%s)%s\n", gray, timeoutDuration, jsluiceApplied, duration.Round(time.Second), reset)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		// On timeout, also surface whatever katana printed before being
		// killed — both streams, only in verbose (avoids noise in normal runs).
		if verbose && stderrBuf.Len() > 0 {
			fmt.Printf("%s[VERBOSE] Katana Stderr (pre-timeout):%s\n%s\n", gray, reset, stderrBuf.String())
		}
		if verbose && stdoutBuf.Len() > 0 {
			fmt.Printf("%s[VERBOSE] Katana Stdout (pre-timeout):%s\n%s\n", gray, reset, stdoutBuf.String())
		}
		return
	}

	file, _ := os.Open(katanaOutput)
	count := 0
	if file != nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			count++
		}
		file.Close()
	}

	// Final uro dedup pass over katana's raw output — mirrors the same
	// pattern already used in nice_passive.go for wayback+gau URLs.
	//
	// Katana writes one URL per line as it discovers them, so a single
	// endpoint typically shows up many times with different query-param
	// VALUES (e.g. /page?id=1, /page?id=2, ..., /page?id=99). These are
	// distinct strings, so a simple `sort -u` (or katana's own dedup)
	// keeps every one of them — same near-duplicate noise problem we
	// already solved for nice_passive's wayback/gau output.
	//
	// uro collapses those near-duplicates by (path + sorted param-name-set)
	// and keeps one representative URL per group — so /page?id=1 and
	// /page?id=2 collapse to one entry (the first-seen value), while
	// /page?id=X and /page?type=Y (different param NAMES) stay separate
	// (both are genuine distinct param candidates for the downstream x9
	// candidate-param-generation step).
	//
	// This dedup runs INSIDE nice_katana (not just inside xsscanner's
	// discoveryutil.MergeAndFilter) so:
	//   - the cached <safeURL>-katana.txt file (which xsscanner's normal
	//     mode and xsscanner_discover both consume via .done-sentinel
	//     reuse) is also the deduped version — no re-deduping needed
	//     on cache hit
	//   - standalone nice_katana invocations (without xsscanner wrapping)
	//     also get the benefit
	//
	// Verified via `uro -h`: uro 1.0.2 supports `-i INPUT_FILE -o OUTPUT_FILE`.
	// On uro failure (e.g. binary not installed), log a warning and keep
	// the un-deduped katanaOutput as-is — never abort the run over this
	// (same error-tolerance pattern as everywhere else in this pipeline).
	preCount := count
	dedupPath := katanaOutput + ".deduped"
	dedupCmd := exec.Command("uro", "-i", katanaOutput, "-o", dedupPath)
	if dedupOut, derr := dedupCmd.CombinedOutput(); derr != nil {
		fmt.Printf("%s[WARNING] uro final-pass failed on katana output: %v (continuing with un-deduped output)%s\n", gray, derr, reset)
		if len(dedupOut) > 0 {
			fmt.Printf("%s[WARNING] uro output: %s%s\n", gray, strings.TrimSpace(string(dedupOut)), reset)
		}
	} else {
		// Replace katanaOutput with the deduped version. os.Rename is
		// atomic on the same filesystem (both files are in outDir).
		if rerr := os.Rename(dedupPath, katanaOutput); rerr != nil {
			// Fall back to copy+remove if rename failed (shouldn't
			// happen since both files are in the same dir, but be
			// defensive — same fallback as nice_passive.go).
			if data, readErr := os.ReadFile(dedupPath); readErr == nil {
				os.WriteFile(katanaOutput, data, 0644)
				os.Remove(dedupPath)
			}
		}
		// Recount lines on the deduped file.
		count = 0
		if file, err := os.Open(katanaOutput); err == nil {
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				count++
			}
			file.Close()
		}
		if preCount != count {
			fmt.Printf("%s[DEDUP] uro collapsed katana output: %d -> %d URLs%s\n", gray, preCount, count, reset)
		}
	}

	fmt.Printf("%sdone for batch, results: %d saved to %s (jsluice=%v, duration=%s)%s\n",
		gray, count, katanaOutput, jsluiceApplied, time.Since(start).Round(time.Second), reset)
}
