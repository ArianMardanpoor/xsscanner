// xsscanner_discover.go
//
// Standalone discovery-only binary: runs nice_passive (deduped) + single-URL
// nice_katana, writes ONE merged/filtered output file per target, and exits.
// No nice_params, no xssniper, no Telegram, no reporter/jsonl, no param_maps
// state files — none of that exists at this stage.
//
// This is a stopping point for manual review: the produced
// <outDir>/<safeName(target)>-discovered.txt can be inspected, hand-edited,
// or fed back into the main xsscanner binary via its new -discovery-file
// flag, which picks up directly at the param-phase/test stage.
//
// Reuses the SAME crawl_cache layout and .done-sentinel coarse-resume logic
// as xsscanner's normal crawl mode (results/crawl_cache/<hostname>.passive[.done]
// and results/crawl_cache/<safeName(target)>-katana.txt[.done]). If both a
// stage's output file and its .done sentinel exist and -force is not set,
// that stage is skipped and the cached file is reused — exactly as in
// xsscanner's normal mode.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"reconpipeline/pkg/discoveryutil"
	"reconpipeline/pkg/spadetect"
)

// ANSI color codes (match xsscanner's existing palette so logs from the two
// binaries look consistent when interleaved in a pipeline).
const (
	D_gray   = "\033[90m"
	D_reset  = "\033[0m"
	D_purple = "\033[35m"
	D_bold   = "\033[1m"
	D_red    = "\033[31m"
	D_green  = "\033[32m"
	D_cyan   = "\033[36m"
)

// globalOutputDir mirrors xsscanner's variable of the same name. The crawl_cache
// lives under <globalOutputDir>/crawl_cache/ (same location as xsscanner's, so
// the two binaries can share cached passive/katana outputs between runs — e.g.
// run xsscanner_discover first to populate the cache, then run xsscanner without
// -discovery-file and it will reuse the same .passive / -katana.txt files).
var globalOutputDir = "./results"

// discoveryOutputDir is the per-target output directory for the final
// <safeName>-discovered.txt files (default results/discovery, override with -o).
// This is deliberately SEPARATE from crawl_cache so a hand-editable discovery
// file never gets confused with raw passive/katana crawl output.
var discoveryOutputDir = "./results/discovery"

// globalAuthArgs holds the parsed -cookie/-header values that get forwarded
// ONLY to the nice_katana subprocess (the only stage in this binary that
// makes live requests against the target). nice_passive is deliberately
// NEVER given these (per the same scope note in xsscanner's main.go: it only
// queries third-party archive APIs, never the target itself, and defines no
// such flags).
var globalAuthArgs []string

// headerList implements flag.Value for the repeatable -header flag (same
// implementation as xsscanner/nice_katana's main.go).
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func logMsg(msg string, color string) {
	ts := time.Now().Format("15:04:05")
	fmt.Fprintf(os.Stdout, "%s[%s]%s %s[DISCOVER] %s%s\n", D_gray, ts, D_reset, color, msg, D_reset)
}

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

// fileExists mirrors xsscanner's helper of the same name.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeDone writes the empty "<file>.done" sentinel marking a crawl stage as
// fully completed for this target (coarse crawl-stage resume). Best-effort.
func writeDone(path string) {
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		logMsg(fmt.Sprintf("Failed to write %s: %v", path, err), D_red)
	}
}

// countLines counts non-blank lines in a file (0 if missing/unreadable).
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

// runBinary runs a subprocess and pipes its stdout/stderr to os.Stdout.
// Mirrors xsscanner's runBinary behavior.
func runBinary(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// getSafeName returns a filesystem-safe name for a URL by replacing every
// non-alphanumeric character with an underscore. Matches xsscanner's
// getSafeName() verbatim so files written by xsscanner_discover use the SAME
// naming scheme as xsscanner's (so xsscanner can later look up its
// <safeURL>-paths-params.json / <safeURL>-test-state.json / <safeURL>-katana.txt
// using the same key it would have computed itself).
func getSafeName(u string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(u, "_")
}

// discoverTarget runs the discovery pipeline for a single target URL:
//
//  1. Reuse the SAME crawl_cache layout and .done-sentinel coarse-resume logic
//     as xsscanner's normal mode (results/crawl_cache/<hostname>.passive[.done]
//     and results/crawl_cache/<safeName(target)>-katana.txt[.done]).
//  2. Run ./nice_passive -o <crawlCacheDir> <hostname> if not skipped.
//  3. If useKatana and not SPA → run ./nice_katana -o <crawlCacheDir> <target>
//     (single-URL seed — NOT the passive output, per the earlier Bug 3 fix;
//     forward -cookie/-header here). If SPA detected, log and skip.
//  4. Call discoveryutil.MergeAndFilter(passiveOutFile, katanaOutFile, target).
//  5. Write the result, one full URL per line, to
//     <discoveryOutputDir>/<safeName(target)>-discovered.txt.
//  6. Print a one-line summary and return.
//
// No other side effects. No nice_params, no xssniper, no reporter, no
// param_maps state files — this binary is intentionally small and fast.
func discoverTarget(target string, useKatana bool, force bool) {
	logMsg(fmt.Sprintf("--- Starting: %s ---", target), D_purple+D_bold)

	u, err := url.Parse(target)
	if err != nil {
		logMsg(fmt.Sprintf("Invalid URL: %s", target), D_red)
		return
	}
	hostname := u.Hostname()
	if hostname == "" {
		hostname = target
	}
	safeURL := getSafeName(target)

	// crawl_cache dir: SHARED with xsscanner's normal mode (same path), so a
	// run of xsscanner_discover pre-populates the cache that xsscanner's later
	// normal-mode run will reuse — and vice versa.
	crawlCacheDir := filepath.Join(globalOutputDir, "crawl_cache")
	if err := os.MkdirAll(crawlCacheDir, 0755); err != nil {
		logMsg(fmt.Sprintf("Error creating crawl_cache dir: %v", err), D_red)
		return
	}
	if err := os.MkdirAll(discoveryOutputDir, 0755); err != nil {
		logMsg(fmt.Sprintf("Error creating discovery output dir: %v", err), D_red)
		return
	}

	passiveOutFile := filepath.Join(crawlCacheDir, hostname+".passive")
	katanaOutFile := filepath.Join(crawlCacheDir, safeURL+"-katana.txt")

	// STEP A: Passive discovery — with the SAME coarse crawl-stage resume logic
	// as xsscanner's normal mode: if a previous run already completed nice_passive
	// for this host (output file AND .done sentinel present, -force not set),
	// the cached file is reused as-is and the subprocess is skipped.
	if fileExists(passiveOutFile) && fileExists(passiveOutFile+".done") && !force {
		logMsg(fmt.Sprintf("[CACHE-SKIP passive] %s — nice_passive already completed for this host, reusing %s", hostname, filepath.Base(passiveOutFile)), D_green)
	} else {
		logMsg(fmt.Sprintf("[1/2] Running nice_passive for %s", target), D_gray)
		// NOTE: nice_passive itself gets NO -cookie/-header (scope note: it only
		// queries third-party archives, never the target — and it defines no
		// such flags). Identical to xsscanner's behavior.
		if err := runBinary("./nice_passive", "-o", crawlCacheDir, hostname); err != nil {
			// No .done on failure (and no deletion of whatever partial file
			// exists): the next run retries from scratch.
			logMsg(fmt.Sprintf("nice_passive failed for %s: %v (no .done written; next run retries)", target, err), D_red)
		} else if countLines(passiveOutFile) > 0 {
			// .done ONLY on: subprocess success AND non-empty output.
			writeDone(passiveOutFile + ".done")
		}
	}

	// STEP B: Katana crawl (default ON; pass -use-katana=false to disable),
	// single-URL seed (NOT the passive output — per the earlier Bug 3 fix),
	// with the same coarse resume pattern via its own .done sentinel.
	if useKatana {
		// Per the earlier Bug 3 fix: katana now crawls from ONLY the original
		// input target URL (once), not from the passive-discovery output.
		if spadetect.IsSPA(target) {
			logMsg(fmt.Sprintf("[SKIP-SPA] %s: SPA detected, skipping katana crawl", target), D_cyan)
		} else if fileExists(katanaOutFile) && fileExists(katanaOutFile+".done") && !force {
			logMsg(fmt.Sprintf("[CACHE-SKIP katana] %s — nice_katana already completed for this target, reusing %s", target, filepath.Base(katanaOutFile)), D_green)
		} else {
			logMsg(fmt.Sprintf("[2/2] Running nice_katana on input target for %s", target), D_gray)
			// -cookie/-header ARE forwarded here (nice_katana makes live requests
			// against the target — same scope as xsscanner's nice_katana call).
			if err := runBinary("./nice_katana", withAuth([]string{"-o", crawlCacheDir, target})...); err != nil {
				// No .done on failure: the next run re-crawls.
				logMsg(fmt.Sprintf("nice_katana failed for %s: %v (no .done written; next run retries)", target, err), D_red)
			} else {
				// nice_katana writes its crawl output to a shared
				// "katana_batch_output.txt" staging file. Move it to this target's
				// dedicated output file (inside the same crawl_cache dir) so the
				// discovery-merge step below (and a later xsscanner run) can
				// consume it deterministically.
				batchFile := filepath.Join(crawlCacheDir, "katana_batch_output.txt")
				if _, statErr := os.Stat(batchFile); statErr == nil {
					if renameErr := os.Rename(batchFile, katanaOutFile); renameErr != nil {
						logMsg(fmt.Sprintf("Failed to move katana batch output to %s: %v (no .done written; next run retries)", katanaOutFile, renameErr), D_red)
					} else if countLines(katanaOutFile) > 0 {
						// .done ONLY on: subprocess success AND non-empty output file.
						writeDone(katanaOutFile + ".done")
					} else {
						logMsg(fmt.Sprintf("nice_katana succeeded for %s but %s is empty — no .done written (next run retries)", target, filepath.Base(katanaOutFile)), D_gray)
					}
				} else {
					// Subprocess succeeded but wrote no staging file at all
					// (a crawl that finished with zero results). Treat
					// identically to the empty-output case: no .done written,
					// next run retries (an empty katana file contributes zero
					// URLs to the discovery merge either way, so re-running is
					// harmless).
					logMsg(fmt.Sprintf("nice_katana succeeded for %s but produced no staging file — no .done written (next run retries)", target), D_gray)
				}
			}
		}
	} else {
		logMsg(fmt.Sprintf("Katana disabled (-use-katana=false), skipping crawl for %s", target), D_gray)
	}

	// STEP C: Build the merged/filtered discovery list using the SHARED
	// discoveryutil package — same logic xsscanner's processTarget() now uses
	// in its own normal crawl mode. No duplicated merge/filter logic anywhere.
	discoveredURLs, errMerge := discoveryutil.MergeAndFilter(passiveOutFile, katanaOutFile, target)
	if errMerge != nil {
		// MergeAndFilter tolerates missing/unreadable input files (treats
		// them as zero lines), so reaching this branch means a real I/O error
		// mid-scan. Log and continue with whatever was collected (best-effort).
		logMsg(fmt.Sprintf("WARN: discoveryutil.MergeAndFilter error for %s: %v (continuing with %d URLs)", target, errMerge, len(discoveredURLs)), D_red)
	}

	// STEP D: Write the result, one URL per line, to the per-target discovery
	// output file. Use the SAME safe-URL naming scheme xsscanner uses for its
	// state files so a later xsscanner run can locate the matching state files
	// using its own safeURL computation.
	outputPath := filepath.Join(discoveryOutputDir, safeURL+"-discovered.txt")
	var b strings.Builder
	for _, line := range discoveredURLs {
		b.WriteString(line)
		b.WriteString("\n")
	}
	if err := os.WriteFile(outputPath, []byte(b.String()), 0644); err != nil {
		logMsg(fmt.Sprintf("Failed to write discovery file %s: %v", outputPath, err), D_red)
		return
	}

	// One-line summary: "[%d urls] %s -> %s". Matches the spec's required
	// summary format.
	logMsg(fmt.Sprintf("[%d urls] %s -> %s", len(discoveredURLs), target, outputPath), D_cyan)
}

func main() {
	inputFile := flag.String("i", "", "Input file with targets (one URL per line)")
	targetURL := flag.String("u", "", "Single target URL to discover")
	outDir := flag.String("o", "results/discovery", "Output directory for the final per-target discovery file (<safeName>-discovered.txt)")
	useKatana := flag.Bool("use-katana", true, "Run nice_katana crawl step (on by default; pass -use-katana=false to disable)")
	cookie := flag.String("cookie", "", "Raw Cookie header value forwarded ONLY to the nice_katana crawl subprocess (nice_passive is never given auth — it only queries third-party archives, never the target), e.g. \"session=abc123; other=val\"")
	var headers headerList
	flag.Var(&headers, "header", "Extra HTTP header forwarded ONLY to the nice_katana crawl subprocess, format \"Name: Value\" (repeatable, order preserved). nice_passive is never given auth.")
	force := flag.Bool("force", false, "Bypass the .done-sentinel reuse logic for both passive and katana stages: re-run both fresh from scratch")

	flag.Parse()

	// Apply -o override (discoveryOutputDir defaults to results/discovery).
	if *outDir != "" {
		discoveryOutputDir = *outDir
	}

	// Build the global auth args list from -cookie / repeatable -header.
	// These are forwarded ONLY to nice_katana via withAuth() above.
	if *cookie != "" {
		globalAuthArgs = append(globalAuthArgs, "-cookie", *cookie)
	}
	for _, h := range headers {
		globalAuthArgs = append(globalAuthArgs, "-header", h)
	}

	// Input validation: exactly one of -u / -i must be set (mirrors xsscanner's
	// existing -u/-i precedence rule, minus xsscanner's -path-file/-only/
	// -discovery-file modes which don't apply here).
	if *targetURL == "" && *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  xsscanner_discover -u https://target.com")
		fmt.Fprintln(os.Stderr, "  xsscanner_discover -i targets.txt")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Build target list. -u takes precedence over -i (same as xsscanner).
	var targets []string
	if *targetURL != "" {
		targets = []string{*targetURL}
		logMsg(fmt.Sprintf("Single target mode: %s", *targetURL), D_cyan)
	} else if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			logMsg(fmt.Sprintf("Error opening input file: %v", err), D_red)
			os.Exit(1)
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
		logMsg("No targets to process.", D_green)
		return
	}

	logMsg(fmt.Sprintf("Ready to discover %d targets.", len(targets)), D_cyan)
	for _, target := range targets {
		discoverTarget(target, *useKatana, *force)
	}
	logMsg(fmt.Sprintf("Done. %d targets processed. Discovery files in %s/", len(targets), discoveryOutputDir), D_green)

	// NOTE: intentionally NO call to anything from reporter / Telegram /
	// param_maps / xssniper / nice_params. This binary stops at the
	// discovery-file write — that's the whole point. To proceed to the
	// param/test stage, run:
	//
	//   xsscanner -u <target> -discovery-file <discoveryOutputDir>/<safeName>-discovered.txt
	//
	// which will skip its own crawling and pick up directly at the per-path
	// phase→test loop using this file as its discoveryList.
}
