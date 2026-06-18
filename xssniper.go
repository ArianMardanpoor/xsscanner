package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Telegram Configuration ───────────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

func loadEnv() {
	candidates := []string{".env"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if os.Getenv(key) == "" {
					os.Setenv(key, val)
				}
			}
		}
		f.Close()
	}
}

func newTelegram() *Telegram {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		logLine("INFO", X_yellow, "Telegram configuration missing. Notifications disabled.")
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID}
}

func (tg *Telegram) notify(targetURL string, findings []string, scanType string) {
	if tg == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 <b>%s XSS Finding!</b>\n\n", scanType))
	sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(targetURL)))
	sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n", ts))
	sb.WriteString(fmt.Sprintf("🔢 <b>Count:</b> %d unique endpoint(s)\n\n", len(findings)))

	for i, f := range findings {
		cleanLine := stripANSI(f)
		if len(cleanLine) > 3500 {
			cleanLine = cleanLine[:3500] + "..."
		}
		sb.WriteString(fmt.Sprintf("<code>%d. %s</code>\n", i+1, escapeHTML(cleanLine)))
	}

	payload := map[string]interface{}{
		"chat_id":                  tg.ChatID,
		"text":                     sb.String(),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	body, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.Token)
	http.Post(apiURL, "application/json", bytes.NewReader(body))
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── UI and Logging ────────────────────────────────────────────────────────────

const (
	X_reset  = "\033[0m"
	X_bold   = "\033[1m"
	X_red    = "\033[31m"
	X_green  = "\033[32m"
	X_yellow = "\033[33m"
	X_blue   = "\033[34m"
	X_purple = "\033[35m"
	X_cyan   = "\033[36m"
	X_gray   = "\033[90m"
	X_white  = "\033[97m"
)

var (
	outputDir      string
	nucleiTemplate string
	domTemplate    string
	canaryTemplate string
	paramFile      string
	concurrency    int
	workers        int
	mu             sync.Mutex
	tg             *Telegram
	allCrawledURLs []string
)

func logLine(level, color, format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", X_gray, ts, X_reset, color, level, X_reset, fmt.Sprintf(format, args...))
}

func stripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAllString(str, "")
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func extractURLsFromNuclei(nucleiOutput string) []string {
	// Nuclei output typically contains [template-id] [protocol] [severity] URL [extractors]
	// We want to find the part that starts with http.
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(nucleiOutput))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
				// Remove trailing brackets if any (sometimes nuclei wraps things)
				urlPart := strings.Trim(part, "[]")
				urls = append(urls, urlPart)
				break
			}
		}
	}
	return uniqueStrings(urls)
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Basic normalization: remove trailing slash
		u := strings.TrimSuffix(s, "/")
		if !seen[u] {
			seen[u] = true
			result = append(result, s)
		}
	}
	return result
}

func dedupeNucleiFindings(findings string) []string {
	lines := strings.Split(strings.TrimSpace(findings), "\n")
	seen := make(map[string]bool)
	var result []string

	// Improved regex to match both probe and heavy payloads
	re := regexp.MustCompile(`x9(?:canary)?[a-z]{3}['\"` + "`" + `\\;<{]*`)

	for _, line := range lines {
		if line == "" {
			continue
		}
		// Try to create a unique key: template-id + simplified URL
		parts := strings.Fields(line)
		if len(parts) < 1 {
			continue
		}

		templateID := parts[0]
		targetURL := ""
		for _, p := range parts {
			if strings.HasPrefix(p, "http") {
				targetURL = strings.Trim(p, "[]")
				break
			}
		}

		if targetURL == "" {
			result = append(result, line)
			continue
		}

		// Simplify URL by replacing x9 payload values with a placeholder
		simpleURL := re.ReplaceAllString(targetURL, "REDACTED")

		key := templateID + "|" + simpleURL
		if !seen[key] {
			seen[key] = true
			result = append(result, line)
		}
	}
	return result
}

func filterFileForNuclei(inputPath string) string {
	file, err := os.Open(inputPath)
	if err != nil {
		return inputPath
	}
	defer file.Close()

	seen := make(map[string]bool)
	var uniqueLines []string
	re := regexp.MustCompile(`x9(?:canary)?[a-z]{3}['\"` + "`" + `\\;<{]*`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Create a key based on the URL structure, not the specific payload
		key := re.ReplaceAllString(line, "REDACTED")
		if !seen[key] {
			seen[key] = true
			uniqueLines = append(uniqueLines, line)
		}
	}

	if len(uniqueLines) == 0 {
		return inputPath
	}

	outputPath := inputPath + ".dedupe"
	os.WriteFile(outputPath, []byte(strings.Join(uniqueLines, "\n")+"\n"), 0644)
	return outputPath
}

// ── Core Logic ────────────────────────────────────────────────────────────────

func processURL(targetURL string, index, total int) {
	logLine("TARGET", X_white, "[%d/%d] %s", index, total, targetURL)
	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(targetURL, "_")

	// Phase 2: Canary Probe
	logLine("PHASE", X_cyan, "2/5 Canary Probing...")
	probeInput := filepath.Join(outputDir, safe+"-probe-in.txt")
	if err := os.WriteFile(probeInput, []byte(targetURL), 0644); err != nil {
		logLine("ERROR", X_red, "Failed to write probe input: %v", err)
	}

	probeOutputBase := filepath.Join(outputDir, safe+"-probe-out")
	x9Args := []string{"-probe", "-json", "-headers", "-i", probeInput, "-o", probeOutputBase}
	if paramFile != "" {
		if _, err := os.Stat(paramFile); err == nil {
			x9Args = append(x9Args, "-p", paramFile)
		}
	}
	if _, err := runCommand("./x9", x9Args...); err != nil {
		logLine("ERROR", X_red, "x9 probe failed: %v", err)
	}

	// Phase 3: Filter Vulnerable Parameters
	logLine("PHASE", X_blue, "3/5 Filtering reflective parameters...")
	// We check GET, JSON, and Header probes
	probeFiles := []string{probeOutputBase + ".get", probeOutputBase + ".json", probeOutputBase + ".header"}
	var allFilterResults []string
	for _, pf := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
			if res != "" {
				allFilterResults = append(allFilterResults, extractURLsFromNuclei(res)...)
			}
		}
	}

	allFilterResults = uniqueStrings(allFilterResults)

	if len(allFilterResults) == 0 {
		logLine("INFO", X_gray, "No reflective parameters found. Skipping heavy attacks.")
		return
	}

	attackInput := filepath.Join(outputDir, safe+"-atk-in.txt")
	os.WriteFile(attackInput, []byte(strings.Join(allFilterResults, "\n")), 0644)

	// Phase 4: Heavy Attack
	logLine("PHASE", X_purple, "4/5 Executing Heavy Attacks & DOM Scan...")
	finalX9Base := filepath.Join(outputDir, safe+"-final")
	runCommand("./x9", "-i", attackInput, "-json", "-headers", "-o", finalX9Base)

	finalFiles := []string{finalX9Base + ".get", finalX9Base + ".json", finalX9Base + ".header"}
	var allTargetFindings []string

	for _, ff := range finalFiles {
		if _, err := os.Stat(ff); err == nil {
			// Deduplicate the input file to speed up Nuclei and reduce redundant requests
			dedupedFile := filterFileForNuclei(ff)

			// Reflection Scan
			if findings, _ := runCommand("nuclei", "-l", dedupedFile, "-t", nucleiTemplate, "-silent"); findings != "" {
				uniqueFindings := dedupeNucleiFindings(findings)
				logLine("VULN", X_red, "Found %d Unique Reflections in %s!", len(uniqueFindings), ff)
				for _, f := range uniqueFindings {
					logLine("FINDING", X_yellow, "-> %s", f)
					allTargetFindings = append(allTargetFindings, f)
				}
			}

			// DOM Scan (only makes sense for GET/URLs usually, but we try anyway or filter)
			if strings.HasSuffix(ff, ".get") {
				if dom, _ := runCommand("nuclei", "-l", dedupedFile, "-t", domTemplate, "-headless", "-silent"); dom != "" {
					uniqueDOM := dedupeNucleiFindings(dom)
					logLine("VULN", X_red, "Found %d Unique DOM XSS!", len(uniqueDOM))
					for _, f := range uniqueDOM {
						logLine("FINDING", X_yellow, "-> [DOM] %s", f)
						allTargetFindings = append(allTargetFindings, "[DOM] "+f)
					}
				}
			}
		}
	}

	if len(allTargetFindings) > 0 {
		tg.notify(targetURL, uniqueStrings(allTargetFindings), "Consolidated")
	}
}

func main() {
	urlFile := flag.String("l", "", "URL list file (use '-' for stdin)")
	flag.StringVar(&outputDir, "o", "./output", "Output directory")
	flag.StringVar(&nucleiTemplate, "t", "xss_template_v2.yaml", "Reflection template")
	flag.StringVar(&domTemplate, "dom", "dom_xss.yaml", "DOM template")
	flag.StringVar(&canaryTemplate, "canary", "canary_matcher.yaml", "Canary template")
	flag.StringVar(&paramFile, "p", "", "Parameter file to use with x9")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency per URL")
	flag.IntVar(&workers, "w", 3, "Parallel URL workers")
	flag.Parse()

	loadEnv()
	tg = newTelegram()
	os.MkdirAll(outputDir, 0755)

	var urls []string
	var scanner *bufio.Scanner
	if *urlFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		flag.Usage()
		os.Exit(1)
	}

	for scanner.Scan() {
		if u := strings.TrimSpace(scanner.Text()); u != "" {
			urls = append(urls, u)
		}
	}
	urls = uniqueStrings(urls)

	mu.Lock()
	allCrawledURLs = append(allCrawledURLs, urls...)
	mu.Unlock()

	logLine("INFO", X_cyan, "Starting Pipeline for %d targets with %d workers...", len(urls), workers)

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			processURL(target, idx+1, len(urls))
		}(u, i)
	}
	wg.Wait()

	// Phase 5: Final Second-Order XSS Check
	logLine("PHASE", X_white, "5/5 Final Second-Order Check on all discovered URLs...")
	mu.Lock()
	allCrawledURLs = uniqueStrings(allCrawledURLs)
	mu.Unlock()

	finalIn := filepath.Join(outputDir, "all_crawled_discovery.txt")
	os.WriteFile(finalIn, []byte(strings.Join(allCrawledURLs, "\n")), 0644)
	if so, _ := runCommand("nuclei", "-l", finalIn, "-t", nucleiTemplate, "-silent"); so != "" {
		uniqueSO := dedupeNucleiFindings(so)
		logLine("VULN", X_red, "Found %d Unique Second-Order XSS vulnerabilities!", len(uniqueSO))
		for _, f := range uniqueSO {
			logLine("FINDING", X_yellow, "-> [SO] %s", f)
		}
		tg.notify("Global Second-Order Check", uniqueSO, "Second-Order")
	}

	fmt.Printf("\n%s[DONE]%s Full Recon & XSS Pipeline Complete.\n", X_green, X_reset)
}
