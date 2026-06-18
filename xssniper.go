package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
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
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID}
}

func dedupeNucleiFindings(findings []string) []string {
	// Group findings by: TemplateID + URL (without payload part)
	// Example line: [x9-v2-reflection-matcher] [http] [info] http://localhost:2121/test.php?p=x9canaryabc [x9canaryabc]
	// We want to keep only one finding per URL+Template if the payload is just a variation.

	// For x9, we redact the randomized part: x9[a-z]{3}
	reX9 := regexp.MustCompile(`x9(?:canary)?[a-z]{3}['\"` + "`" + `\\;<{]*`)

	seen := make(map[string]bool)
	var unique []string

	for _, f := range findings {
		// Redact the x9 payload to normalize the finding line
		normalizedLine := reX9.ReplaceAllString(f, "x9REDACTED")
		if !seen[normalizedLine] {
			seen[normalizedLine] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func (tg *Telegram) notify(targetURL string, findings []string, scanType string) {
	if tg == nil {
		for _, f := range findings {
			fmt.Printf("%s[FINDING]%s -> %s\n", X_green, X_reset, f)
		}
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
	return urls
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

	// Phase 3: Filter Vulnerable Parameters (HTTP & DOM)
	logLine("PHASE", X_blue, "3/5 Filtering reflective parameters...")
	// We check GET, JSON, and Header probes
	probeFiles := []string{probeOutputBase + ".get", probeOutputBase + ".json", probeOutputBase + ".header"}
	var allFilterResults []string
	for _, pf := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			// HTTP Canary
			res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
			if res != "" {
				allFilterResults = append(allFilterResults, extractURLsFromNuclei(res)...)
			}

			// DOM Canary (Only for GET/URLs)
			if strings.HasSuffix(pf, ".get") {
				resDom, _ := runCommand("nuclei", "-l", pf, "-t", "dom_canary.yaml", "-headless", "-silent")
				if resDom != "" {
					allFilterResults = append(allFilterResults, extractURLsFromNuclei(resDom)...)
				}
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
	for _, ff := range finalFiles {
		if _, err := os.Stat(ff); err == nil {
			// Reflection Scan
			if findings, _ := runCommand("nuclei", "-l", ff, "-t", nucleiTemplate, "-silent"); findings != "" {
				lines := strings.Split(strings.TrimSpace(findings), "\n")
				uniqueFindings := dedupeNucleiFindings(lines)
				logLine("VULN", X_red, "Found %d Reflections in %s!", len(uniqueFindings), ff)
				tg.notify(targetURL, uniqueFindings, "Reflection")
			}

			// DOM Scan (only makes sense for GET/URLs usually, but we try anyway or filter)
			if strings.HasSuffix(ff, ".get") {
				if dom, _ := runCommand("nuclei", "-l", ff, "-t", domTemplate, "-headless", "-silent"); dom != "" {
					lines := strings.Split(strings.TrimSpace(dom), "\n")
					uniqueFindings := dedupeNucleiFindings(lines)
					logLine("VULN", X_red, "Found %d DOM XSS!", len(uniqueFindings))
					tg.notify(targetURL, uniqueFindings, "DOM")
				}
			}
		}
	}
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		u, err := url.Parse(entry)
		if err != nil {
			if !keys[entry] {
				keys[entry] = true
				list = append(list, entry)
			}
			continue
		}
		// Basic normalization
		if u.Path == "/" {
			u.Path = ""
		}
		normalized := u.String()
		if !keys[normalized] {
			keys[normalized] = true
			list = append(list, entry)
		}
	}
	return list
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
	finalIn := filepath.Join(outputDir, "all_crawled_discovery.txt")
	uniqueCrawled := uniqueStrings(allCrawledURLs)
	os.WriteFile(finalIn, []byte(strings.Join(uniqueCrawled, "\n")), 0644)
	if so, _ := runCommand("nuclei", "-l", finalIn, "-t", nucleiTemplate, "-silent"); so != "" {
		lines := strings.Split(strings.TrimSpace(so), "\n")
		uniqueFindings := dedupeNucleiFindings(lines)
		logLine("VULN", X_red, "Found %d Second-Order XSS vulnerabilities!", len(uniqueFindings))
		tg.notify("Global Second-Order Check", uniqueFindings, "Second-Order")
	}

	fmt.Printf("\n%s[DONE]%s Full Recon & XSS Pipeline Complete.\n", X_green, X_reset)
}
