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
	"sync/atomic"
	"time"
)

// ── Telegram Configuration ───────────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

// ── Vulnerability Reporting ──────────────────────────────────────────────────

type Vulnerability struct {
	Name     string   `json:"parameter,omitempty"` // parameter name, header name, or json key
	Payloads []string `json:"payloads"`
}

type VulnerabilityReport struct {
	URL             string          `json:"url"`
	QueryParameters []Vulnerability `json:"query_parameters,omitempty"`
	Headers         []Vulnerability `json:"headers,omitempty"`
	JSONBody        []Vulnerability `json:"json_body,omitempty"`
	DOM             []Vulnerability `json:"dom,omitempty"`
}

func (r *VulnerabilityReport) HasVulns() bool {
	return len(r.QueryParameters) > 0 || len(r.Headers) > 0 || len(r.JSONBody) > 0 || len(r.DOM) > 0
}

func redactX9(s string) string {
	return reX9.ReplaceAllString(s, "x9")
}

func (r *VulnerabilityReport) aggregateFindings(nucleiOutput string, phase string) {
	if nucleiOutput == "" {
		return
	}

	lines := strings.Split(strings.TrimSpace(nucleiOutput), "\n")

	for _, line := range lines {
		line = stripANSI(strings.TrimSpace(line))
		line = reCleaning.ReplaceAllString(line, "")
		if line == "" {
			continue
		}

		// 1. Extract redacted payload
		payload := ""
		if m := rePayload.FindStringSubmatch(line); len(m) > 0 {
			if m[1] != "" {
				payload = m[1]
			} else {
				payload = m[2]
			}
		}
		if payload != "" {
			payload = redactX9(payload)
		}

		// 2. Extract URL and injection point
		rawURL := ""
		parts := strings.Fields(line)
		for _, p := range parts {
			if strings.HasPrefix(p, "http") {
				rawURL = strings.Trim(p, "[]")
				break
			}
		}

		if rawURL == "" {
			continue
		}

		// Parse injection info from URL (format: target|injection)
		decodedURL, _ := url.QueryUnescape(rawURL)
		injection := ""
		if strings.Contains(decodedURL, "|") {
			sub := strings.SplitN(decodedURL, "|", 2)
			injection = sub[1]
		}

		name := "unknown"
		targetList := &r.QueryParameters

		switch phase {
		case "header":
			targetList = &r.Headers
			if strings.Contains(injection, ":") {
				name = strings.SplitN(injection, ":", 2)[0]
			}
		case "json":
			targetList = &r.JSONBody
			if strings.HasPrefix(injection, "{") {
				var data map[string]interface{}
				if err := json.Unmarshal([]byte(injection), &data); err == nil {
					for k, v := range data {
						valStr := fmt.Sprintf("%v", v)
						if strings.Contains(redactX9(valStr), "x9") {
							name = k
							break
						}
					}
				} else {
					name = "JSON Body"
				}
			}
		case "dom":
			targetList = &r.DOM
			if u, err := url.Parse(decodedURL); err == nil {
				// Find which query param matches the reflection
				for k, v := range u.Query() {
					if strings.Contains(redactX9(strings.Join(v, "")), "x9") {
						name = k
						break
					}
				}
			}
		default: // get or second-order
			if u, err := url.Parse(decodedURL); err == nil {
				q := u.Query()
				for k, v := range q {
					for _, val := range v {
						if strings.Contains(redactX9(val), "x9") {
							name = k
							goto found
						}
					}
				}
			}
		found:
		}

		// Add to list
		found := false
		for i, v := range *targetList {
			if v.Name == name {
				if payload != "" {
					exists := false
					for _, p := range v.Payloads {
						if p == payload {
							exists = true
							break
						}
					}
					if !exists {
						(*targetList)[i].Payloads = append((*targetList)[i].Payloads, payload)
					}
				}
				found = true
				break
			}
		}
		if !found {
			newVuln := Vulnerability{Name: name}
			if payload != "" {
				newVuln.Payloads = []string{payload}
			}
			*targetList = append(*targetList, newVuln)
		}
	}
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
	type Group struct {
		DisplayURL string
		Payloads   []string
		Seen       map[string]bool
	}

	groups := make(map[string]*Group)
	var order []string

	for _, f := range findings {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}

		// 1. Extract payload
		var payload string
		if m := rePayload.FindStringSubmatch(f); len(m) > 0 {
			if m[1] != "" {
				payload = m[1]
			} else {
				payload = m[2]
			}
		}

		// 2. Extract original URL from line
		originalURL := ""
		parts := strings.Fields(f)
		for _, p := range parts {
			if strings.HasPrefix(p, "http") {
				originalURL = strings.Trim(p, "[]")
				break
			}
		}
		if originalURL == "" {
			continue
		}

		// 3. Create Grouping Key
		keyLine := rePayload.ReplaceAllString(f, "")
		groupKey := redactX9(keyLine)
		groupKey = strings.TrimSpace(groupKey)

		if _, ok := groups[groupKey]; !ok {
			// Clean up display URL
			displayURL := originalURL
			if strings.Contains(displayURL, "|") || strings.Contains(displayURL, "%7C") {
				displayURL = strings.ReplaceAll(displayURL, "%7C", "|")
				sub := strings.SplitN(displayURL, "|", 2)
				if len(sub) == 2 {
					target := sub[0]
					injection := sub[1]
					if strings.HasPrefix(injection, "{") {
						displayURL = fmt.Sprintf("%s (JSON Body)", target)
					} else {
						displayURL = fmt.Sprintf("%s (Injection: %s)", target, injection)
					}
				}
			}
			// Redact x9 from display URL for a cleaner look
			displayURL = redactX9(displayURL)

			// De-duplicate parameters in display URL
			if u, err := url.Parse(displayURL); err == nil {
				q := u.Query()
				for k, v := range q {
					if len(v) > 1 {
						q.Set(k, v[0])
					}
				}
				u.RawQuery = q.Encode()
				displayURL = u.String()
			}

			groups[groupKey] = &Group{
				DisplayURL: displayURL,
				Seen:       make(map[string]bool),
			}
			order = append(order, groupKey)
		}

		if payload != "" && !groups[groupKey].Seen[payload] {
			groups[groupKey].Seen[payload] = true
			groups[groupKey].Payloads = append(groups[groupKey].Payloads, payload)
		}
	}

	var result []string
	for _, key := range order {
		g := groups[key]
		if len(g.Payloads) > 0 {
			quoted := make([]string, len(g.Payloads))
			for i, p := range g.Payloads {
				quoted[i] = fmt.Sprintf("\"%s\"", p)
			}
			result = append(result, fmt.Sprintf("%s [%s]", g.DisplayURL, strings.Join(quoted, ", ")))
		} else {
			result = append(result, g.DisplayURL)
		}
	}
	return result
}

func dedupeConfirmedURLs(urls []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, u := range urls {
		normalized := u
		uParsed, err := url.Parse(u)
		if err == nil {
			// Redact x9 in query values for grouping
			q := uParsed.Query()
			newQuery := url.Values{}
			for k, v := range q {
				val := v[0]
				val = redactX9(val)
				newQuery.Set(k, val)
			}
			uParsed.RawQuery = newQuery.Encode()
			if uParsed.Path == "/" {
				uParsed.Path = ""
			}
			normalized = uParsed.String()
		} else {
			normalized = redactX9(u)
		}

		if !seen[normalized] {
			seen[normalized] = true
			unique = append(unique, u)
		}
	}
	return unique
}

func (tg *Telegram) notify(report VulnerabilityReport) {
	if !report.HasVulns() {
		return
	}

	if _, loaded := vulnerableMap.LoadOrStore(report.URL, true); !loaded {
		atomic.AddInt64(&vulnerableTargets, 1)
	}

	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	// 1. Terminal Output
	mu.Lock()
	fmt.Printf("\n%s[VULN FOUND]%s\n%s%s%s\n", X_red+X_bold, X_reset, X_yellow, string(reportJSON), X_reset)
	mu.Unlock()

	// 2. Save to File
	vulnDir := filepath.Join(outputDir, "vulnerabilities")
	os.MkdirAll(vulnDir, 0755)
	safeName := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(report.URL, "_")
	fileName := filepath.Join(vulnDir, safeName+".json")
	os.WriteFile(fileName, reportJSON, 0644)

	// 3. Telegram Notification
	if tg != nil {
		ts := time.Now().Format("2006-01-02 15:04:05")
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("🚨 <b>XSS Finding!</b>\n\n"))
		sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(report.URL)))
		sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n\n", ts))
		sb.WriteString(fmt.Sprintf("<pre>%s</pre>", escapeHTML(string(reportJSON))))

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
	outputDir         string
	nucleiTemplate    string
	domTemplate       string
	canaryTemplate    string
	paramFile         string
	concurrency       int
	workers           int
	mu                sync.Mutex
	tg                *Telegram
	allCrawledURLs    []string
	processedTargets  int64
	vulnerableTargets int64
	vulnerableMap     sync.Map

	// Regexes
	reX9       = regexp.MustCompile(`x9(?:canary)?[a-z]*`)
	rePayload  = regexp.MustCompile(`\[(?:"([^"]+)"|([^"\]]+))\]$`)
	reANSI     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	reCleaning = regexp.MustCompile(`\s*\["0m"\]\s*`)
)

func logLine(level, color, format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", X_gray, ts, X_reset, color, level, X_reset, fmt.Sprintf(format, args...))
}

func stripANSI(str string) string {
	return reANSI.ReplaceAllString(str, "")
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
	atomic.AddInt64(&processedTargets, 1)
	currProcessed := atomic.LoadInt64(&processedTargets)
	currVulns := atomic.LoadInt64(&vulnerableTargets)

	logLine("TARGET", X_white, "[%d/%d | Vulns: %d] %s", currProcessed, total, currVulns, targetURL)
	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(targetURL, "_")

	report := VulnerabilityReport{URL: targetURL}

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
	var httpConfirmed []string
	var domConfirmed []string

	for _, pf := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			// HTTP Canary
			res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
			if res != "" {
				httpConfirmed = append(httpConfirmed, extractURLsFromNuclei(res)...)
			}

			// DOM Canary (Only for GET/URLs)
			if strings.HasSuffix(pf, ".get") {
				resDom, _ := runCommand("nuclei", "-l", pf, "-t", "dom_canary.yaml", "-headless", "-silent")
				if resDom != "" {
					domConfirmed = append(domConfirmed, extractURLsFromNuclei(resDom)...)
				}
			}
		}
	}

	httpConfirmed = dedupeConfirmedURLs(httpConfirmed)
	domConfirmed = dedupeConfirmedURLs(domConfirmed)

	if len(httpConfirmed) == 0 && len(domConfirmed) == 0 {
		logLine("INFO", X_gray, "No reflective parameters found. Skipping heavy attacks.")
		return
	}

	// Phase 4: Heavy Attack
	logLine("PHASE", X_purple, "4/5 Executing Heavy Attacks & DOM Scan...")

	// 4.1: HTTP Heavy Attack
	if len(httpConfirmed) > 0 {
		atkIn := filepath.Join(outputDir, safe+"-http-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(httpConfirmed, "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-http")
		runCommand("./x9", "-i", atkIn, "-json", "-headers", "-o", finalX9Base)

		finalFiles := map[string]string{
			finalX9Base + ".get":    "get",
			finalX9Base + ".json":   "json",
			finalX9Base + ".header": "header",
		}
		for ff, phase := range finalFiles {
			if _, err := os.Stat(ff); err == nil {
				if findings, _ := runCommand("nuclei", "-l", ff, "-t", nucleiTemplate, "-silent"); findings != "" {
					report.aggregateFindings(findings, phase)
				}
			}
		}
	}

	// 4.2: DOM Heavy Attack (Only for DOM-confirmed parameters)
	if len(domConfirmed) > 0 {
		logLine("INFO", X_gray, "Running heavy DOM scan for %d confirmed parameters...", len(domConfirmed))
		atkIn := filepath.Join(outputDir, safe+"-dom-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(domConfirmed, "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-dom")
		runCommand("./x9", "-i", atkIn, "-o", finalX9Base)

		ff := finalX9Base + ".get"
		if _, err := os.Stat(ff); err == nil {
			// Added timeout to headless scan
			if dom, _ := runCommand("nuclei", "-l", ff, "-t", domTemplate, "-headless", "-silent", "-timeout", "300"); dom != "" {
				report.aggregateFindings(dom, "dom")
			}
		}
	}

	if report.HasVulns() {
		tg.notify(report)
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
		soReport := VulnerabilityReport{URL: "Global Second-Order Check"}
		soReport.aggregateFindings(so, "get")
		if soReport.HasVulns() {
			tg.notify(soReport)
		}
	}

	fmt.Printf("\n%s[DONE]%s Full Recon & XSS Pipeline Complete.\n", X_green, X_reset)
}
