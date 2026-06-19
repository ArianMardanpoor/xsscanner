// FILE: xssniper.go — MODIFIED
// Changes: Fix duplicate processing, improve payload capture, add URL filtering, and ensure DOM scan reliability.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	Name      string   `json:"parameter,omitempty"`
	Payloads  []string `json:"payloads"`
	Severity  string   `json:"severity"`
	Confirmed bool     `json:"confirmed"`
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

		// 1. Extract payload
		payload := ""
		if m := rePayload.FindStringSubmatch(line); len(m) > 0 {
			if m[1] != "" {
				payload = m[1]
			} else {
				payload = m[2]
			}
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

		decodedURL, _ := url.QueryUnescape(rawURL)
		injection := ""
		targetURL := rawURL
		if strings.Contains(decodedURL, "|") {
			sub := strings.SplitN(decodedURL, "|", 2)
			targetURL = sub[0]
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
				}
			}
		case "dom":
			targetList = &r.DOM
			if u, err := url.Parse(decodedURL); err == nil {
				// Check fragment first
				if strings.Contains(redactX9(u.Fragment), "x9") {
					name = "fragment"
				} else {
					for k, v := range u.Query() {
						if strings.Contains(redactX9(strings.Join(v, "")), "x9") {
							name = k
							break
						}
					}
				}
			}
		default:
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

		if name == "unknown" {
			continue
		}
		if phase == "header" && strings.HasPrefix(injection, "{") {
			continue
		}

		severity := "possible"
		if phase == "get" || phase == "dom" {
			severity = "likely"
		} else if phase == "header" || phase == "json" {
			canary := ""
			if m := reX9.FindString(injection); m != "" {
				canary = m
			}
			if canary != "" {
				headers := make(map[string]string)
				method := "GET"
				body := ""
				if phase == "header" {
					parts := strings.SplitN(injection, ":", 2)
					headers[parts[0]] = parts[1]
				} else {
					method = "POST"
					body = injection
				}
				if verifyReflection(targetURL, method, headers, body, canary) {
					severity = "likely"
				} else {
					continue
				}
			}
		}

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
				if severityWeight(severity) > severityWeight((*targetList)[i].Severity) {
					(*targetList)[i].Severity = severity
				}
				found = true
				break
			}
		}
		if !found {
			newVuln := Vulnerability{Name: name, Severity: severity}
			if payload != "" {
				newVuln.Payloads = []string{payload}
			}
			*targetList = append(*targetList, newVuln)
		}
	}
}

func severityWeight(s string) int {
	switch s {
	case "confirmed": return 3
	case "likely": return 2
	case "possible": return 1
	default: return 0
	}
}

func verifyReflection(targetURL, method string, headers map[string]string, body, canary string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(body))
		if err == nil { req.Header.Set("Content-Type", "application/json") }
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
	}

	if err != nil { return false }
	for k, v := range headers { req.Header.Set(k, v) }

	resp, err := client.Do(req)
	if err != nil { return false }
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(respBody), canary)
}

func loadEnv() {
	candidates := []string{".env"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil { continue }
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") { continue }
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if os.Getenv(key) == "" { os.Setenv(key, val) }
			}
		}
		f.Close()
	}
}

func newTelegram() *Telegram {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" { return nil }
	return &Telegram{Token: token, ChatID: chatID}
}

func dedupeNucleiFindings(report VulnerabilityReport) string {
	var sb strings.Builder
	renderSection := func(title string, vulns []Vulnerability) {
		if len(vulns) == 0 { return }
		sb.WriteString(fmt.Sprintf("\n  %s[%s]%s\n", X_cyan, title, X_reset))
		for _, v := range vulns {
			sevColor := X_gray
			switch v.Severity {
			case "confirmed": sevColor = X_red + X_bold
			case "likely": sevColor = X_yellow
			case "possible": sevColor = X_white
			}
			sb.WriteString(fmt.Sprintf("    - %s: %s [%s]%s\n", v.Name, sevColor, v.Severity, X_reset))
			if len(v.Payloads) > 0 {
				sb.WriteString(fmt.Sprintf("      Payloads: %s\n", strings.Join(v.Payloads, ", ")))
			}
		}
	}
	sb.WriteString(fmt.Sprintf("%s%s%s", X_bold, report.URL, X_reset))
	renderSection("Query Params", report.QueryParameters)
	renderSection("Headers", report.Headers)
	renderSection("JSON Body", report.JSONBody)
	renderSection("DOM", report.DOM)
	return sb.String()
}

func dedupeConfirmedURLs(urls []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, u := range urls {
		normalized := u
		uParsed, err := url.Parse(u)
		if err == nil {
			q := uParsed.Query()
			newQuery := url.Values{}
			for k, v := range q {
				val := v[0]
				val = redactX9(val)
				newQuery.Set(k, val)
			}
			uParsed.RawQuery = newQuery.Encode()
			uParsed.Fragment = redactX9(uParsed.Fragment)
			if uParsed.Path == "/" { uParsed.Path = "" }
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
	if !report.HasVulns() { return }

	if _, loaded := vulnerableMap.LoadOrStore(report.URL, true); !loaded {
		atomic.AddInt64(&vulnerableTargets, 1)
	}

	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	formatted := dedupeNucleiFindings(report)

	mu.Lock()
	fmt.Printf("\n%s[VULN FOUND]%s\n%s\n", X_red+X_bold, X_reset, formatted)
	mu.Unlock()

	vulnDir := filepath.Join(outputDir, "vulnerabilities")
	os.MkdirAll(vulnDir, 0755)
	safeName := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(report.URL, "_")
	fileName := filepath.Join(vulnDir, safeName+".json")
	os.WriteFile(fileName, reportJSON, 0644)

	hasHighSeverity := false
	checkList := [][]Vulnerability{report.QueryParameters, report.Headers, report.JSONBody, report.DOM}
	for _, list := range checkList {
		for _, v := range list {
			if v.Severity == "confirmed" || v.Severity == "likely" {
				hasHighSeverity = true
				break
			}
		}
		if hasHighSeverity { break }
	}

	if tg != nil && hasHighSeverity {
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
	workerLock        sync.Map
	nucleiExists      bool

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
	if name == "nuclei" && !nucleiExists { return "", nil }
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func extractURLsFromNuclei(nucleiOutput string) []string {
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(nucleiOutput))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
				urlPart := strings.Trim(part, "[]")
				urls = append(urls, urlPart)
				break
			}
		}
	}
	return urls
}

// ── Core Logic ────────────────────────────────────────────────────────────────

func confirmParameter(targetURL, phase, name string) (bool, string) {
	payloads := []string{
		`"><img src=x onerror=prompt(document.domain)>`,
		`" onmouseover=prompt(document.domain) x="`,
		`';prompt(document.domain)//`,
		" `${prompt(document.domain)}` ",
		`javascript:prompt(document.domain)`,
	}

	for _, p := range payloads {
		method := "GET"
		headers := make(map[string]string)
		body := ""
		finalURL := targetURL

		u, err := url.Parse(targetURL)
		if err != nil { continue }

		switch phase {
		case "get":
			q := u.Query()
			q.Set(name, p)
			u.RawQuery = q.Encode()
			finalURL = u.String()
		case "header":
			headers[name] = p
		case "json":
			method = "POST"
			data := make(map[string]interface{})
			// If we could parse original body, we'd preserve it.
			// For now, we use a simple object as Task 4 asks for unencoded check.
			data[name] = p
			b, _ := json.Marshal(data)
			body = string(b)
		}

		if reflectionExists(finalURL, method, headers, body, p) { return true, p }
	}
	return false, ""
}

func reflectionExists(targetURL, method string, headers map[string]string, body, payload string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	var req *http.Request
	if method == "POST" {
		req, _ = http.NewRequest("POST", targetURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest("GET", targetURL, nil)
	}
	for k, v := range headers { req.Header.Set(k, v) }

	resp, err := client.Do(req)
	if err != nil { return false }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(b), payload)
}

func processURL(targetURL string, index, total int) {
	if _, loaded := workerLock.LoadOrStore(targetURL, true); loaded { return }

	atomic.AddInt64(&processedTargets, 1)
	currProcessed := atomic.LoadInt64(&processedTargets)
	currVulns := atomic.LoadInt64(&vulnerableTargets)

	logLine("TARGET", X_white, "[%d/%d | Vulns: %d] %s", currProcessed, total, currVulns, targetURL)
	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(targetURL, "_")

	report := VulnerabilityReport{URL: targetURL}

	// Phase 2: Canary Probe
	logLine("PHASE", X_cyan, "2/5 Canary Probing...")
	probeInput := filepath.Join(outputDir, safe+"-probe-in.txt")
	os.WriteFile(probeInput, []byte(targetURL), 0644)

	probeOutputBase := filepath.Join(outputDir, safe+"-probe-out")
	runCommand("./x9", "-probe", "-json", "-headers", "-dom", "-i", probeInput, "-o", probeOutputBase)

	// Phase 3: Filter Vulnerable Parameters
	logLine("PHASE", X_blue, "3/5 Filtering reflective parameters...")
	probeFiles := map[string]string{
		probeOutputBase + ".get":        "get",
		probeOutputBase + ".json":       "json",
		probeOutputBase + ".header":     "header",
		probeOutputBase + ".dom.canary": "dom",
	}

	p3Findings := make(map[string][]string)

	for pf, phase := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			if phase == "dom" {
				res, _ := runCommand("nuclei", "-l", pf, "-t", "dom_canary.yaml", "-headless", "-silent")
				p3Findings["dom"] = append(p3Findings["dom"], extractURLsFromNuclei(res)...)
			} else {
				res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
				p3Findings[phase] = append(p3Findings[phase], extractURLsFromNuclei(res)...)
			}
		}
	}

	if len(p3Findings) == 0 {
		logLine("INFO", X_gray, "No reflective parameters found.")
		return
	}

	// Phase 4b: Confirmation Triage
	logLine("PHASE", X_yellow, "4b/5 Triage & Context Confirmation...")
	confirmedParams := make(map[string]map[string]bool)
	for p := range p3Findings { confirmedParams[p] = make(map[string]bool) }

	for phase, urls := range p3Findings {
		if phase == "dom" { continue }
		tempRep := VulnerabilityReport{URL: targetURL}
		dummy := ""
		for _, u := range urls { dummy += "[canary] [info] " + u + " [x9canary]\n" }
		tempRep.aggregateFindings(dummy, phase)

		var vList *[]Vulnerability
		switch phase {
		case "get": vList = &tempRep.QueryParameters
		case "header": vList = &tempRep.Headers
		case "json": vList = &tempRep.JSONBody
		}

		if vList != nil {
			for _, v := range *vList {
				if ok, p := confirmParameter(targetURL, phase, v.Name); ok {
					v.Confirmed = true
					v.Severity = "confirmed"
					v.Payloads = []string{p}
					confirmedParams[phase][v.Name] = true
					switch phase {
					case "get": report.QueryParameters = append(report.QueryParameters, v)
					case "header": report.Headers = append(report.Headers, v)
					case "json": report.JSONBody = append(report.JSONBody, v)
					}
					logLine("CONFIRM", X_green, "Confirmed XSS (%s): %s (param: %s)", phase, targetURL, v.Name)
				}
			}
		}
	}

	// Phase 4: Heavy Attack (Exclude Confirmed)
	logLine("PHASE", X_purple, "4/5 Executing Heavy Attacks...")

	httpAtkUrls := []string{}
	for phase, urls := range p3Findings {
		if phase == "dom" { continue }
		for _, u := range urls {
			uDecoded, _ := url.QueryUnescape(u)
			isConfirmed := false
			for name := range confirmedParams[phase] {
				if strings.Contains(uDecoded, name+"=") || strings.Contains(uDecoded, name+":") || strings.Contains(uDecoded, "\""+name+"\"") {
					isConfirmed = true
					break
				}
			}
			if !isConfirmed { httpAtkUrls = append(httpAtkUrls, u) }
		}
	}

	if len(httpAtkUrls) > 0 {
		atkIn := filepath.Join(outputDir, safe+"-http-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(httpAtkUrls), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-http")
		runCommand("./x9", "-i", atkIn, "-json", "-headers", "-o", finalX9Base)

		exts := map[string]string{".get": "get", ".json": "json", ".header": "header"}
		for ext, ph := range exts {
			if findings, _ := runCommand("nuclei", "-l", finalX9Base+ext, "-t", nucleiTemplate, "-silent"); findings != "" {
				report.aggregateFindings(findings, ph)
			}
		}
	}

	if len(p3Findings["dom"]) > 0 {
		atkIn := filepath.Join(outputDir, safe+"-dom-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(p3Findings["dom"]), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-dom")
		runCommand("./x9", "-i", atkIn, "-dom", "-o", finalX9Base)

		if dom, _ := runCommand("nuclei", "-l", finalX9Base+".dom.attack", "-t", domTemplate, "-headless", "-silent", "-timeout", "300"); dom != "" {
			report.aggregateFindings(dom, "dom")
		}
	}

	if report.HasVulns() { tg.notify(report) }
}

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		u, err := url.Parse(entry)
		if err != nil {
			if !keys[entry] { keys[entry] = true; list = append(list, entry) }
			continue
		}
		if u.Path == "/" { u.Path = "" }
		normalized := u.String()
		if !keys[normalized] { keys[normalized] = true; list = append(list, entry) }
	}
	return list
}

func main() {
	urlFile := flag.String("l", "", "URL list file")
	singleURL := flag.String("u", "", "Single target URL")
	flag.StringVar(&outputDir, "o", "./output", "Output directory")
	flag.StringVar(&nucleiTemplate, "t", "xss_template_v2.yaml", "Reflection template")
	flag.StringVar(&domTemplate, "dom", "dom_xss.yaml", "DOM template")
	flag.StringVar(&canaryTemplate, "canary", "canary_matcher.yaml", "Canary template")
	flag.StringVar(&paramFile, "p", "", "Parameter file")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency")
	flag.IntVar(&workers, "w", 3, "Parallel workers")
	flag.Parse()

	if _, err := exec.LookPath("nuclei"); err == nil {
		nucleiExists = true
	} else {
		logLine("WARN", X_yellow, "Nuclei not found in PATH. Skipping nuclei phases.")
	}

	loadEnv()
	tg = newTelegram()
	os.MkdirAll(outputDir, 0755)

	var urls []string
	if *singleURL != "" {
		urls = append(urls, *singleURL)
	}

	if *urlFile == "-" {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" { urls = append(urls, u) }
		}
	} else if *urlFile != "" {
		file, _ := os.Open(*urlFile)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" { urls = append(urls, u) }
		}
		file.Close()
	}

	if len(urls) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	urls = uniqueStrings(urls)

	// Issue 4: Filter out localhost and non-matching hosts in single-target mode
	if *singleURL != "" {
		uTarget, _ := url.Parse(*singleURL)
		if uTarget != nil {
			var filtered []string
			for _, u := range urls {
				parsed, err := url.Parse(u)
				if err == nil && parsed.Host == uTarget.Host {
					filtered = append(filtered, u)
				}
			}
			urls = filtered
		}
	}

	allCrawledURLs = append(allCrawledURLs, urls...)

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

	logLine("PHASE", X_white, "5/5 Final Second-Order Check...")
	finalIn := filepath.Join(outputDir, "all_crawled_discovery.txt")
	os.WriteFile(finalIn, []byte(strings.Join(uniqueStrings(allCrawledURLs), "\n")), 0644)
	if so, _ := runCommand("nuclei", "-l", finalIn, "-t", nucleiTemplate, "-silent"); so != "" {
		soReport := VulnerabilityReport{URL: "Global Second-Order Check"}
		soReport.aggregateFindings(so, "get")
		if soReport.HasVulns() { tg.notify(soReport) }
	}
	fmt.Printf("\n%s[DONE]%s Pipeline Complete.\n", X_green, X_reset)
}
