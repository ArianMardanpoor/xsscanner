// FILE: xssniper.go — REFACTORED
// Changes:
// - Scope filter by root domain in main()
// - Added SPA detection with -skip-spa flag
// - Early return in processURL if SPA detected

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
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

type DomSinkOutput struct {
	URL   string   `json:"url"`
	Sinks []string `json:"sinks"`
}

func (r *VulnerabilityReport) HasVulns() bool {
	return len(r.QueryParameters) > 0 || len(r.Headers) > 0 || len(r.JSONBody) > 0 || len(r.DOM) > 0
}

func redactX9(s string) string {
	return reX9.ReplaceAllString(s, "x9")
}

func (r *VulnerabilityReport) processDomJson(domOut DomSinkOutput, phase string) {
	u, err := url.Parse(domOut.URL)
	if err != nil {
		return
	}

	name := "unknown"
	logLine("DEBUG", X_gray, "DOM parse rawURL=%s fragment=%s query=%s", domOut.URL, u.Fragment, u.RawQuery)
	if u.Fragment != "" && strings.Contains(redactX9(u.Fragment), "x9") {
		name = "fragment"
	} else {
		for k, v := range u.Query() {
			val, _ := url.QueryUnescape(strings.Join(v, ""))
			logLine("DEBUG", X_gray, "DOM checking param=%s val=%s redacted=%s", k, val, redactX9(val))
			if strings.Contains(redactX9(val), "x9") {
				name = k
				break
			}
		}
	}

	if name == "unknown" {
		return
	}

	if !isInScope(r.URL, domOut.URL) {
		return
	}

	severity := "likely"
	confirmed := false
	note := ""
	if phase == "dom_confirmed" {
		severity = "confirmed"
		confirmed = true

		canary := ""
		if m := reX9.FindString(domOut.URL); m != "" {
			canary = m
		}

		if canary != "" && u.Fragment != "" {
			if !reflectionExists(domOut.URL, "GET", nil, "", canary) {
				severity = "possible"
				confirmed = false
				note = " (Note: No HTTP reflection, possible false positive)"
				logLine("DEBUG", X_yellow, "Downgrading DOM XSS for %s: No HTTP reflection", domOut.URL)
			}
		}
	}

	found := false
	for i, v := range r.DOM {
		baseName := strings.Split(v.Name, " (Note:")[0]
		if baseName == name {
			for _, sink := range domOut.Sinks {
				exists := false
				for _, p := range v.Payloads {
					if p == sink {
						exists = true
						break
					}
				}
				if !exists {
					r.DOM[i].Payloads = append(r.DOM[i].Payloads, sink)
				}
			}
			if severityWeight(severity) > severityWeight(v.Severity) {
				logLine("DEBUG", X_gray, "Upgrading DOM param=%s from=%s to=%s", name, v.Severity, severity)
				r.DOM[i].Severity = severity
			}
			if note != "" && !strings.Contains(r.DOM[i].Name, note) {
				r.DOM[i].Name += note
			}
			if confirmed {
				r.DOM[i].Confirmed = true
			}
			found = true
			break
		}
	}

	if !found {
		r.DOM = append(r.DOM, Vulnerability{
			Name:      name + note,
			Severity:  severity,
			Confirmed: confirmed,
			Payloads:  domOut.Sinks,
		})
	}
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

		if (phase == "dom" || phase == "dom_confirmed") && strings.HasPrefix(line, "{") {
			var domOut DomSinkOutput
			if err := json.Unmarshal([]byte(line), &domOut); err == nil {
				r.processDomJson(domOut, phase)
				continue
			}
		}

		payload := ""
		if m := rePayload.FindStringSubmatch(line); len(m) > 0 {
			if m[1] != "" {
				payload = m[1]
			} else {
				payload = m[2]
			}
		}

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

		if !isInScope(r.URL, rawURL) {
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
		case "dom", "dom_confirmed":
			targetList = &r.DOM
			if u, err := url.Parse(rawURL); err == nil {
				logLine("DEBUG", X_gray, "DOM parse rawURL=%s fragment=%s query=%s", rawURL, u.Fragment, u.RawQuery)
				if u.Fragment != "" && strings.Contains(redactX9(u.Fragment), "x9") {
					name = "fragment"
				} else {
					for k, v := range u.Query() {
						val, _ := url.QueryUnescape(strings.Join(v, ""))
						logLine("DEBUG", X_gray, "DOM checking param=%s val=%s redacted=%s", k, val, redactX9(val))
						if strings.Contains(redactX9(val), "x9") {
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
		note := ""
		if phase == "get" {
			severity = "likely"
		} else if phase == "dom" {
			severity = "likely"
		} else if phase == "dom_confirmed" {
			severity = "confirmed"
			phase = "dom"

			canary := ""
			if m := reX9.FindString(rawURL); m != "" {
				canary = m
			}
			if canary != "" {
				if !reflectionExists(targetURL, "GET", nil, "", canary) {
					severity = "possible"
					note = " (Note: No HTTP reflection, possible false positive)"
					logLine("DEBUG", X_yellow, "Downgrading DOM XSS for %s: No HTTP reflection", targetURL)
				}
			}
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
					logLine("DEBUG", X_gray, "Upgrading DOM param=%s from=%s to=%s", name, (*targetList)[i].Severity, severity)
					(*targetList)[i].Severity = severity
				}
				if note != "" && !strings.Contains((*targetList)[i].Name, note) {
					(*targetList)[i].Name += note
				}
				found = true
				break
			}
		}
		if !found {
			newVuln := Vulnerability{Name: name + note, Severity: severity}
			if payload != "" {
				newVuln.Payloads = []string{payload}
			}
			*targetList = append(*targetList, newVuln)
		}
	}
}

func severityWeight(s string) int {
	switch s {
	case "confirmed":
		return 3
	case "likely":
		return 2
	case "possible":
		return 1
	default:
		return 0
	}
}

func verifyReflection(targetURL, method string, headers map[string]string, body, canary string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest("POST", targetURL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req, err = http.NewRequest("GET", targetURL, nil)
	}

	if err != nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
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

func dedupeNucleiFindings(report VulnerabilityReport) string {
	var sb strings.Builder
	renderSection := func(title string, vulns []Vulnerability) {
		if len(vulns) == 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("\n  %s[%s]%s\n", X_cyan, title, X_reset))
		for _, v := range vulns {
			sevColor := X_gray
			switch v.Severity {
			case "confirmed":
				sevColor = X_red + X_bold
			case "likely":
				sevColor = X_yellow
			case "possible":
				sevColor = X_white
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
		if hasHighSeverity {
			break
		}
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
	outputDir            string
	nucleiTemplate       string
	domTemplate          string
	canaryTemplate       string
	paramFile            string
	concurrency          int
	workers              int
	mu                   sync.Mutex
	tg                   *Telegram
	allCrawledURLs       []string
	maxURLsPerTarget     int
	allowWildcards       bool
	processedTargets     int64
	vulnerableTargets    int64
	vulnerableMap        sync.Map
	workerLock           sync.Map
	nucleiExists         bool
	domSinkCheckerExists bool
	skipSPA              bool // NEW: flag to skip SPA detection

	reX9       = regexp.MustCompile(`x9(?:canary)?[a-z]*`)
	rePayload  = regexp.MustCompile(`\[(?:"([^"]+)"|([^"\]]+))\]$`)
	reANSI     = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	reCleaning = regexp.MustCompile(`\s*\["0m"\]\s*`)
)

func logLine(level, color, format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", X_gray, ts, X_reset, color, level, X_reset, fmt.Sprintf(format, args...))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stripANSI(str string) string {
	return reANSI.ReplaceAllString(str, "")
}

func extractRootDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isInScope(targetURL, rawURL string) bool {
	tParsed, errT := url.Parse(targetURL)
	uParsed, errU := url.Parse(rawURL)
	if errT != nil || errU != nil {
		return false
	}

	rootDomain := extractRootDomain(tParsed.Hostname())
	urlDomain := uParsed.Hostname()

	return urlDomain == rootDomain || strings.HasSuffix(urlDomain, "."+rootDomain)
}

func isConcreteURL(rawURL string) bool {
	if allowWildcards {
		return true
	}
	decoded, _ := url.QueryUnescape(rawURL)
	if strings.Contains(decoded, "*") {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	for _, seg := range strings.Split(parsed.Path, "/") {
		decoded, _ := url.QueryUnescape(seg)
		if decoded == "*" {
			return false
		}
	}
	return true
}

func isTargetAlive(targetURL string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	u.Fragment = ""
	checkURL := u.String()

	req, _ := http.NewRequestWithContext(ctx, "HEAD", checkURL, nil)
	resp, err := client.Do(req)

	if err != nil {
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		reqGET, _ := http.NewRequestWithContext(ctx2, "GET", checkURL, nil)
		resp, err = client.Do(reqGET)
		if err != nil {
			return false
		}
	} else {
		defer resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			return true
		}
		if resp.StatusCode >= 404 && resp.StatusCode != 405 {
			return false
		}
		reqGET, _ := http.NewRequestWithContext(ctx, "GET", checkURL, nil)
		resp, err = client.Do(reqGET)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
	}

	return resp.StatusCode < 500
}

func runCommand(name string, args ...string) (string, error) {
	if name == "nuclei" && !nucleiExists {
		return "", nil
	}
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
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

// ── SPA Detection ────────────────────────────────────────────────────────────

func isSPA(targetURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; xssniper)")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	body := string(bodyBytes)

	// 1. Static markers
	markers := []string{
		`<div id="root"`,
		`<div id="app"`,
		`__NEXT_DATA__`,
		`window.__INITIAL_STATE__`,
		`ReactDOM.render`,
		`ng-version=`,
		`data-reactroot`,
	}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}

	// 2. Visible text length (strip script/style tags)
	reScript := regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`)
	reStyle := regexp.MustCompile(`(?s)<style[^>]*>.*?</style>`)
	clean := reScript.ReplaceAllString(body, "")
	clean = reStyle.ReplaceAllString(clean, "")
	reTag := regexp.MustCompile(`<[^>]*>`)
	text := reTag.ReplaceAllString(clean, " ")
	visibleCount := 0
	for _, ch := range text {
		if !unicode.IsSpace(ch) {
			visibleCount++
		}
	}
	if visibleCount < 500 {
		return true
	}

	// 3. Headers + near‑empty body (already checked visibleCount<500)
	xPoweredBy := resp.Header.Get("x-powered-by")
	if strings.Contains(strings.ToLower(xPoweredBy), "next.js") && visibleCount < 500 {
		return true
	}
	if strings.Contains(strings.ToLower(xPoweredBy), "express") && visibleCount < 500 {
		return true
	}

	return false
}

// ── Core Logic ────────────────────────────────────────────────────────────────

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func confirmParameter(targetURL, phase, name string) (bool, []string) {
	prefix := "x9" + randomString(3)
	breakChars := []string{"'", "\"", "`", "<", ";", "{{"}
	var confirmed []string

	for _, bc := range breakChars {
		p := prefix + bc
		method := "GET"
		headers := make(map[string]string)
		body := ""
		finalURL := targetURL

		u, err := url.Parse(targetURL)
		if err != nil {
			continue
		}

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
			data[name] = p
			b, _ := json.Marshal(data)
			body = string(b)
		}

		if reflectionExists(finalURL, method, headers, body, p) {
			confirmed = append(confirmed, p)
		}
	}
	return len(confirmed) > 0, confirmed
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
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(b), payload)
}

// checkHeaderReflection performs a GET request with the given header and checks if the value is reflected.
func checkHeaderReflection(targetURL, headerName, headerValue string) bool {
	headers := map[string]string{headerName: headerValue}
	return reflectionExists(targetURL, "GET", headers, "", headerValue)
}

func processURL(targetURL string, index, total int) {
	uParsed, err := url.Parse(targetURL)
	normalizedLockURL := targetURL
	if err == nil {
		uParsed.Path = strings.TrimSuffix(uParsed.Path, "/")
		if strings.HasSuffix(uParsed.Path, "/index.php") {
			uParsed.Path = strings.TrimSuffix(uParsed.Path, "/index.php")
		}
		if strings.HasSuffix(uParsed.Path, "/index.html") {
			uParsed.Path = strings.TrimSuffix(uParsed.Path, "/index.html")
		}
		normalizedLockURL = uParsed.String()
	}

	if _, loaded := workerLock.LoadOrStore(normalizedLockURL, true); loaded {
		return
	}

	atomic.AddInt64(&processedTargets, 1)
	currProcessed := atomic.LoadInt64(&processedTargets)
	currVulns := atomic.LoadInt64(&vulnerableTargets)

	logLine("TARGET", X_white, "[%d/%d | Vulns: %d] %s", currProcessed, total, currVulns, targetURL)

	// ── SPA DETECTION (NEW) ──
	if !skipSPA && isSPA(targetURL) {
		logLine("SKIP", X_yellow, "SPA/React detected, skipping heavy scan for %s", targetURL)
		return
	}

	report := VulnerabilityReport{URL: targetURL}

	// Phase 2: Canary Probe
	logLine("PHASE", X_cyan, "2/5 Canary Probing...")
	probeInput := filepath.Join(outputDir, safe+"-probe-in.txt")
	os.WriteFile(probeInput, []byte(targetURL), 0644)

	probeOutputBase := filepath.Join(outputDir, safe+"-probe-out")
	runCommand("./x9", "-probe", "-json", "-headers", "-dom", "-i", probeInput, "-o", probeOutputBase)

	// Phase 2: Canary Probing - DOM query params
	logLine("PHASE", X_cyan, "2/5 Canary Probing (DOM query params)...")
	domQueryProbeFile := filepath.Join(outputDir, safe+"-dom-query-probe.txt")
	paramsToProbe := []string{}
	if paramFile != "" {
		if pf, err := os.Open(paramFile); err == nil {
			scanner := bufio.NewScanner(pf)
			for scanner.Scan() {
				if p := strings.TrimSpace(scanner.Text()); p != "" {
					paramsToProbe = append(paramsToProbe, p)
				}
			}
			pf.Close()
		}
	}
	if len(paramsToProbe) == 0 {
		paramsToProbe = []string{
			"q", "s", "search", "id", "url", "redirect", "next", "return",
			"callback", "code", "token", "data", "input", "value", "text",
			"name", "message", "template", "write", "timeout", "src", "frame",
			"href", "goto", "dest", "destination", "target",
		}
	}

	if len(paramsToProbe) > 0 {
		var domProbeURLs []string
		for _, param := range paramsToProbe {
			canary := "x9canary" + randomString(3)
			u, err := url.Parse(targetURL)
			if err != nil {
				continue
			}
			q := u.Query()
			q.Set(param, canary)
			u.RawQuery = q.Encode()
			domProbeURLs = append(domProbeURLs, u.String())
		}
		if len(domProbeURLs) > 0 {
			os.WriteFile(domQueryProbeFile, []byte(strings.Join(domProbeURLs, "\n")), 0644)
		}
	}

	// Phase 3: Filter Vulnerable Parameters
	logLine("PHASE", X_blue, "3/5 Filtering reflective parameters...")

	targetAlive := isTargetAlive(targetURL)

	probeFiles := map[string]string{
		probeOutputBase + ".get":        "get",
		probeOutputBase + ".json":       "json",
		probeOutputBase + ".header":     "header",
		probeOutputBase + ".dom.canary": "dom",
	}

	p3Findings := make(map[string][]string)
	candidateHeaders := []string{} // new: store header names that reflect canary

	for pf, phase := range probeFiles {
		if _, err := os.Stat(pf); err == nil {
			if phase == "dom" {
				if !targetAlive {
					logLine("DEBUG", X_gray, "Target dead, skipping DOM canary for %s", targetURL)
					continue
				}

				content, _ := os.ReadFile(pf)
				lines := strings.Split(strings.TrimSpace(string(content)), "\n")
				lineCount := 0
				if len(lines) > 0 && lines[0] != "" {
					lineCount = len(lines)
					logLine("DEBUG", X_gray, "First %d lines of %s:", min(3, lineCount), pf)
					for i := 0; i < min(3, lineCount); i++ {
						logLine("DEBUG", X_gray, "  %s", lines[i])
					}
				}
				logLine("DEBUG", X_gray, "DOM Canary file %s has %d lines", pf, lineCount)

				if domSinkCheckerExists {
					logLine("DEBUG", X_gray, "Invoking: ./dom_sink_checker -l %s", pf)
					res, _ := runCommand("./dom_sink_checker", "-l", pf)
					logLine("DEBUG", X_gray, "Raw dom_sink_checker output for %s:\n%s", pf, res)
					if res != "" {
						lines := strings.Split(strings.TrimSpace(res), "\n")
						for _, l := range lines {
							l = strings.TrimSpace(l)
							var probe DomSinkOutput
							if err := json.Unmarshal([]byte(l), &probe); err == nil && probe.URL != "" {
								p3Findings["dom"] = append(p3Findings["dom"], l)
							}
						}
					}
				}
			} else if phase == "header" {
				// ---- NEW: Handle header canary directly without nuclei ----
				file, err := os.Open(pf)
				if err != nil {
					continue
				}
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					// Expected format: url|HeaderName:value
					parts := strings.SplitN(line, "|", 2)
					if len(parts) != 2 {
						continue
					}
					urlPart := parts[0]
					headerPart := parts[1]
					headerParts := strings.SplitN(headerPart, ":", 2)
					if len(headerParts) != 2 {
						continue
					}
					headerName := strings.TrimSpace(headerParts[0])
					headerValue := strings.TrimSpace(headerParts[1])

					// Check if the canary is reflected
					if checkHeaderReflection(urlPart, headerName, headerValue) {
						// Add to candidateHeaders (dedupe)
						found := false
						for _, h := range candidateHeaders {
							if h == headerName {
								found = true
								break
							}
						}
						if !found {
							candidateHeaders = append(candidateHeaders, headerName)
							logLine("DEBUG", X_gray, "Found reflective header: %s", headerName)
						}
					}
				}
				file.Close()
				// Do not add to p3Findings
			} else {
				// GET and JSON: use nuclei
				res, _ := runCommand("nuclei", "-l", pf, "-t", canaryTemplate, "-silent")
				p3Findings[phase] = append(p3Findings[phase], extractURLsFromNuclei(res)...)
			}
		}
	}

	// DOM query probe
	if _, err := os.Stat(domQueryProbeFile); err == nil {
		if !targetAlive {
			logLine("DEBUG", X_gray, "Target dead, skipping DOM query probe for %s", targetURL)
		} else if domSinkCheckerExists {
			lineCount := countLines(domQueryProbeFile)
			logLine("DEBUG", X_gray, "DOM Query probe file has %d lines", lineCount)

			logLine("DEBUG", X_gray, "Invoking: ./dom_sink_checker -l %s", domQueryProbeFile)

			res, _ := runCommand("./dom_sink_checker", "-l", domQueryProbeFile)
			logLine("DEBUG", X_gray, "Raw dom_sink_checker output for %s:\n%s", domQueryProbeFile, res)

			if res != "" {
				lines := strings.Split(strings.TrimSpace(res), "\n")
				for _, l := range lines {
					l = strings.TrimSpace(l)
					var probe DomSinkOutput
					if err := json.Unmarshal([]byte(l), &probe); err == nil && probe.URL != "" {
						p3Findings["dom"] = append(p3Findings["dom"], l)
					}
				}
			}
		}
	}

	// If no findings at all (including header candidates), return
	if len(p3Findings) == 0 && len(candidateHeaders) == 0 {
		logLine("INFO", X_gray, "No reflective parameters found.")
		return
	}

	// Phase 4b: Triage & Context Confirmation
	logLine("PHASE", X_yellow, "4b/5 Triage & Context Confirmation...")
	confirmedParams := make(map[string]map[string]bool)
	for p := range p3Findings {
		confirmedParams[p] = make(map[string]bool)
	}

	// Confirm non-header parameters (get, json, dom) as before
	for phase, urls := range p3Findings {
		if phase == "dom" {
			continue
		}
		tempRep := VulnerabilityReport{URL: targetURL}
		dummy := ""
		for _, u := range urls {
			dummy += "[canary] [info] " + u + " [x9canary]\n"
		}
		tempRep.aggregateFindings(dummy, phase)

		var vList *[]Vulnerability
		switch phase {
		case "get":
			vList = &tempRep.QueryParameters
		case "json":
			vList = &tempRep.JSONBody
		}

		if vList != nil {
			for _, v := range *vList {
				if ok, p := confirmParameter(targetURL, phase, v.Name); ok {
					v.Confirmed = true
					v.Severity = "confirmed"
					v.Payloads = p
					confirmedParams[phase][v.Name] = true
					switch phase {
					case "get":
						report.QueryParameters = append(report.QueryParameters, v)
					case "json":
						report.JSONBody = append(report.JSONBody, v)
					}
					logLine("CONFIRM", X_green, "Confirmed XSS (%s): %s (param: %s)", phase, targetURL, v.Name)
				}
			}
		}
	}

	// ---- NEW: Confirm header candidates ----
	for _, headerName := range candidateHeaders {
		if ok, payloads := confirmParameter(targetURL, "header", headerName); ok {
			v := Vulnerability{
				Name:      headerName,
				Severity:  "confirmed",
				Confirmed: true,
				Payloads:  payloads,
			}
			report.Headers = append(report.Headers, v)
			// Store in confirmedParams for later skipping in attack phase
			if confirmedParams["header"] == nil {
				confirmedParams["header"] = make(map[string]bool)
			}
			confirmedParams["header"][headerName] = true
			logLine("CONFIRM", X_green, "Confirmed XSS (header): %s (header: %s)", targetURL, headerName)
		}
	}

	// Phase 4: Heavy Attack (Exclude Confirmed)
	logLine("PHASE", X_purple, "4/5 Executing Heavy Attacks...")

	httpAtkUrls := []string{}
	for phase, urls := range p3Findings {
		if phase == "dom" {
			continue
		}
		for _, u := range urls {
			uParsedAtk, _ := url.Parse(u)
			if uParsedAtk == nil {
				continue
			}
			isConfirmed := false

			query := uParsedAtk.Query()
			for name := range confirmedParams[phase] {
				switch phase {
				case "get":
					if _, exists := query[name]; exists {
						isConfirmed = true
					}
				case "json":
					if strings.Contains(u, "\""+name+"\"") {
						isConfirmed = true
					}
				}
				if isConfirmed {
					break
				}
			}
			if !isConfirmed && isInScope(targetURL, u) && isConcreteURL(u) {
				httpAtkUrls = append(httpAtkUrls, u)
			}
		}
	}

	if len(httpAtkUrls) > 0 {
		atkIn := filepath.Join(outputDir, safe+"-http-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(httpAtkUrls), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-http")
		runCommand("./x9", "-i", atkIn, "-json", "-headers", "-o", finalX9Base)

		exts := map[string]string{".get": "get", ".json": "json"}
		for ext, ph := range exts {
			if findings, _ := runCommand("nuclei", "-l", finalX9Base+ext, "-t", nucleiTemplate, "-silent"); findings != "" {
				report.aggregateFindings(findings, ph)
			}
		}

		// ---- NEW: Handle header attack directly ----
		headerAtkFile := finalX9Base + ".header"
		if _, err := os.Stat(headerAtkFile); err == nil {
			file, err := os.Open(headerAtkFile)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					parts := strings.SplitN(line, "|", 2)
					if len(parts) != 2 {
						continue
					}
					urlPart := parts[0]
					headerPart := parts[1]
					headerParts := strings.SplitN(headerPart, ":", 2)
					if len(headerParts) != 2 {
						continue
					}
					headerName := strings.TrimSpace(headerParts[0])
					headerValue := strings.TrimSpace(headerParts[1])

					// Skip if already confirmed
					if confirmedParams["header"] != nil && confirmedParams["header"][headerName] {
						continue
					}

					// Check reflection
					if checkHeaderReflection(urlPart, headerName, headerValue) {
						// Add to report.Headers (if not already)
						found := false
						for i, v := range report.Headers {
							if v.Name == headerName {
								// Add payload if not present
								exists := false
								for _, p := range v.Payloads {
									if p == headerValue {
										exists = true
										break
									}
								}
								if !exists {
									report.Headers[i].Payloads = append(report.Headers[i].Payloads, headerValue)
								}
								found = true
								break
							}
						}
						if !found {
							report.Headers = append(report.Headers, Vulnerability{
								Name:     headerName,
								Severity: "likely",
								Payloads: []string{headerValue},
							})
						}
						logLine("FIND", X_green, "Found header reflection: %s = %s", headerName, headerValue)
					}
				}
				file.Close()
			}
		}
	}

	// Phase 4 DOM: only fragment URLs
	var fragmentURLs []string
	for _, line := range p3Findings["dom"] {
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		parsed, err := url.Parse(domOut.URL)
		if err == nil && parsed.Fragment != "" && isInScope(targetURL, domOut.URL) && isConcreteURL(domOut.URL) {
			fragmentURLs = append(fragmentURLs, domOut.URL)
		}
	}
	if len(fragmentURLs) > 0 {
		atkIn := filepath.Join(outputDir, safe+"-dom-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(fragmentURLs), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-dom")
		runCommand("./x9", "-i", atkIn, "-dom", "-o", finalX9Base)
		if domSinkCheckerExists {
			if dom, _ := runCommand("./dom_sink_checker", "-xss", "-l", finalX9Base+".dom.attack", "-timeout", "300"); dom != "" {
				report.aggregateFindings(dom, "dom_confirmed")
			}
		}
	}
	// Add DOM canary findings to report as "likely" before Phase 4c
	logLine("DEBUG", X_gray, "canary pre-loop: p3Findings dom len=%d", len(p3Findings["dom"]))
	for _, line := range p3Findings["dom"] {
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		report.processDomJson(domOut, "dom")
	}

	// Phase 4c: DOM Query Attack (only query param URLs, no fragments)
	var domQueryURLs []string
	for _, line := range p3Findings["dom"] {
		var domOut DomSinkOutput
		if err := json.Unmarshal([]byte(line), &domOut); err != nil {
			continue
		}
		parsed, err := url.Parse(domOut.URL)
		if err == nil && parsed.Fragment == "" && isInScope(targetURL, domOut.URL) && isConcreteURL(domOut.URL) {
			domQueryURLs = append(domQueryURLs, domOut.URL)
		}
	}
	if len(domQueryURLs) > 0 {
		logLine("PHASE", X_purple, "4c/5 Executing DOM Query Attacks...")
		atkIn := filepath.Join(outputDir, safe+"-dom-query-atk-in.txt")
		os.WriteFile(atkIn, []byte(strings.Join(dedupeConfirmedURLs(domQueryURLs), "\n")), 0644)
		finalX9Base := filepath.Join(outputDir, safe+"-final-dom-query")
		runCommand("./x9", "-i", atkIn, "-o", finalX9Base)
		if domSinkCheckerExists {
			dom, _ := runCommand("./dom_sink_checker", "-xss", "-l", finalX9Base+".get", "-timeout", "300")
			if dom != "" {
				report.aggregateFindings(dom, "dom_confirmed")
			}
		}
	}

	if report.HasVulns() {
		tg.notify(report)
	}
}

// ── Helper: safe name for file naming ──────────────────────────────────────

var safeNameRe = regexp.MustCompile(`[^a-zA-Z0-9]`)

func safeName(s string) string {
	return safeNameRe.ReplaceAllString(s, "_")
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
		u.Path = strings.TrimSuffix(u.Path, "/")
		if strings.HasSuffix(u.Path, "/index.php") {
			u.Path = strings.TrimSuffix(u.Path, "/index.php")
		}
		if strings.HasSuffix(u.Path, "/index.html") {
			u.Path = strings.TrimSuffix(u.Path, "/index.html")
		}

		normalized := u.String()
		if !keys[normalized] {
			keys[normalized] = true
			list = append(list, entry)
		}
	}
	return list
}

func countLines(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

// ── main ────────────────────────────────────────────────────────────────────

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
	flag.IntVar(&maxURLsPerTarget, "max-urls", 50, "Max URLs per target")
	flag.BoolVar(&allowWildcards, "allow-wildcards", false, "Allow wildcard URLs")
	flag.BoolVar(&skipSPA, "skip-spa", true, "Skip SPA detection (if true, do not check for SPA)")
	flag.Parse()

	if _, err := exec.LookPath("nuclei"); err == nil {
		nucleiExists = true
	} else {
		logLine("WARN", X_yellow, "Nuclei not found in PATH. Skipping nuclei phases.")
	}

	if _, err := exec.LookPath("./dom_sink_checker"); err == nil {
		domSinkCheckerExists = true
		logLine("INFO", X_green, "dom_sink_checker confirmed")
	} else {
		logLine("WARN", X_yellow, "dom_sink_checker not found or not executable — DOM phases will be skipped")
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
			if u := strings.TrimSpace(scanner.Text()); u != "" {
				urls = append(urls, u)
			}
		}
	} else if *urlFile != "" {
		file, _ := os.Open(*urlFile)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" {
				urls = append(urls, u)
			}
		}
		file.Close()
	}

	if len(urls) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	urls = uniqueStrings(urls)

	var concreteURLs []string
	for _, u := range urls {
		if isConcreteURL(u) {
			concreteURLs = append(concreteURLs, u)
		}
	}
	urls = concreteURLs

	// ── FIX BUG 1: Scope filter by root domain (unconditional) ──
	if *singleURL != "" {
		uTarget, _ := url.Parse(*singleURL)
		if uTarget != nil {
			rootDomain := extractRootDomain(uTarget.Hostname())
			var filtered []string
			for _, u := range urls {
				parsed, err := url.Parse(u)
				if err != nil {
					continue
				}
				host := parsed.Hostname()
				if host == rootDomain || strings.HasSuffix(host, "."+rootDomain) {
					filtered = append(filtered, u)
				}
			}
			urls = filtered
		}
	}

	groups := make(map[string][]string)
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		root := extractRootDomain(parsed.Hostname())
		groups[root] = append(groups[root], u)
	}

	var finalURLs []string
	for _, groupUrls := range groups {
		sort.Slice(groupUrls, func(i, j int) bool {
			pi, _ := url.Parse(groupUrls[i])
			pj, _ := url.Parse(groupUrls[j])
			hasQi := pi != nil && len(pi.RawQuery) > 0
			hasQj := pj != nil && len(pj.RawQuery) > 0
			if hasQi != hasQj {
				return hasQi
			}
			return len(groupUrls[i]) < len(groupUrls[j])
		})

		if maxURLsPerTarget > 0 && len(groupUrls) > maxURLsPerTarget {
			groupUrls = groupUrls[:maxURLsPerTarget]
		}
		finalURLs = append(finalURLs, groupUrls...)
	}
	urls = finalURLs

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
		if soReport.HasVulns() {
			tg.notify(soReport)
		}
	}
	fmt.Printf("\n%s[DONE]%s Pipeline Complete.\n", X_green, X_reset)
}
