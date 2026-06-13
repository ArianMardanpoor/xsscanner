package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// ============================================
// آمار خروجی
// ============================================

type Stats struct {
	TotalURLs  int
	ByStrategy map[string]int
	ByBase     map[string]int
}

func newStats() *Stats {
	return &Stats{
		ByStrategy: make(map[string]int),
		ByBase:     make(map[string]int),
	}
}

// ============================================
// ۱. لیست پیش‌فرض پارامترها و هدرها
// ============================================

var defaultParams = []string{
	"q", "s", "search", "id", "lang", "keyword", "query", "page",
	"keywords", "year", "view", "email", "type", "name", "p", "month",
	"image", "list_type", "url", "terms", "categoryid", "key", "login",
	"begindate", "enddate", "d", "redirect_uri", "currentURL", "callback",
	"debug", "test", "redirect", "src", "source", "file", "path",
}

var targetHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"Origin",
	"X-Real-IP",
	"Client-IP",
}

// ============================================
// ۲. تابع تولید رشته رندوم
// ============================================

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// ============================================
// ۳. Payload های جدید (بر پایه Break)
// ============================================

func getBreakPayloads() []string {
	prefix := "x9" + randomString(3)
	return []string{
		prefix + "'",
		prefix + "\"",
		prefix + "`",
		prefix + "\\'",
		prefix + "<",
		prefix + ";",
		prefix + "{{",
	}
}

// ============================================
// ۴. ساختار URL تجزیه‌شده
// ============================================

type ParsedURL struct {
	Scheme   string
	Host     string
	Path     string
	RawQuery string
	Fragment string
	Params   map[string]string
}

// ============================================
// ۵. توابع کمکی
// ============================================

func parseURL(rawURL string) (*ParsedURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	parsed := &ParsedURL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
		Params:   make(map[string]string),
	}
	for k, v := range u.Query() {
		parsed.Params[k] = v[0]
	}
	return parsed, nil
}

func buildURL(base *ParsedURL, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(params[k]))
	}
	u := &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     base.Path,
		RawQuery: strings.Join(parts, "&"),
		Fragment: base.Fragment,
	}
	return u.String()
}

func getAllParams(originalParams map[string]string, paramFile string) []string {
	allParamsMap := make(map[string]bool)
	for k := range originalParams {
		allParamsMap[k] = true
	}
	for _, p := range defaultParams {
		allParamsMap[p] = true
	}
	if paramFile != "" {
		file, err := os.Open(paramFile)
		if err == nil {
			sc := bufio.NewScanner(file)
			for sc.Scan() {
				p := strings.TrimSpace(sc.Text())
				if p != "" {
					allParamsMap[p] = true
				}
			}
			file.Close()
		}
	}
	result := make([]string, 0, len(allParamsMap))
	for p := range allParamsMap {
		result = append(result, p)
	}
	sort.Strings(result)
	return result
}

// ============================================
// ۶. تولید خروجی‌های JSON و Header
// ============================================

func main() {
	rand.Seed(time.Now().UnixNano())

	var (
		inputFile  string
		paramFile  string
		outputFile string
		singleURL  string
		probeMode  bool
		jsonMode   bool
		headerMode bool
	)

	flag.StringVar(&inputFile, "i", "", "File containing URLs")
	flag.StringVar(&singleURL, "u", "", "Single URL to test")
	flag.StringVar(&paramFile, "p", "", "Custom parameters file")
	flag.StringVar(&outputFile, "o", "x9_output.txt", "Output file")
	flag.BoolVar(&probeMode, "probe", false, "Enable canary probe mode")
	flag.BoolVar(&jsonMode, "json", false, "Enable JSON body generation")
	flag.BoolVar(&headerMode, "headers", false, "Enable Header injection mode")
	flag.Parse()

	if inputFile == "" && singleURL == "" {
		flag.Usage()
		os.Exit(1)
	}

	var rawURLs []string
	if singleURL != "" {
		rawURLs = append(rawURLs, singleURL)
	}
	if inputFile != "" {
		file, _ := os.Open(inputFile)
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				rawURLs = append(rawURLs, line)
			}
		}
		file.Close()
	}

	f, _ := os.Create(outputFile)
	defer f.Close()

	for _, raw := range rawURLs {
		base, err := parseURL(raw)
		if err != nil {
			continue
		}

		payloads := getBreakPayloads()
		if probeMode {
			payloads = []string{"x9canary" + randomString(3)}
		}

		allParams := getAllParams(base.Params, paramFile)

		for _, payload := range payloads {
			// 1. Standard URL Parameters
			for _, p := range allParams {
				newParams := make(map[string]string)
				for k, v := range base.Params {
					newParams[k] = v
				}
				newParams[p] = payload
				fmt.Fprintln(f, buildURL(base, newParams))
			}

			// 2. JSON Body Mode
			if jsonMode {
				jsonData := make(map[string]string)
				for _, p := range allParams {
					jsonData[p] = payload
				}
				jsonStr, _ := json.Marshal(jsonData)
				// Output format: URL|JSON_BODY
				fmt.Fprintf(f, "%s://%s%s|%s\n", base.Scheme, base.Host, base.Path, string(jsonStr))
			}

			// 3. Header Injection Mode
			if headerMode {
				for _, h := range targetHeaders {
					// Output format: URL|HEADER_NAME:HEADER_VALUE
					fmt.Fprintf(f, "%s|%s:%s\n", raw, h, payload)
				}
			}
		}
	}
}
