// pkg/spadetect/spadetect.go
package spadetect

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"reconpipeline/pkg/ratelimit"
)

// IsSPA performs a lightweight GET and checks for SPA markers,
// page-structure and visible-text heuristics.
//
// The classification itself lives in AnalyzeSPA (pure function, unit-tested
// with HTML fixtures); IsSPA only fetches the page and hands over the body +
// the x-powered-by header.
func IsSPA(targetURL string) bool {
	ratelimit.Acquire(targetURL)
	client := ratelimit.GetHTTPClient(targetURL)
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

	return AnalyzeSPA(string(bodyBytes), resp.Header.Get("x-powered-by"))
}

// ── Classification (pure, testable) ──────────────────────────────────────────

// spaMarkers are strong, independent SPA signals. Any single marker is
// sufficient on its own: a page that carries one of these is a client-side
// rendered app regardless of how much visible text it has.
var spaMarkers = []string{
	`<div id="root"`,
	`<div id="app"`,
	`__NEXT_DATA__`,
	`window.__INITIAL_STATE__`,
	`ReactDOM.render`,
	`ng-version=`,
	`data-reactroot`,
}

var (
	reScript = regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`)
	reStyle  = regexp.MustCompile(`(?s)<style[^>]*>.*?</style>`)
	reTag    = regexp.MustCompile(`<[^>]*>`)
	reForm   = regexp.MustCompile(`(?i)<form[\s>]`)
	reLink   = regexp.MustCompile(`(?i)<a\s[^>]*href`)
)

const (
	// lowVisibleTextThreshold: below this many visible non-space characters
	// the page is "text-light". This is a WEAK signal on its own — countless
	// ordinary login/landing/error pages are text-light — so it may only be
	// used in conjunction with a corroborating signal (see AnalyzeSPA).
	lowVisibleTextThreshold = 500

	// Empty-app-shell thresholds: a text-light page with no <form> elements
	// and almost no static <a href> links looks like an empty shell waiting
	// for JS to render, not like a real (small) server-rendered page.
	// webapp.nozbe.com's login page (2 forms, 3 links) must NOT match this.
	emptyShellMaxLinks = 2
)

// AnalyzeSPA classifies a page as a single-page application from its HTML
// body and x-powered-by header.
//
// Decision rules (in order):
//
//  1. Any known SPA/framework marker (div#root, div#app, __NEXT_DATA__,
//     __INITIAL_STATE__, ReactDOM.render, ng-version=, data-reactroot) →
//     SPA. These stay independent, sufficient conditions.
//
//  2. Low visible text (< lowVisibleTextThreshold) AND a corroborating
//     signal → SPA. Low text alone is NO LONGER sufficient (Bug 2: it
//     misclassified ordinary short server-rendered pages — login forms,
//     error pages, interstitials — as SPA, which caused the caller to skip
//     katana crawling entirely). Corroborating signals:
//       a. x-powered-by mentions next.js or express; or
//       b. the page looks like an empty app shell: zero <form> elements
//          AND at most emptyShellMaxLinks static <a href> links.
//
//  3. Otherwise → not SPA.
func AnalyzeSPA(body, xPoweredBy string) bool {
	for _, m := range spaMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}

	visibleCount := countVisibleText(body)
	if visibleCount >= lowVisibleTextThreshold {
		return false
	}

	// Text-light page: require a corroborating signal before calling it SPA.
	xpb := strings.ToLower(xPoweredBy)
	if strings.Contains(xpb, "next.js") || strings.Contains(xpb, "express") {
		return true
	}

	formCount := len(reForm.FindAllString(body, -1))
	linkCount := len(reLink.FindAllString(body, -1))
	if formCount == 0 && linkCount <= emptyShellMaxLinks {
		return true
	}

	return false
}

// countVisibleText counts non-whitespace characters of the page's visible
// text: <script> and <style> contents are stripped first, then remaining
// tags are removed.
func countVisibleText(body string) int {
	clean := reScript.ReplaceAllString(body, "")
	clean = reStyle.ReplaceAllString(clean, "")
	text := reTag.ReplaceAllString(clean, " ")

	visibleCount := 0
	for _, ch := range text {
		if !unicode.IsSpace(ch) {
			visibleCount++
		}
	}
	return visibleCount
}
