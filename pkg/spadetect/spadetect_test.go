// pkg/spadetect/spadetect_test.go
//
// Regression tests for the SPA-classification heuristics.
//
// Bug 2 background: IsSPA()'s old `visibleCount < 500` fallback alone was
// enough to classify ANY short page as an SPA. webapp.nozbe.com's login page
// (a plain server-rendered HTML form with a real reflected XSS in the hidden
// `go_from` field) was misclassified, which caused the callers to skip the
// katana crawl and the xssniper heavy scan entirely. These tests pin:
//   1. the nozbe login page (real HTML, fetched 2026-11-14) → NOT SPA;
//   2. a minimal real SPA (div#root + bundle.js) → SPA;
//   3. marker-based SPA detection stays a sufficient condition on its own;
//   4. low visible text alone is never sufficient;
//   5. the empty-app-shell conjunction (low text + no forms + ~no links)
//      still classifies as SPA;
//   6. the x-powered-by corroboration still works;
//   7. IsSPA() end-to-end (HTTP fetch → classification) wiring.
package spadetect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// nozbeLoginHTML is the exact HTML of https://webapp.nozbe.com/ (fetched
// 2026-11-14): a plain server-rendered login form — no React/Vue/Angular
// markers, no framework-rendered DOM, ~380 visible characters, 2 <form>
// elements, 3 static <a href> links (2 inside an HTML comment, so they do
// NOT count as real links — the regex finds them either way; the forms are
// what keep this page out of the empty-shell branch).
const nozbeLoginHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Nozbe - getting things done gtd software task manager and to-do list for project management and time tracking. Now on Apple iPhone and Mobile Phone!</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="https://img.nozbe.com/img/css/login.css">
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>
    <script type="text/javascript" src="https://js.nozbe.com/js/jquery.placeholder.1.3.min.js"></script>
    <script type="text/javascript" src="https://js.nozbe.com/js/login.js"></script>
    <script type="text/javascript" src="https://use.typekit.com/fzr5xij.js"></script>
    <script type="text/javascript">try{Typekit.load();}catch(e){}</script>
    <meta name="viewport" content="initial-scale = 1.0,maximum-scale = 1.0">
    <style>
        a { color: black; }
    </style>
</head>
<body>
    <form action="https://webapp.nozbe.com/page/login/lang-gtd" method="post" id="boxloginform" class="page_form">
        <h3><span>Account Log-In</span></h3>
        <img class="nozbe_icon" src="https://app.nozbe.com/app/img/logo.c4eec0b1.svg" width="250">
        <p>
            <input type="text" size="40" name="email" id="email" placeholder="Email Address"><br />
            <input type="password" size="40" name="password" id="password" placeholder="Password">
        </p>
        <p>
            <input type="hidden" name="go_from" value="" />
            <input type="submit" id="submit" value="Log me in!">
        </p>
    </form>
    <form action="/page/forget" method="post" id="boxforgetform" class="page_form" style="display:none">
        <h3><span>Forgot your password?</span></h3>
        <p>
            <input type="email" size="40" name="email" id="email" placeholder="Email Address">
        </p>
        <p>
            <input type="submit" id="submit" value="Send me new password!">
        </p>
    </form>
</body>
</html>`

// minimalSPAHTML is a minimal client-rendered app shell: no visible text,
// no forms, no real static links, and the canonical <div id="root"> marker.
const minimalSPAHTML = `<!DOCTYPE html>
<html>
<head><title>App</title></head>
<body>
    <div id="root"></div>
    <script src="/static/js/bundle.js"></script>
</body>
</html>`

// emptyShellHTML has NO framework marker but looks like an app shell
// waiting for JS: almost no visible text, zero <form> elements, and only
// one static <a href> link. The conjunction (low text + empty shell) must
// classify it as SPA.
const emptyShellHTML = `<!DOCTYPE html>
<html>
<head><title>Loading…</title></head>
<body>
    <a href="/">Home</a>
</body>
</html>`

// shortLoginPageHTML is a DIFFERENT short server-rendered login page (no
// framework marker): low visible text, but it carries a real <form>, so the
// empty-shell branch must not fire. Guards against the Bug 2 false-positive
// class generally, not just for the nozbe page.
const shortLoginPageHTML = `<!DOCTYPE html>
<html>
<head><title>Sign in</title></head>
<body>
    <h1>Please sign in</h1>
    <form action="/login" method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Sign in</button>
    </form>
</body>
</html>`

// TestNozbeLoginPageNotSPA is THE Bug 2 regression test: the exact HTML of
// webapp.nozbe.com's login page must NOT be classified as an SPA. The old
// `visibleCount < 500` fallback returned true here and caused the scanner
// to skip the katana crawl (including -automatic-form-fill discovery) and
// the heavy scan for a page with a real reflected XSS in `go_from`.
func TestNozbeLoginPageNotSPA(t *testing.T) {
	if got := AnalyzeSPA(nozbeLoginHTML, ""); got {
		t.Fatalf("AnalyzeSPA(nozbe login page) = true, want false: the page is plain server-rendered HTML (Bug 2 regression)")
	}
}

// TestMinimalSPAStillSPA guards the true-positive direction: a minimal
// div#root + bundle.js app shell must still be classified as SPA.
func TestMinimalSPAStillSPA(t *testing.T) {
	if !AnalyzeSPA(minimalSPAHTML, "") {
		t.Fatalf("AnalyzeSPA(minimal SPA) = false, want true")
	}
}

// TestMarkersRemainSufficient: every known framework marker alone must
// still classify the page as SPA, independent of visible-text count.
func TestMarkersRemainSufficient(t *testing.T) {
	bodies := map[string]string{
		"div#root":      `<html><body><div id="root"></div><script src="/bundle.js"></script></body></html>`,
		"div#app":       `<html><body><div id="app">Pretend this page has lots and lots of perfectly visible server-rendered text, well over five hundred characters of it, so the text heuristic could never fire on its own. ` + longText(600) + `</div></body></html>`,
		"__NEXT_DATA__": `<html><body>` + longText(600) + `<script id="__NEXT_DATA__" type="application/json">{}</script></body></html>`,
		"__INITIAL_STATE__": `<html><body>` + longText(600) + `<script>window.__INITIAL_STATE__={};</script></body></html>`,
		"ReactDOM.render":  `<html><body>` + longText(600) + `<script>ReactDOM.render(x, y);</script></body></html>`,
		"ng-version":       `<html><body>` + longText(600) + `<app-root ng-version="17.0.0"></app-root></body></html>`,
		"data-reactroot":   `<html><body><div data-reactroot=""></div></body></html>`,
	}
	for name, body := range bodies {
		if !AnalyzeSPA(body, "") {
			t.Errorf("AnalyzeSPA(%s marker) = false, want true (markers must stay sufficient)", name)
		}
	}
}

// TestLowTextAloneNotSPA: a text-light page WITHOUT any marker, WITHOUT
// the x-powered-by corroboration, and WITH real page structure (a form)
// must never be classified as SPA on the low text count alone.
func TestLowTextAloneNotSPA(t *testing.T) {
	if got := AnalyzeSPA(shortLoginPageHTML, ""); got {
		t.Fatalf("AnalyzeSPA(short login page) = true, want false: low visible text alone must not classify as SPA (Bug 2)")
	}
}

// TestEmptyAppShellStillSPA: the conjunction — low text AND zero forms AND
// (almost) no static links — must still classify as SPA even without a
// framework marker (that is what an empty app shell looks like pre-render).
func TestEmptyAppShellStillSPA(t *testing.T) {
	if !AnalyzeSPA(emptyShellHTML, "") {
		t.Fatalf("AnalyzeSPA(empty app shell) = false, want true (low text + no forms + no links must still fire)")
	}
}

// TestXPoweredByCorroboration: low text + next.js/express in x-powered-by
// must still classify as SPA (existing heuristic, now as a corroboration).
func TestXPoweredByCorroboration(t *testing.T) {
	if !AnalyzeSPA(shortLoginPageHTML, "Next.js") {
		t.Errorf("AnalyzeSPA(short page, x-powered-by=Next.js) = false, want true")
	}
	if !AnalyzeSPA(shortLoginPageHTML, "Express") {
		t.Errorf("AnalyzeSPA(short page, x-powered-by=Express) = false, want true")
	}
}

// TestTextHeavyNonSPA: a text-heavy plain page must never classify as SPA.
func TestTextHeavyNonSPA(t *testing.T) {
	body := `<html><body><h1>Article</h1>` + longText(2000) + `</body></html>`
	if AnalyzeSPA(body, "") {
		t.Fatalf("AnalyzeSPA(text-heavy page) = true, want false")
	}
}

// TestIsSPAWiring exercises IsSPA() itself (fetch → classify): the nozbe
// login page served locally must return false end-to-end, and the minimal
// SPA must return true end-to-end.
func TestIsSPAWiring(t *testing.T) {
	pages := []struct {
		name string
		html string
		want bool
	}{
		{"nozbe login page", nozbeLoginHTML, false},
		{"minimal SPA", minimalSPAHTML, true},
	}
	for _, p := range pages {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, p.html)
		}))
		if got := IsSPA(ts.URL); got != p.want {
			t.Errorf("IsSPA(%s) = %v, want %v", p.name, got, p.want)
		}
		ts.Close()
	}
}

// longText builds n characters of plain visible words (no tags, no spaces
// stripped — every char counts toward the visible-text total).
func longText(n int) string {
	buf := make([]byte, 0, n+8)
	word := []byte("loremipsumdolor")
	for len(buf) < n {
		buf = append(buf, word...)
		buf = append(buf, ' ')
	}
	return string(buf[:n])
}
