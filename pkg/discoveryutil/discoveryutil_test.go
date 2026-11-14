package discoveryutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// lookUro isolates exec.LookPath for the availability check in the test.
func lookUro() (string, error) { return exec.LookPath("uro") }

// TestMergeAndFilterUroSemanticDedup seeds passive + katana files whose
// UNION contains near-duplicates (same path, same param-name set, different
// values) that only a semantic (path+param-set) pass can collapse — each
// source individually also carries internal near-duplicates.
func TestMergeAndFilterUroSemanticDedup(t *testing.T) {
	tmp := t.TempDir()
	passive := filepath.Join(tmp, "passive.txt")
	katana := filepath.Join(tmp, "katana.txt")

	os.WriteFile(passive, []byte(
		"https://sub.target.com/search?q=alpha\n"+          // group A rep (first seen)
			"https://sub.target.com/search?q=beta\n"+           // group A near-dup (same path, same param set)
			"https://sub.target.com/items?item=1&sort=asc\n"+   // group B rep
			"https://sub.target.com/profile\n"), 0644)
	os.WriteFile(katana, []byte(
		"https://sub.target.com/search?q=gamma\n"+          // cross-source near-dup of group A
			"https://sub.target.com/items?item=2&sort=desc\n"+ // near-dup of group B
			"https://sub.target.com/contact\n"), 0644)

	got, err := MergeAndFilter(passive, katana, "https://target.com/")
	if err != nil {
		t.Fatalf("MergeAndFilter error: %v", err)
	}

	// Without a uro binary on PATH this test still must pass the exact-string
	// contract; with the stub uro installed in the manual-test PATH it should
	// collapse the three near-duplicate groups. We assert the semantic result
	// only when uro is available (the warning path is exercised otherwise).
	if _, lookErr := lookUro(); lookErr == nil {
		want := []string{
			"https://sub.target.com/search?q=alpha",
			"https://sub.target.com/items?item=1&sort=asc",
			"https://sub.target.com/profile",
			"https://sub.target.com/contact",
		}
		if len(got) != len(want) {
			t.Fatalf("expected %d URLs after semantic dedup, got %d: %v", len(want), len(got), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("order/content mismatch at %d: want %q got %q", i, want[i], got[i])
			}
		}
		} else {
			t.Skipf("uro not on PATH; exact-string dedup only (got %d URLs)", len(got))
		}
}

// TestCollapseStructural_NozbePatterns pins the collapse rules against the
// REAL duplication shapes observed in the webapp.nozbe.com passive list
// (892 URLs from wayback/gau that inflated the test loop to 893 paths ×
// 8 chunks): paginated forums, per-email profile paths, sid-hex session
// paths, numbered content pages, language-prefix copies of the same
// endpoint, and scheme/port variants.
func TestCollapseStructural_NozbePatterns(t *testing.T) {
	in := []string{
		// line 0 — the target itself (never dropped, kept verbatim)
		"https://webapp.nozbe.com/",
		// pagination cluster: /gtd/forum/section-1/page-N  (119 URLs real-world)
		"https://webapp.nozbe.com/gtd/forum/section-1/page-53",
		"https://webapp.nozbe.com/gtd/forum/section-1/page-88",
		"http://webapp.nozbe.com:80/pl/forum/section-1/page-3",
		// per-user profiles: /<lang>/for/<email>  (79 URLs real-world)
		"https://webapp.nozbe.com/pl/for/support@a1pcservices.co.uk",
		"http://webapp.nozbe.com:80/nl/for/torqy@wp.pl",
		"https://webapp.nozbe.com/de/for/other@xmpl.de",
		// session-id paths: /<lang>/forum/sid-<hex32>  (38 URLs real-world)
		"http://webapp.nozbe.com:80/gtd/forum/sid-c21bec4822fc3f7f50cb12d2ad836c7a",
		"https://webapp.nozbe.com/pl/forum/sid-3f52b594f1efe5975f03fcb0c662f2e0",
		// numbered content: /<lang>/show/site-courseN  (63 URLs real-world)
		"http://webapp.nozbe.com:80/pl/show/site-course9",
		"https://webapp.nozbe.com/gtd/show/site-course4",
		"https://webapp.nozbe.com/es/show/site-course1",
		// language copies of the SAME endpoint (9 copies each real-world)
		"http://webapp.nozbe.com:80/pl/login",
		"https://webapp.nozbe.com/jp/login",
		"http://webapp.nozbe.com:80/de/signup",
		"https://webapp.nozbe.com/nl/signup",
		// structurally DISTINCT endpoints — must all survive
		"https://webapp.nozbe.com/api",
		"https://webapp.nozbe.com/help",
		"https://webapp.nozbe.com/sync3/login/return_hash_id-1/from_payments-1",
		// same shape + SAME param-name set, different values (uro rule):
		// collapses to the richest-query member
		"http://webapp.nozbe.com:80/jp/index?logout=1",
		"https://webapp.nozbe.com/ru/index?logout=1",
		"https://webapp.nozbe.com/gtd/login/checkl-1/?go_from=http%3A%2F%2Fexample.com%2Fforum%2Fsection-1",
		// different param-NAME set than /index?logout → distinct, survives
		"https://webapp.nozbe.com/de/index?go_from=x&logout=1",
	}

	got, dropped := collapseStructural(in, true)

	// Expected clusters (15 signatures for 24 inputs):
	//   target, forum-pagination, for-email, forum-sid, show-courseN,
	//   login, signup, api, help, sync3-login, index?logout, login/checkl?go_from,
	//   index?go_from&logout  → 13... plus language-collapsed /login and
	//   /signup counted once each above. Count precisely below instead.
	want := []string{
		"https://webapp.nozbe.com/",                                                 // target, position 0 always kept
		"https://webapp.nozbe.com/gtd/forum/section-1/page-53",                     // pagination rep (first seen of cluster)
		"http://webapp.nozbe.com:80/nl/for/torqy@wp.pl",                             // email rep (shortest path of the email cluster)
		"http://webapp.nozbe.com:80/gtd/forum/sid-c21bec4822fc3f7f50cb12d2ad836c7a", // sid rep
		"http://webapp.nozbe.com:80/pl/show/site-course9",                           // course rep
		"http://webapp.nozbe.com:80/pl/login",                                       // login rep (lang collapse)
		"http://webapp.nozbe.com:80/de/signup",                                      // signup rep (lang collapse)
		"https://webapp.nozbe.com/api",
		"https://webapp.nozbe.com/help",
		"https://webapp.nozbe.com/sync3/login/return_hash_id-1/from_payments-1",
		"https://webapp.nozbe.com/gtd/login/checkl-1/?go_from=http%3A%2F%2Fexample.com%2Fforum%2Fsection-1", // richest-query rep
		"https://webapp.nozbe.com/de/index?go_from=x&logout=1", // different param-name set
		// NOTE: /jp/index?logout + /ru/index?logout share the "index?logout"
		// signature with... nothing else — wait, they DO cluster together
		// (lang prefix dropped, both are host+index?logout), so ONE of them
		// must also appear in the output.
	}
	// The index?logout cluster's representative:
	if !contains(got, "http://webapp.nozbe.com:80/jp/index?logout=1") && !contains(got, "https://webapp.nozbe.com/ru/index?logout=1") {
		t.Errorf("index?logout cluster lost its representative entirely: %v", got)
	}

	if len(got) != 13 {
		t.Fatalf("expected 13 surviving URLs, got %d (dropped %d): %v", len(got), dropped, got)
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("expected %q to survive, got: %v", w, got)
		}
	}
	if got[0] != "https://webapp.nozbe.com/" {
		t.Errorf("target URL must stay position 0, got %q", got[0])
	}
	if dropped != len(in)-len(got) {
		t.Errorf("dropped count mismatch: %d vs %d", dropped, len(in)-len(got))
	}
}

// TestCollapseStructural_ParamNameSetsNeverMerge verifies the safety rule:
// two URLs with the same masked path but DIFFERENT query param-name sets
// must both survive (same rule as uro's semantic dedup).
func TestCollapseStructural_ParamNameSetsNeverMerge(t *testing.T) {
	in := []string{
		"https://t.com/search?q=1",
		"https://t.com/search?query=1", // different param NAME → distinct
		"https://t.com/search?q=1&page=2",
	}
	got, _ := collapseStructural(in, true)
	if len(got) != 3 {
		t.Errorf("different param-name sets must never merge, got %d: %v", len(got), got)
	}
}

// TestCollapseStructural_FirstSegmentToggle verifies the language/app-prefix
// collapse is a separate, toggleable rule: with it off, /pl/login and
// /jp/login are distinct; with it on they collapse.
func TestCollapseStructural_FirstSegmentToggle(t *testing.T) {
	in := []string{
		"https://t.com/pl/login",
		"https://t.com/jp/login",
		"https://t.com/login",
	}
	if got, _ := collapseStructural(in, false); len(got) != 3 {
		t.Errorf("with collapseFirstSegment=false expected 3, got %d: %v", len(got), got)
	}
	if got, _ := collapseStructural(in, true); len(got) != 1 {
		t.Errorf("with collapseFirstSegment=true expected 1 (all are host+login), got %d: %v", len(got), got)
	}
}

// TestMergeAndFilterStructuralCollapseEndToEnd runs the full MergeAndFilter
// (scope filter + exact dedup + uro fallback + structural collapse) on a
// realistic archive-shaped passive file and asserts the test-loop input no
// longer contains the explosion patterns.
func TestMergeAndFilterStructuralCollapseEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	passive := filepath.Join(tmp, "passive.txt")

	var b strings.Builder
	b.WriteString("https://webapp.nozbe.com/\n")
	for i := 1; i <= 50; i++ {
		b.WriteString(fmt.Sprintf("https://webapp.nozbe.com/gtd/forum/section-1/page-%d\n", i))
	}
	for _, lang := range []string{"pl", "de", "jp", "fr", "es"} {
		b.WriteString(fmt.Sprintf("https://webapp.nozbe.com/%s/login\n", lang))
	}
	b.WriteString("https://webapp.nozbe.com/api\n")
	b.WriteString("https://webapp.nozbe.com/help\n")
	os.WriteFile(passive, []byte(b.String()), 0644)

	got, err := MergeAndFilter(passive, "", "https://webapp.nozbe.com/")
	if err != nil {
		t.Fatalf("MergeAndFilter error: %v", err)
	}
	// 58 URLs in → 4 out: target + pagination-rep + login-rep + api + help
	// (help and api are distinct singletons; /login langs collapse to 1).
	if len(got) != 5 {
		t.Fatalf("expected 5 surviving URLs (58 in), got %d: %v", len(got), got)
	}
	if got[0] != "https://webapp.nozbe.com/" {
		t.Errorf("target must remain first, got %q", got[0])
	}
	nPage := 0
	for _, u := range got {
		if strings.Contains(u, "/page-") {
			nPage++
		}
	}
	if nPage != 1 {
		t.Errorf("exactly one pagination representative must survive, got %d", nPage)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
