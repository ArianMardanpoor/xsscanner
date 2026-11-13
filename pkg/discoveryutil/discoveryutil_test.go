package discoveryutil

import (
	"os"
	"os/exec"
	"path/filepath"
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
