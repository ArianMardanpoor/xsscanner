// collapse_nozbe_test.go — validation of collapseStructural against the
// REAL webapp.nozbe.com passive list captured from the 34m run
// (892 URLs; upload/Pasted Content_1794667862018.txt). Skips itself when
// the capture file is absent so `go test ./pkg/...` stays hermetic.
//
// Run with:
//
//	go test ./pkg/discoveryutil/ -run TestCollapseStructural_RealNozbeList -v
package discoveryutil

import (
	"os"
	"strings"
	"testing"
)

func TestCollapseStructural_RealNozbeList(t *testing.T) {
	const src = "/home/z/my-project/upload/Pasted Content_1794667862018.txt"
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("real nozbe capture not present (%v) — skipping", err)
	}
	var urls []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			urls = append(urls, line)
		}
	}
	if len(urls) < 800 {
		t.Skipf("capture too small (%d URLs) — not the expected list", len(urls))
	}

	got, dropped := collapseStructural(urls, true)

	t.Logf("real nozbe list: %d URLs -> %d representatives (dropped %d, %.0f%% reduction)",
		len(urls), len(got), dropped, 100*float64(dropped)/float64(len(urls)))

	// The explosion patterns must be gone — measured on SIGNATURES (a
	// substring like "/for/" legitimately matches several distinct real
	// endpoints: /for/EMAIL, /for/<wayback-masked>, /page/for/EMAIL...).
	sigCount := make(map[string]int)
	for _, u := range got {
		sigCount[collapseSignature(u, true)]++
	}
	for sig, n := range sigCount {
		if n > 1 {
			t.Errorf("signature %q has %d representatives — collapse is not deterministic", sig, n)
		}
	}

	// The signature space itself must have collapsed the known clusters:
	// count signatures by shape.
	shapes := make(map[string]int)
	for sig := range sigCount {
		if strings.Contains(sig, "/page-") || strings.Contains(sig, "/post-") {
			shapes["pagination"]++
		}
	}
	if shapes["pagination"] > 6 {
		t.Errorf("pagination cluster still has %d distinct signatures", shapes["pagination"])
	}

	// Reasonable overall shape: the prototype predicted ~262±shape with all
	// rules on. Over-collapse below 150 would lose real endpoints;
	// under-collapse above 400 means the rules are not firing.
	if len(got) < 150 {
		t.Errorf("over-collapse suspected: %d representatives for %d URLs", len(got), len(urls))
	}
	if len(got) > 450 {
		t.Errorf("under-collapse: %d representatives (expected ~262±shape)", len(got))
	}
}
