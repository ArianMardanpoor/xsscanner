// fallparams_test.go
//
// Integration tests for runFallparams()'s output capture (Bug 1).
//
// Background: runFallparams() used to read ONLY runDir/parameters.txt and
// ignore the CombinedOutput it had already captured. With fallparams v1.0.12
// the invocation always passes -silent, whose runner (funcs/run/runner.go)
// prints params to stdout and — with the DEFAULT output filename — never
// writes the file, so every scan silently returned zero parameters.
//
// The fix passes -o <runDir>/parameters.txt explicitly (which makes the
// file channel work even in -silent mode) and parses BOTH channels,
// warning loudly when both are empty. These tests verify each channel
// combination against a stub fallparams binary placed on PATH:
//
//   TestRunFallparams_FileChannel     stub writes the -o file (channel 1)
//   TestRunFallparams_StdoutChannel   stub prints to stdout only (channel 2)
//   TestRunFallparams_BothChannels    stub writes both (union, deduped)
//   TestRunFallparams_NoOutput        stub produces nothing (nil, no panic)
//   TestRunFallparams_FlagContract    stub records argv; asserts exact flags
//
// NOTE on running: the repository root holds several independent main
// packages built file-by-file (see build.sh), so the root package as a
// whole does not compile. Run this test file paired with nice_params.go:
//
//	go test nice_params.go fallparams_test.go -v
//
// The stub protocol: the stub parses the flags nice_params passes
// (-u, -silent, -o, -crawl, -d, -ct) and its behavior is selected via the
// FALL_STUB_MODE environment variable:
//
//	file     → write params to the -o path only
//	stdout   → print params to stdout only
//	both     → write the file AND print to stdout (real fallparams v1.0.12
//	           behavior with a customized -o plus -silent, per runner.go)
//	none     → write nothing anywhere, exit 0
//	flagdump → write the argv it received, one element per line, to the
//	           -o path (so the flags themselves flow back through the very
//	           channel whose path they named)
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubSource is a tiny Go program compiled by the test into a temporary
// bin dir and prepended to PATH so exec.CommandContext(ctx, "fallparams", …)
// inside runFallparams resolves to it.
const stubSource = `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	mode := os.Getenv("FALL_STUB_MODE")

	// Parse the flags the same way nice_params passes them.
	outPath := ""
	for i := 0; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-o" || os.Args[i] == "-output" {
			outPath = os.Args[i+1]
		}
	}

	params := []string{"go_from", "email", "password", "submit", "boxloginform", "viewport", "blog", "e"}

	switch mode {
	case "flagdump":
		// Each argv element is tagged with "F:" so the raw value survives
		// runFallparams' isCandidateWord filter (an untagged absolute -o
		// path starts with "/" and would be dropped from the parsed
		// candidates — the test strips the tag to recover exact argv).
		lines := make([]string, 0, len(os.Args)-1)
		for _, a := range os.Args[1:] {
			lines = append(lines, "F:"+a)
		}
		os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	case "file":
		os.WriteFile(outPath, []byte(strings.Join(params, "\n")+"\n"), 0644)
	case "stdout":
		for _, p := range params {
			fmt.Println(p)
		}
	case "both":
		os.WriteFile(outPath, []byte(strings.Join(params, "\n")+"\n"), 0644)
		for _, p := range params {
			fmt.Println(p)
		}
	case "none":
		// produce nothing anywhere
	}
}
`

var stubParams = []string{"go_from", "email", "password", "submit", "boxloginform", "viewport", "blog", "e"}

// findGo locates the Go toolchain for compiling the stub (PATH first, then
// the usual install locations).
func findGo(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	for _, p := range []string{"/home/z/go/bin/go", "/usr/local/go/bin/go", "/usr/lib/go/bin/go"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no Go toolchain found to compile the stub fallparams binary")
	return ""
}

// buildStubFallparams compiles the stub and returns its bin dir (to be
// prepended to PATH). The binary is named exactly "fallparams" so PATH
// resolution inside runFallparams finds it.
func buildStubFallparams(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	src := filepath.Join(binDir, "stub_main.go")
	if err := os.WriteFile(src, []byte(stubSource), 0644); err != nil {
		t.Fatalf("write stub source: %v", err)
	}
	bin := filepath.Join(binDir, "fallparams")
	cmd := exec.Command(findGo(t), "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stub fallparams: %v\n%s", err, out)
	}
	return binDir
}

// withStubFallparamsOnPATH runs f with dir prepended to PATH.
func withStubFallparamsOnPATH(t *testing.T, dir string, f func()) {
	t.Helper()
	old := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+old)
	defer os.Setenv("PATH", old)
	f()
}

func runFallparamsForTest(t *testing.T) ([]string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return runFallparams(ctx, "https://example.com/", true, true, 2, 120, "", nil)
}

func assertParamsEqual(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("runFallparams returned %d params, want %d (got: %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("runFallparams[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

// TestRunFallparams_FileChannel: a fallparams that writes the -o file and
// prints nothing to stdout must yield the params (channel 1).
func TestRunFallparams_FileChannel(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "file")
		got, err := runFallparamsForTest(t)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}
		assertParamsEqual(t, got, stubParams)
	})
}

// TestRunFallparams_StdoutChannel: a fallparams that prints to stdout only
// and writes NO file (exactly what real fallparams v1.0.12 does with
// -silent and the default output filename) must still yield the params
// (channel 2). This is the Bug 1 scenario verbatim.
func TestRunFallparams_StdoutChannel(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "stdout")
		got, err := runFallparamsForTest(t)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}
		assertParamsEqual(t, got, stubParams)
	})
}

// TestRunFallparams_BothChannels: a fallparams that emits BOTH the file and
// stdout must yield the union, deduped (8 params, not 16).
func TestRunFallparams_BothChannels(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "both")
		got, err := runFallparamsForTest(t)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}
		assertParamsEqual(t, got, stubParams)
	})
}

// TestRunFallparams_NoOutput: a fallparams that produces nothing at all
// (no file, empty stdout, exit 0) must return nil without panicking —
// "target genuinely has no parameters" stays a valid outcome; the loud
// warning goes to stderr (logErrorMsg) in silent mode.
func TestRunFallparams_NoOutput(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "none")
		got, err := runFallparamsForTest(t)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}
		if got != nil {
			t.Fatalf("runFallparams returned %v, want nil for a no-output run", got)
		}
	})
}

// TestRunFallparams_FlagContract: the exact flags nice_params passes are
// pinned here. The invocation flags (-u, -silent, -crawl, -d, -ct) must
// stay exactly as before (confirmed working; Bug 1 explicitly says do not
// change them), and the Bug 1 fix adds the explicit -o <path> flag whose
// path value is the exact file runFallparams then reads. The flagdump stub
// writes its argv into the -o file, so the flags flow back through the
// very channel whose path they named — proving -o's value matches the
// read path (otherwise the file channel would be empty).
func TestRunFallparams_FlagContract(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "flagdump")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		got, err := runFallparams(ctx, "https://example.com/", true, true, 2, 120, "", nil)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}

		// The flagdump stub tags each argv element with "F:" so the raw
		// values (including the -o path, which starts with "/" and would
		// otherwise be dropped by isCandidateWord) survive the candidate
		// filter. Strip the tag to recover the exact argv.
		var argv []string
		for _, w := range got {
			argv = append(argv, strings.TrimPrefix(w, "F:"))
		}
		set := make(map[string]bool)
		for _, a := range argv {
			set[a] = true
		}
		for _, want := range []string{"-u", "https://example.com/", "-silent", "-o", "-crawl", "-d", "2", "-ct", "120"} {
			if !set[want] {
				t.Errorf("flag %q missing from fallparams invocation (captured argv: %v)", want, argv)
			}
		}
		// -o must be immediately followed by an absolute path ending in
		// parameters.txt.
		for i, w := range argv {
			if w == "-o" && i+1 < len(argv) {
				v := argv[i+1]
				if !filepath.IsAbs(v) || filepath.Base(v) != "parameters.txt" {
					t.Errorf("-o value = %q, want an absolute path ending in parameters.txt", v)
				}
			}
		}
	})
}

// TestExtractCandidates pins the per-line cleaning/dedup of a fallparams
// output channel: whitespace trimmed, invalid words skipped, dedup preserved
// in first-seen order.
func TestExtractCandidates(t *testing.T) {
	long := make([]byte, 120)
	for i := range long {
		long[i] = 'a'
	}
	content := "go_from\n  email  \npassword\ngo_from\n\npassword\n" + string(long) + "\n"
	got := extractCandidates(content)
	want := []string{"go_from", "email", "password"} // 120-char word rejected by isCandidateWord
	assertParamsEqual(t, got, want)
}

// TestMergeCandidateLists pins the union semantics: file-channel order
// first, stdout-only additions after, duplicates dropped.
func TestMergeCandidateLists(t *testing.T) {
	a := []string{"go_from", "email"}
	b := []string{"email", "password", "submit"}
	got := mergeCandidateLists(a, b)
	want := []string{"go_from", "email", "password", "submit"}
	assertParamsEqual(t, got, want)
}

// TestNoOutputWarningDistinguishable verifies the no-output contract via
// the json-out channel shape: a run with no output produces an empty (not
// missing) params array, so "tool produced nothing" stays distinguishable
// from a failed run in main.go's phasePath. (The loud warning itself goes
// to stderr; here we pin the JSON shape that phasePath consumes.)
func TestNoOutputWarningDistinguishable(t *testing.T) {
	binDir := buildStubFallparams(t)
	withStubFallparamsOnPATH(t, binDir, func() {
		t.Setenv("FALL_STUB_MODE", "none")
		got, err := runFallparamsForTest(t)
		if err != nil {
			t.Fatalf("runFallparams error: %v", err)
		}
		if got != nil {
			t.Fatalf("want nil, got %v", got)
		}
		// rawPerURLParams normalizes nil to [] for the -json-out channel.
		normalized := rawPerURLParams(got)
		if normalized == nil {
			t.Fatal("rawPerURLParams(nil) = nil, want [] (must marshal as [] not null)")
		}
		data, _ := json.Marshal(normalized)
		if string(data) != "[]" {
			t.Fatalf("json = %s, want []", data)
		}
	})
}
