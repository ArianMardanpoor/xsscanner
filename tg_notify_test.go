// tg_notify_test.go — unit tests for the standalone Telegram notifier.
// Run with:  go test tg_notify.go tg_notify_test.go
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findingLine(t *testing.T, conf, param, url, refl, loc string, chars []string) string {
	t.Helper()
	f := Finding{
		Timestamp:           "2026-11-20T12:00:00+03:30",
		RootDomain:          "example.com",
		URL:                 url,
		VulnerableParameter: param,
		DiscoverySource:     "xssniper",
		Confidence:          conf,
		ReflectionType:      refl,
		Context: findingContext{
			Location:     loc,
			AllowedChars: chars,
		},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestIsConfirmed(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want bool
	}{
		{"HIGH is confirmed", Finding{Confidence: "HIGH"}, true},
		{"case-insensitive", Finding{Confidence: "high"}, true},
		{"MEDIUM is not (likely candidate)", Finding{Confidence: "MEDIUM"}, false},
		{"LOW is not (x9 candidate)", Finding{Confidence: "LOW"}, false},
		{"empty is not", Finding{}, false},
		{"HIGH but noisy context", Finding{
			Confidence: "HIGH",
			Context:    findingContext{Location: "sink (Note: No HTTP reflection, possible false positive)"},
		}, false},
		{"HIGH but noisy reflection type", Finding{
			Confidence:     "HIGH",
			ReflectionType: "dom_sink (Note: No HTTP reflection, possible false positive)",
		}, false},
	}
	for _, c := range cases {
		if got := isConfirmed(c.f); got != c.want {
			t.Errorf("%s: isConfirmed=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestDedupKey(t *testing.T) {
	a := Finding{RootDomain: "e.com", URL: "u", VulnerableParameter: "q",
		ReflectionType: "source_reflection", Context: findingContext{Location: "body"}}
	same := a
	otherParam := a
	otherParam.VulnerableParameter = "id"

	if dedupKey(a) != dedupKey(same) {
		t.Error("identical findings must produce the same key")
	}
	if dedupKey(a) == dedupKey(otherParam) {
		t.Error("different parameter must produce a different key")
	}
}

func TestFormatMessageSingle(t *testing.T) {
	f := Finding{
		Timestamp:           "2026-11-20T12:00:00+03:30",
		RootDomain:          "example.com",
		URL:                 "https://example.com/search?q=<script>",
		VulnerableParameter: "q",
		DiscoverySource:     "xssniper",
		Confidence:          "HIGH",
		ReflectionType:      "source_reflection",
		Context:             findingContext{Location: "reflected in HTML body", AllowedChars: []string{"<", ">"}},
	}
	msg := formatMessage([]Finding{f})
	for _, want := range []string{
		"CONFIRMED VULN",
		"https://example.com/search?q=&lt;script&gt;", // URL must be HTML-escaped
		"param: <code>q</code>",
		"source_reflection/xssniper",
		"reflected in HTML body",
		"2026-11-20T12:00:00+03:30",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if len(msg) > maxMsgLen {
		t.Errorf("message too long: %d > %d", len(msg), maxMsgLen)
	}
}

func TestFormatMessageBatchAndCap(t *testing.T) {
	var batch []Finding
	for i := 0; i < maxPerMessage+3; i++ {
		batch = append(batch, Finding{
			URL:                 "https://example.com/p" + strings.Repeat("a", 50) + string(rune('a'+i)),
			VulnerableParameter: "q",
			Confidence:          "HIGH",
		})
	}
	msg := formatMessage(batch)
	if !strings.Contains(msg, "CONFIRMED VULNS") || !strings.Contains(msg, "new") {
		t.Errorf("batch header missing:\n%s", msg[:80])
	}
	if !strings.Contains(msg, "… + 3 more") {
		t.Error("overflow count missing")
	}
	if len(msg) > maxMsgLen {
		t.Errorf("capped message too long: %d > %d", len(msg), maxMsgLen)
	}
}

func TestTruncMessageNeverSplitsTag(t *testing.T) {
	// A message whose only '>' sits at the very end must be cut before the
	// dangling '<b>' tag, never in the middle of it.
	long := "x <b>" + strings.Repeat("y", maxMsgLen)
	got := truncMessage(long)
	if strings.HasSuffix(got, "<") || strings.HasSuffix(got, "<b") {
		t.Errorf("truncation split an HTML tag: %q", got[len(got)-10:])
	}
	if len(got) > maxMsgLen+10 {
		t.Errorf("truncated message still too long: %d", len(got))
	}
}

func TestTailerAppendsAndPartialLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	tt := &tailer{path: path}
	tt.open()

	if got := tt.poll(); got != nil {
		t.Errorf("empty file should give no lines, got %v", got)
	}

	// append two complete lines + one torn line without newline
	f1, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f1.WriteString("line1\nline2\npartial-without-newline")
	f1.Close()

	got := tt.poll()
	if len(got) != 2 || got[0] != "line1" || got[1] != "line2" {
		t.Fatalf("poll = %v, want [line1 line2]", got)
	}

	// complete the torn line
	f2, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	f2.WriteString("-done\n")
	f2.Close()

	got = tt.poll()
	if len(got) != 1 || got[0] != "partial-without-newline-done" {
		t.Fatalf("poll = %v, want [partial-without-newline-done]", got)
	}
}

func TestTailerTruncateResets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	os.WriteFile(path, []byte("old1\nold2\n"), 0644)

	tt := &tailer{path: path}
	tt.open()
	tt.offset = 12 // pretend we already read everything

	// file gets wiped and rewritten from scratch (fresh results dir)
	os.WriteFile(path, []byte("fresh1\n"), 0644)

	got := tt.poll()
	if len(got) != 1 || got[0] != "fresh1" {
		t.Fatalf("poll after truncate = %v, want [fresh1]", got)
	}
}

func TestTailerMissingFileWaits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notyet.jsonl")

	tt := &tailer{path: path}
	if got := tt.poll(); got != nil {
		t.Fatalf("missing file should give no lines, got %v", got)
	}
	os.WriteFile(path, []byte("appeared\n"), 0644)
	got := tt.poll()
	if len(got) != 1 || got[0] != "appeared" {
		t.Fatalf("poll = %v, want [appeared]", got)
	}
}

// TestJSONRoundTripWithReporterSchema makes sure the struct parses a real
// line as pkg/reporter would have written it (field-name compatibility).
func TestJSONRoundTripWithReporterSchema(t *testing.T) {
	line := `{"timestamp":"2026-11-20T12:00:00Z","root_domain":"nozbe.com","url":"https://webapp.nozbe.com/pl/login?next=x9","vulnerable_parameter":"next","discovery_source":"xssniper","confidence":"HIGH","reflection_type":"source_reflection","context":{"location":"reflected unescaped in <title>","allowed_chars":["<",">","'"],"status_code":200}}`
	var f Finding
	if err := json.Unmarshal([]byte(line), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !isConfirmed(f) {
		t.Error("reporter-style HIGH finding should count as confirmed")
	}
	if f.VulnerableParameter != "next" || f.RootDomain != "nozbe.com" {
		t.Errorf("field mapping wrong: %+v", f)
	}
}
