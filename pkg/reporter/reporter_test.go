package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendWafBlockedSection_NoParamMapsDir(t *testing.T) {
	tmp := t.TempDir()
	mdPath := filepath.Join(tmp, "report.md")
	if err := os.WriteFile(mdPath, []byte("# Existing\n\nbody\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// nonexistent param_maps dir → no-op, no error, file untouched
	if err := AppendWafBlockedSection(mdPath, filepath.Join(tmp, "nonexistent_param_maps")); err != nil {
		t.Fatalf("AppendWafBlockedSection returned err: %v", err)
	}
	data, _ := os.ReadFile(mdPath)
	if !strings.HasPrefix(string(data), "# Existing") {
		t.Errorf("existing report should be untouched, got: %s", string(data))
	}
	// Should still append the section header (no targets, "no target was blocked" message)
	if !strings.Contains(string(data), "## ⛔ WAF/Blocked — Not Fully Tested") {
		t.Errorf("missing section header")
	}
	if !strings.Contains(string(data), "No target was WAF/blocked") {
		t.Errorf("missing empty-state message")
	}
}

func TestAppendWafBlockedSection_WithBlockedPaths(t *testing.T) {
	tmp := t.TempDir()
	mdPath := filepath.Join(tmp, "report.md")
	os.WriteFile(mdPath, []byte("# Existing Report\n\nsome content\n"), 0644)

	paramMaps := filepath.Join(tmp, "param_maps")
	os.MkdirAll(paramMaps, 0755)

	// Build a waf-blocked.json with two blocked paths
	blocked := map[string]WafBlockedEntry{
		"https://sub1.target.com/admin": {
			Stage:           "test",
			Scope:           "own",
			BlockCounterEnd: 9,
			Timestamp:       "2026-11-01T12:00:00Z",
		},
		"https://sub1.target.com/search": {
			Stage:           "phase",
			BlockCounterEnd: 12,
			Timestamp:       "2026-11-01T12:01:00Z",
		},
	}
	data, _ := json.MarshalIndent(blocked, "", "  ")
	os.WriteFile(filepath.Join(paramMaps, "https___sub1_target_com_-waf-blocked.json"), append(data, '\n'), 0644)

	// Another target with no blocked paths (empty file) — should be skipped
	os.WriteFile(filepath.Join(paramMaps, "https___sub2_target_com_-waf-blocked.json"), []byte("{}"), 0644)

	if err := AppendWafBlockedSection(mdPath, paramMaps); err != nil {
		t.Fatalf("AppendWafBlockedSection returned err: %v", err)
	}

	result, _ := os.ReadFile(mdPath)
	rs := string(result)
	if !strings.HasPrefix(rs, "# Existing Report") {
		t.Errorf("existing report should be preserved at top, got: %q", rs[:60])
	}
	if !strings.Contains(rs, "## ⛔ WAF/Blocked — Not Fully Tested") {
		t.Errorf("missing section header")
	}
	if !strings.Contains(rs, "https___sub1_target_com_") {
		t.Errorf("missing target name")
	}
	if !strings.Contains(rs, "https://sub1.target.com/admin") {
		t.Errorf("missing blocked path 1")
	}
	if !strings.Contains(rs, "https://sub1.target.com/search") {
		t.Errorf("missing blocked path 2")
	}
	if !strings.Contains(rs, "phase") {
		t.Errorf("missing phase stage label")
	}
	if !strings.Contains(rs, "test") {
		t.Errorf("missing test stage label")
	}
	// Empty target should NOT appear
	if strings.Contains(rs, "https___sub2_target_com_") {
		t.Errorf("empty waf-blocked.json should be skipped, not appended")
	}
}

func TestAppendWafBlockedSection_CorruptJsonSkipped(t *testing.T) {
	tmp := t.TempDir()
	mdPath := filepath.Join(tmp, "report.md")
	os.WriteFile(mdPath, []byte("# R\n"), 0644)

	paramMaps := filepath.Join(tmp, "param_maps")
	os.MkdirAll(paramMaps, 0755)
	// corrupt json file
	os.WriteFile(filepath.Join(paramMaps, "https___bad_-waf-blocked.json"), []byte("{not valid json"), 0644)

	if err := AppendWafBlockedSection(mdPath, paramMaps); err != nil {
		t.Fatalf("err: %v", err)
	}
	result, _ := os.ReadFile(mdPath)
	if strings.Contains(string(result), "https___bad_") {
		t.Errorf("corrupt file should be silently skipped")
	}
	// Empty-state should be present (no valid sections found)
	if !strings.Contains(string(result), "No target was WAF/blocked") {
		t.Errorf("missing empty-state message")
	}
}
