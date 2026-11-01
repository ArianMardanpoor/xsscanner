// Package reporter provides a unified findings pipeline for the recon/XSS toolchain:
//  1. JSONL append log      -> results/raw_findings.jsonl   (machine-readable)
//  2. Markdown report       -> results/TARGET_REPORT.md     (human-readable)
//  3. ASCII stats dashboard -> stdout at end of run
package reporter

import (
        "bufio"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "strings"
        "sync"
        "time"
)

// ─── Schema ─────────────────────────────────────────────────────────────────

type Context struct {
        Location     string   `json:"location"`
        AllowedChars []string `json:"allowed_chars"`
        StatusCode   int      `json:"status_code"`
}

type Finding struct {
        Timestamp           string  `json:"timestamp"`
        RootDomain          string  `json:"root_domain"`
        URL                 string  `json:"url"`
        VulnerableParameter string  `json:"vulnerable_parameter"`
        DiscoverySource     string  `json:"discovery_source"` // katana, x8, fallparams, x9, dom_sink, xssniper...
        Confidence          string  `json:"confidence"`       // HIGH / MEDIUM / LOW
        ReflectionType      string  `json:"reflection_type"`  // source_reflection, dom_sink_injection, candidate...
        Context             Context `json:"context"`
}

// NewFinding is a convenience constructor that stamps the current time.
func NewFinding(rootDomain, url, param, source, confidence, reflType string, ctx Context) Finding {
        return Finding{
                Timestamp:           time.Now().Format(time.RFC3339),
                RootDomain:          rootDomain,
                URL:                 url,
                VulnerableParameter: param,
                DiscoverySource:     source,
                Confidence:          strings.ToUpper(confidence),
                ReflectionType:      reflType,
                Context:             ctx,
        }
}

// ─── Logger (JSONL writer, safe for concurrent use across goroutines/tools) ─

type Logger struct {
        mu   sync.Mutex
        path string
}

// NewLogger opens (or creates) the JSONL file for appending and returns a Logger.
// Call this once per process; safe to share across goroutines via the same *Logger.
func NewLogger(path string) (*Logger, error) {
        if dir := filepath.Dir(path); dir != "" {
                if err := os.MkdirAll(dir, 0755); err != nil {
                        return nil, fmt.Errorf("reporter: mkdir %s: %w", dir, err)
                }
        }
        return &Logger{path: path}, nil
}

// Log appends a single Finding as one JSON line. Safe for concurrent calls.
func (l *Logger) Log(f Finding) error {
        l.mu.Lock()
        defer l.mu.Unlock()

        fh, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return fmt.Errorf("reporter: open %s: %w", l.path, err)
        }
        defer fh.Close()

        b, err := json.Marshal(f)
        if err != nil {
                return fmt.Errorf("reporter: marshal finding: %w", err)
        }
        if _, err := fh.Write(append(b, '\n')); err != nil {
                return fmt.Errorf("reporter: write finding: %w", err)
        }
        return nil
}

// LogFromExternalTool is a helper for logging findings emitted by a subprocess
// (e.g. a Python dom_sink_checker) that prints one JSON-per-line Finding to stdout.
// Call this per captured line from the subprocess's output.
func (l *Logger) LogFromExternalTool(line string) error {
        line = strings.TrimSpace(line)
        if line == "" {
                return nil
        }
        var f Finding
        if err := json.Unmarshal([]byte(line), &f); err != nil {
                return fmt.Errorf("reporter: invalid finding line from external tool: %w", err)
        }
        return l.Log(f)
}

// ─── Reading back all findings ──────────────────────────────────────────────

func ReadFindings(jsonlPath string) ([]Finding, error) {
        fh, err := os.Open(jsonlPath)
        if err != nil {
                if os.IsNotExist(err) {
                        return nil, nil
                }
                return nil, err
        }
        defer fh.Close()

        var out []Finding
        sc := bufio.NewScanner(fh)
        sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
        for sc.Scan() {
                line := strings.TrimSpace(sc.Text())
                if line == "" {
                        continue
                }
                var f Finding
                if err := json.Unmarshal([]byte(line), &f); err != nil {
                        continue // skip malformed lines rather than aborting the whole report
                }
                out = append(out, f)
        }
        return out, sc.Err()
}

// isNoisy checks if a finding has been flagged as a false positive.
func isNoisy(f Finding) bool {
        marker := "(Note: No HTTP reflection, possible false positive)"
        return strings.Contains(f.Context.Location, marker) || strings.Contains(f.ReflectionType, marker)
}

// isHigh decides whether a finding belongs in the "High Confidence" bucket.
func isHigh(f Finding) bool {
        // Exclude explicitly flagged noisy findings
        if isNoisy(f) {
                return false
        }
        // Strictly rely on Confidence value
        return strings.EqualFold(f.Confidence, "HIGH")
}

// ─── Markdown report ────────────────────────────────────────────────────────

// GenerateMarkdownReport reads jsonlPath and writes a grouped, table-based
// markdown report to mdPath.
//
// WAF/block-guard note: this report does NOT consult
// results/param_maps/<safeURL>-waf-blocked.json directly (the report is
// findings-driven, not state-driven); a separate per-target "WAF/Blocked —
// Not Fully Tested" section is emitted by the standalone helper
// AppendWafBlockedSection below — main.go wires that into the final report
// after GenerateMarkdownReport runs.
func GenerateMarkdownReport(jsonlPath, mdPath string) error {
        findings, err := ReadFindings(jsonlPath)
        if err != nil {
                return fmt.Errorf("reporter: read findings: %w", err)
        }

        var high, medium, noisy []Finding
        for _, f := range findings {
                if isNoisy(f) {
                        noisy = append(noisy, f)
                } else if isHigh(f) {
                        high = append(high, f)
                } else {
                        medium = append(medium, f)
                }
        }

        sortFn := func(s []Finding) {
                sort.Slice(s, func(i, j int) bool {
                        if s[i].RootDomain != s[j].RootDomain {
                                return s[i].RootDomain < s[j].RootDomain
                        }
                        return s[i].Timestamp < s[j].Timestamp
                })
        }
        sortFn(high)
        sortFn(medium)
        sortFn(noisy)

        var b strings.Builder
        b.WriteString("# 🎯 Vulnerability Scan Report\n\n")
        b.WriteString(fmt.Sprintf("_Generated: %s_\n\n", time.Now().Format(time.RFC3339)))

        // Updated summary line to include Noisy/Unverified findings
        b.WriteString(fmt.Sprintf("**Total findings:** %d  |  **High confidence:** %d  |  **Medium/Low:** %d  |  **Noisy/Unverified:** %d\n\n",
                len(findings), len(high), len(medium), len(noisy)))
        b.WriteString("---\n\n")

        writeTable := func(title, emptyMsg string, rows []Finding) {
                b.WriteString("## " + title + "\n\n")
                if len(rows) == 0 {
                        b.WriteString("_" + emptyMsg + "_\n\n")
                        return
                }
                b.WriteString("| URL | Parameter | Context / Sink | Source |\n")
                b.WriteString("|---|---|---|---|\n")
                for _, f := range rows {
                        ctxDesc := f.Context.Location
                        if ctxDesc == "" {
                                ctxDesc = f.ReflectionType
                        }
                        if len(f.Context.AllowedChars) > 0 {
                                ctxDesc += fmt.Sprintf(" (chars: `%s`)", strings.Join(f.Context.AllowedChars, ""))
                        }
                        param := f.VulnerableParameter
                        if param == "" {
                                param = "—"
                        }
                        // Escape pipe characters so the URL/context can't break the table.
                        url := strings.ReplaceAll(f.URL, "|", "\\|")
                        ctxDesc = strings.ReplaceAll(ctxDesc, "|", "\\|")
                        b.WriteString(fmt.Sprintf("| [%s](%s) | `%s` | %s | %s |\n",
                                f.RootDomain, url, param, ctxDesc, f.DiscoverySource))
                }
                b.WriteString("\n")
        }

        writeTable("🔥 High Confidence Targets", "No confirmed reflections or DOM sinks yet.", high)
        writeTable("🔍 Medium/Low Confidence Targets", "No candidate parameters recorded yet.", medium)
        writeTable("⚠️ Noisy/Unverified (flagged false-positive)", "No noisy targets found.", noisy)

        if err := os.MkdirAll(filepath.Dir(mdPath), 0755); err != nil {
                return fmt.Errorf("reporter: mkdir for report: %w", err)
        }
        if err := os.WriteFile(mdPath, []byte(b.String()), 0644); err != nil {
                return fmt.Errorf("reporter: write report: %w", err)
        }
        return nil
}

// ─── WAF/Blocked section (per-target waf-blocked.json) ───────────────────────
//
// A target that gets WAF/blocked partway through must NOT silently read as
// "clean" — a "0 vulnerabilities found" result for a blocked target actually
// means "we got blocked before we could finish", not "target is safe". This
// helper appends a visible "⛔ WAF/Blocked — Not Fully Tested" section to the
// existing report listing every blocked path + its stage (and scope for tests),
// so a reviewer can see at a glance which targets need re-running with
// -retry-blocked or a different rate/cookie/header.

// WafBlockedEntry is one path's waf-blocked record (mirrors main.go's
// wafBlockedEntry shape, kept as a value type so reporter does not depend on
// the main package).
type WafBlockedEntry struct {
        Stage           string `json:"stage"`            // "phase" or "test"
        Scope           string `json:"scope,omitempty"`   // "own"/"all" for stage="test"; "" for stage="phase"
        BlockCounterEnd int64  `json:"blockCounterEnd"`
        Timestamp       string `json:"timestamp"`
}

// AppendWafBlockedSection reads every results/param_maps/*-waf-blocked.json
// file and appends a "⛔ WAF/Blocked — Not Fully Tested" section to mdPath
// listing each non-empty target's blocked paths. A target whose file is
// missing, empty, or unreadable is silently skipped (its targets-scanned count
// is not affected — the dashboard already reports that elsewhere). Best-effort:
// a write failure is returned so main.go can log it, but the report itself was
// already successfully written by GenerateMarkdownReport.
func AppendWafBlockedSection(mdPath, paramMapsDir string) error {
        // Read the existing report and append (do NOT overwrite). If the report
        // does not exist (GenerateMarkdownReport failed earlier), we still
        // write the WAF/Blocked section as a standalone file so the user can
        // see blocked targets even when the main report is missing.
        existing, _ := os.ReadFile(mdPath)

        var b strings.Builder
        b.Write(existing)
        if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n\n") {
                b.WriteString("\n")
        }

        b.WriteString("---\n\n")
        b.WriteString("## ⛔ WAF/Blocked — Not Fully Tested\n\n")

        // Read every results/param_maps/*-waf-blocked.json file. Missing or
        // unreadable dir → no blocked targets to list (still write the section
        // header so the report explicitly says "no blocked targets" rather than
        // being silent — see TestAppendWafBlockedSection_NoParamMapsDir).
        var sections []targetSection
        if entries, err := os.ReadDir(paramMapsDir); err == nil {
                for _, e := range entries {
                        if e.IsDir() || !strings.HasSuffix(e.Name(), "-waf-blocked.json") {
                                continue
                        }
                        full := filepath.Join(paramMapsDir, e.Name())
                        data, rerr := os.ReadFile(full)
                        if rerr != nil {
                                continue
                        }
                        var m map[string]WafBlockedEntry
                        if jerr := json.Unmarshal(data, &m); jerr != nil {
                                continue // corrupt — skip silently (main.go logs at load time)
                        }
                        if len(m) == 0 {
                                continue
                        }
                        safeURL := strings.TrimSuffix(strings.TrimSuffix(e.Name(), "-waf-blocked.json"), "")
                        sections = append(sections, targetSection{safeURL: safeURL, paths: m})
                }
        }

        if len(sections) == 0 {
                b.WriteString("_No target was WAF/blocked during this run — every target was scanned to completion (or skipped via the normal pathParams/testState resume cache, not the WAF/block guard)._\n\n")
        } else {
                b.WriteString("The following targets were marked **WAF/blocked** by the block-guard during the run. A \"0 vulnerabilities found\" result for any of these targets means **the scan was aborted partway through**, not that the target is clean. Re-run with `-retry-blocked` to re-attempt these specific paths, or `-force` to re-scan everything fresh.\n\n")
                for _, s := range sections {
                        b.WriteString(fmt.Sprintf("### Target: `%s`\n\n", s.safeURL))
                        b.WriteString("| Path | Stage | Scope | Counter End | Timestamp |\n")
                        b.WriteString("|---|---|---|---|---|\n")
                        // Stable ordering by path so the section is reproducible.
                        var paths []string
                        for p := range s.paths {
                                paths = append(paths, p)
                        }
                        sort.Strings(paths)
                        for _, p := range paths {
                                e := s.paths[p]
                                scope := e.Scope
                                if scope == "" {
                                        scope = "—"
                                }
                                ts := e.Timestamp
                                if ts == "" {
                                        ts = "—"
                                }
                                url := strings.ReplaceAll(p, "|", "\\|")
                                b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %s |\n", url, e.Stage, scope, e.BlockCounterEnd, ts))
                        }
                        b.WriteString("\n")
                }
        }

        if err := os.MkdirAll(filepath.Dir(mdPath), 0755); err != nil {
                return fmt.Errorf("reporter: mkdir for waf-blocked append: %w", err)
        }
        return os.WriteFile(mdPath, []byte(b.String()), 0644)
}

// targetSection is a small helper struct used by AppendWafBlockedSection so the
// sections slice can be iterated in stable order (sorted by safeURL below).
type targetSection struct {
        safeURL string
        paths   map[string]WafBlockedEntry
}

// ─── Dashboard ───────────────────────────────────────────────────────────────

type DashboardStats struct {
        TargetsScanned   int
        PassiveURLs      int
        ParamsDiscovered int
        VulnsFound       int // canary-reflected / confirmed
        ReportPath       string
        Elapsed          time.Duration
}

// PrintDashboard renders a compact ASCII summary box to stdout.
func PrintDashboard(s DashboardStats) {
        const width = 56
        line := func(label string, value interface{}) string {
                content := fmt.Sprintf(" %-30s %-21v", label, value)
                if len(content) > width-2 {
                        content = content[:width-2]
                }
                return "║" + content + strings.Repeat(" ", width-2-len(content)) + "║"
        }

        top := "╔" + strings.Repeat("═", width-2) + "╗"
        mid := "╠" + strings.Repeat("═", width-2) + "╣"
        bot := "╚" + strings.Repeat("═", width-2) + "╝"

        fmt.Println()
        fmt.Println(top)
        fmt.Println("║" + centre(" SCAN SUMMARY DASHBOARD ", width-2) + "║")
        fmt.Println(mid)
        fmt.Println(line("Targets Scanned:", s.TargetsScanned))
        fmt.Println(line("Passive URLs Extracted:", s.PassiveURLs))
        fmt.Println(line("Parameters Discovered:", s.ParamsDiscovered))
        fmt.Println(line("Potential Vulns Found:", s.VulnsFound))
        fmt.Println(line("Elapsed:", s.Elapsed.Round(time.Second)))
        fmt.Println(mid)
        fmt.Println(line("Report:", s.ReportPath))
        fmt.Println(bot)
        fmt.Println()
}

func centre(s string, width int) string {
        if len(s) >= width {
                return s[:width]
        }
        padTotal := width - len(s)
        left := padTotal / 2
        right := padTotal - left
        return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
