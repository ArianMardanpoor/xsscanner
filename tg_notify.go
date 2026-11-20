// tg_notify.go — standalone Telegram notifier for the xsscanner toolchain.
//
// ADD-ON FILE: this program is fully self-contained (standard library only).
// It does not import, modify or interfere with any existing file — build it
// on its own, exactly the way build.sh builds every other tool:
//
//	go build -o tg_notify tg_notify.go        (or: bash build_tg_notify.sh)
//
// # WHAT IT DOES
//
// Every tool in this toolchain (xsscanner, xssniper, ...) appends each
// finding to results/raw_findings.jsonl the MOMENT it is produced (the
// pkg/reporter Logger writes one JSON line per finding, immediately). A
// finding with confidence "HIGH" is a fully CONFIRMED bug: xssniper maps
// severity "confirmed" (or Confirmed=true) to confidence HIGH — the same
// criterion xsscanner's dashboard counts as "Vulns Found" and the one
// TARGET_REPORT.md uses for its "🔥 High Confidence Targets" section.
//
// This watcher tails that file and, the instant a new HIGH-confidence
// (non-noisy, non-duplicate) finding is appended, sends you a Telegram
// message through your own bot. No existing binary has to be rebuilt or
// changed.
//
// CONFIG — .env in the working directory (or next to this binary), using the
// SAME variable names the toolchain already uses for its end-of-run log
// upload:
//
//	TELEGRAM_BOT_TOKEN=123456:ABC...
//	TELEGRAM_CHAT_ID=123456789
//
// Optional (rarely needed):
//
//	TELEGRAM_API_BASE=https://api.telegram.org   # override, e.g. for tests
//
// USAGE
//
//	./tg_notify                     # watch results/raw_findings.jsonl (new findings only)
//	./tg_notify -f other.jsonl      # watch a different findings file
//	./tg_notify -from-start         # also notify findings already in the file
//	./tg_notify -v                  # verbose: log every appended line
//
// Or let run_with_telegram.sh arm it around any tool of the toolchain:
//
//	./run_with_telegram.sh -u https://target/            # wraps ./xsscanner
//	./run_with_telegram.sh xssniper -u https://target/   # wraps ./xssniper
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ── Finding schema (mirrors pkg/reporter.Finding — same JSON tags) ──────────

type findingContext struct {
	Location     string   `json:"location"`
	AllowedChars []string `json:"allowed_chars"`
	StatusCode   int      `json:"status_code"`
}

type Finding struct {
	Timestamp           string         `json:"timestamp"`
	RootDomain          string         `json:"root_domain"`
	URL                 string         `json:"url"`
	VulnerableParameter string         `json:"vulnerable_parameter"`
	DiscoverySource     string         `json:"discovery_source"`
	Confidence          string         `json:"confidence"`
	ReflectionType      string         `json:"reflection_type"`
	Context             findingContext `json:"context"`
}

// noisyMarker is the false-positive flag pkg/reporter recognizes (written by
// xssniper's processDomJson when a dom_confirmed sink shows no HTTP
// reflection). Noisy findings are excluded from the report's high-confidence
// section, so they are excluded from notifications too.
const noisyMarker = "(Note: No HTTP reflection, possible false positive)"

func isNoisy(f Finding) bool {
	return strings.Contains(f.Context.Location, noisyMarker) ||
		strings.Contains(f.ReflectionType, noisyMarker)
}

// isConfirmed is the toolchain's own "fully confirmed bug" rule: a HIGH
// confidence finding that is not flagged noisy. Exactly the set xsscanner
// counts as "Vulns Found" and TARGET_REPORT.md lists under "🔥 High
// Confidence Targets" (xssniper severity "confirmed" / Confirmed=true both
// map to confidence HIGH; "likely" is MEDIUM and "possible" is LOW, so
// candidates never notify).
func isConfirmed(f Finding) bool {
	return strings.EqualFold(f.Confidence, "HIGH") && !isNoisy(f)
}

// dedupKey identifies one bug. The same URL/param can be re-logged by a later
// chunk run (logReportFindings fires at every phase boundary); the first
// confirmation notifies, identical repeats are suppressed.
func dedupKey(f Finding) string {
	return strings.Join([]string{
		f.RootDomain, f.URL, f.VulnerableParameter, f.ReflectionType, f.Context.Location,
	}, "\x00")
}

// ── .env loading (same semantics as xssniper.go's loadEnv: real environment
// variables win over .env values; values may be quoted) ──────────────────────

func loadEnv() {
	candidates := []string{".env"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			if key == "" || os.Getenv(key) != "" {
				continue
			}
			_ = os.Setenv(key, val)
		}
	}
}

// ── Telegram client ─────────────────────────────────────────────────────────

type tgClient struct {
	base   string // e.g. https://api.telegram.org
	token  string
	chatID string
	http   *http.Client
}

// tgError is a non-200 answer from the Bot API. Codes 400/401/403 are
// permanent configuration problems (bad token, bad chat id, malformed
// message) and are never retried; everything else is retried.
type tgError struct {
	code        int
	description string
	retryAfter  int // seconds, from a 429 answer
}

func (e *tgError) Error() string {
	msg := fmt.Sprintf("telegram api error %d", e.code)
	if e.description != "" {
		msg += ": " + e.description
	}
	if e.retryAfter > 0 {
		msg += fmt.Sprintf(" (retry_after=%ds)", e.retryAfter)
	}
	return msg
}

func (e *tgError) permanent() bool {
	return e.code == 400 || e.code == 401 || e.code == 403
}

func (c *tgClient) sendMessage(text string) error {
	payload := map[string]interface{}{
		"chat_id":                  c.chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	apiURL := fmt.Sprintf("%s/bot%s/sendMessage", strings.TrimRight(c.base, "/"), c.token)
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var parsed struct {
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	_ = json.Unmarshal(raw, &parsed)
	return &tgError{
		code:        resp.StatusCode,
		description: parsed.Description,
		retryAfter:  parsed.Parameters.RetryAfter,
	}
}

// sendWithRetry delivers one message, retrying transient failures (network
// errors, 5xx, 429 with its server-provided retry_after). Permanent errors
// (400/401/403) abort immediately so a broken token is reported at once.
func (c *tgClient) sendWithRetry(text string) error {
	backoff := []time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	var lastErr error
	for attempt := 0; attempt < len(backoff); attempt++ {
		if backoff[attempt] > 0 {
			time.Sleep(backoff[attempt])
		}
		err := c.sendMessage(text)
		if err == nil {
			return nil
		}
		lastErr = err
		var te *tgError
		if errors.As(err, &te) {
			if te.permanent() {
				return te
			}
			if te.retryAfter > 0 {
				wait := time.Duration(te.retryAfter) * time.Second
				if wait > 30*time.Second {
					wait = 30 * time.Second
				}
				time.Sleep(wait)
			}
		}
	}
	return lastErr
}

// ── Message formatting ──────────────────────────────────────────────────────

const (
	maxURLLen     = 400
	maxParamLen   = 120
	maxContextLen = 300
	maxCharsLen   = 200
	maxMsgLen     = 3900 // Telegram hard limit is 4096 — stay safely below
	maxPerMessage = 8
)

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// trunc shortens s to at most n runes (never splits a UTF-8 sequence).
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// truncMessage keeps the final text under Telegram's limit without ever
// splitting an HTML tag (a broken tag would make the whole message fail
// parse_mode=HTML and be rejected with a 400).
func truncMessage(s string) string {
	if len(s) <= maxMsgLen {
		return s
	}
	cut := s[:maxMsgLen]
	if i := strings.LastIndex(cut, "<"); i >= 0 && strings.IndexByte(cut[i:], '>') < 0 {
		cut = cut[:i]
	}
	cut = strings.ToValidUTF8(cut, "")
	return cut + "\n…"
}

// formatFinding renders one finding as HTML lines. num > 0 prefixes the
// entry with its number (batch mode).
func formatFinding(f Finding, num int) string {
	var b strings.Builder
	if num > 0 {
		fmt.Fprintf(&b, "%d) ", num)
	}
	fmt.Fprintf(&b, "🎯 <code>%s</code>\n", escapeHTML(trunc(f.URL, maxURLLen)))

	param := f.VulnerableParameter
	if param == "" {
		param = "—"
	}
	line := fmt.Sprintf("   🔢 param: <code>%s</code>", escapeHTML(trunc(param, maxParamLen)))
	if f.ReflectionType != "" || f.DiscoverySource != "" {
		line += fmt.Sprintf(" | 🔍 %s", escapeHTML(strings.Trim(f.ReflectionType+"/"+f.DiscoverySource, "/")))
	}
	if f.RootDomain != "" {
		line += fmt.Sprintf(" | 🌐 %s", escapeHTML(f.RootDomain))
	}
	b.WriteString(line)
	b.WriteByte('\n')

	ctx := f.Context.Location
	if ctx == "" {
		ctx = f.ReflectionType
	}
	if ctx == "" {
		ctx = "—"
	}
	ctxLine := "   📄 " + escapeHTML(trunc(ctx, maxContextLen))
	if len(f.Context.AllowedChars) > 0 {
		ctxLine += fmt.Sprintf(" (chars: <code>%s</code>)",
			escapeHTML(trunc(strings.Join(f.Context.AllowedChars, ""), maxCharsLen)))
	}
	b.WriteString(ctxLine)
	b.WriteByte('\n')

	ts := f.Timestamp
	if ts == "" {
		ts = time.Now().Format(time.RFC3339)
	}
	fmt.Fprintf(&b, "   🕒 %s\n", escapeHTML(ts))
	return b.String()
}

// formatMessage renders one notification for a batch of findings that
// arrived in the same instant (they are combined into a single message to
// stay friendly to Telegram's rate limits).
func formatMessage(batch []Finding) string {
	var b strings.Builder
	if len(batch) == 1 {
		b.WriteString("🚨 <b>CONFIRMED VULN</b>\n\n")
		b.WriteString(formatFinding(batch[0], 0))
		return truncMessage(b.String())
	}
	fmt.Fprintf(&b, "🚨 <b>CONFIRMED VULNS</b> (%d new)\n\n", len(batch))
	shown := batch
	more := 0
	if len(shown) > maxPerMessage {
		more = len(shown) - maxPerMessage
		shown = shown[:maxPerMessage]
	}
	for i, f := range shown {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(formatFinding(f, i+1))
	}
	if more > 0 {
		fmt.Fprintf(&b, "\n… + %d more", more)
	}
	return truncMessage(b.String())
}

// ── Findings-file tailer ────────────────────────────────────────────────────
//
// The reporter Logger appends one JSON line per finding with O_APPEND
// (line-atomic), so a reader that follows the file sees each finding the
// moment it is written. The tailer polls every 300ms, handles a file that
// does not exist yet (fresh run, results/ not created), a file that got
// truncated or replaced (results/ wiped between runs), and buffers a torn
// trailing line until its newline arrives.

const (
	pollInterval   = 300 * time.Millisecond
	maxReadPerPoll = 8 << 20
	maxLineBuf     = 4 << 20
)

type tailer struct {
	path    string
	f       *os.File
	ident   os.FileInfo // stat of the opened file, to detect replacement
	offset  int64
	partial []byte // trailing bytes of a not-yet-complete line
}

func (t *tailer) reset() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
	t.ident = nil
	t.offset = 0
	t.partial = t.partial[:0]
}

// open attaches to the current file at t.path. Returns false while the file
// does not exist yet.
func (t *tailer) open() bool {
	f, err := os.Open(t.path)
	if err != nil {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return false
	}
	if st.Size() < t.offset {
		// smaller than what we already read → truncated/replaced, start over
		t.offset = 0
		t.partial = t.partial[:0]
	}
	t.f = f
	t.ident = st
	return true
}

// poll reads newly appended bytes and returns every complete line.
func (t *tailer) poll() []string {
	if t.f == nil && !t.open() {
		return nil
	}
	cur, err := os.Stat(t.path)
	if err != nil {
		t.reset() // file vanished → wait for it to be recreated
		return nil
	}
	if !os.SameFile(t.ident, cur) {
		t.reset() // path now names a different file → follow the new one
		return t.poll()
	}
	if cur.Size() < t.offset {
		t.reset() // truncated
		return t.poll()
	}
	if cur.Size() == t.offset {
		return nil
	}
	toRead := cur.Size() - t.offset
	if toRead > maxReadPerPoll {
		toRead = maxReadPerPoll
	}
	if _, err := t.f.Seek(t.offset, io.SeekStart); err != nil {
		t.reset()
		return nil
	}
	buf := make([]byte, toRead)
	read, err := t.f.Read(buf)
	if read > 0 {
		t.offset += int64(read)
		t.partial = append(t.partial, buf[:read]...)
	}
	if err != nil && err != io.EOF {
		t.reset()
		return nil
	}
	if len(t.partial) == 0 {
		return nil
	}
	var lines []string
	for {
		i := bytes.IndexByte(t.partial, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(string(t.partial[:i]))
		t.partial = t.partial[i+1:]
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(t.partial) > maxLineBuf {
		// pathological single line — drop it rather than grow unbounded
		t.partial = t.partial[:0]
	}
	return lines
}

// ── Single-instance lock ────────────────────────────────────────────────────
//
// Two watchers tailing the same file would double every notification. A tiny
// pidfile next to the findings file prevents that; a stale lock (process
// gone) is taken over automatically.

func acquirePidLock(findingsPath string) (release func(), err error) {
	dir := filepath.Dir(findingsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("tg_notify: mkdir %s: %w", dir, err)
	}
	pidPath := filepath.Join(dir, ".tg_notify.pid")
	if data, rerr := os.ReadFile(pidPath); rerr == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil {
			if kerr := syscall.Kill(pid, 0); kerr == nil || kerr == syscall.EPERM {
				if pid != os.Getpid() {
					return nil, fmt.Errorf(
						"another tg_notify is already running (pid %d, lock %s) — kill it first",
						pid, pidPath)
				}
			}
		}
	}
	if werr := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0644); werr != nil {
		return nil, fmt.Errorf("tg_notify: cannot write %s: %w", pidPath, werr)
	}
	return func() { _ = os.Remove(pidPath) }, nil
}

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	findingsPath := flag.String("f", "results/raw_findings.jsonl",
		"findings JSONL file to watch (the file every tool appends to)")
	fromStart := flag.Bool("from-start", false,
		"also notify findings already present in the file (default: only new ones)")
	verbose := flag.Bool("v", false, "verbose: log every appended finding line")
	flag.Parse()

	loadEnv()
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		fmt.Fprintln(os.Stderr,
			"[tg_notify] ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set "+
				"(in the environment or in .env — see .env.example)")
		os.Exit(1)
	}
	base := os.Getenv("TELEGRAM_API_BASE")
	if base == "" {
		base = "https://api.telegram.org"
	}

	release, err := acquirePidLock(*findingsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[tg_notify] ERROR:", err)
		os.Exit(1)
	}

	client := &tgClient{
		base:   base,
		token:  token,
		chatID: chatID,
		http:   &http.Client{Timeout: 20 * time.Second},
	}

	// The armed ping doubles as a credentials check: if the token or chat id
	// is wrong we find out NOW, before a multi-hour scan runs with
	// notifications silently going nowhere.
	armedMsg := fmt.Sprintf("✅ <b>tg_notify armed</b>\n👀 watching <code>%s</code> for CONFIRMED findings",
		escapeHTML(*findingsPath))
	if err := client.sendWithRetry(armedMsg); err != nil {
		fmt.Fprintln(os.Stderr, "[tg_notify] ERROR: Telegram test message failed:", err)
		release()
		os.Exit(1)
	}
	startPos := "end"
	if *fromStart {
		startPos = "start"
	}
	fmt.Printf("[tg_notify] ARMED: chat_id=%s findings=%s (from=%s, poll=%s)\n",
		chatID, *findingsPath, startPos, pollInterval)

	t := &tailer{path: *findingsPath}
	if !*fromStart {
		if st, err := os.Stat(*findingsPath); err == nil {
			t.offset = st.Size() // skip everything already on disk
		}
	}

	// Sender goroutine: notifications are delivered off the tail loop so a
	// slow Telegram API never delays reading the findings file.
	type job struct{ text string }
	queue := make(chan job, 256)
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for j := range queue {
			if err := client.sendWithRetry(j.text); err != nil {
				fmt.Fprintln(os.Stderr,
					"[tg_notify] ERROR: sendMessage failed (message dropped):", err)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	seen := make(map[string]bool)
	var pending []Finding

	flush := func() {
		if len(pending) == 0 {
			return
		}
		text := formatMessage(pending)
		pending = pending[:0]
		select {
		case queue <- job{text: text}:
		default:
			// queue full — deliver synchronously rather than drop
			if err := client.sendWithRetry(text); err != nil {
				fmt.Fprintln(os.Stderr,
					"[tg_notify] ERROR: sendMessage failed (message dropped):", err)
			}
		}
	}

	// drainLines consumes everything newly appended, queues confirmed
	// findings and returns how many were queued.
	drainLines := func() int {
		queued := 0
		for _, line := range t.poll() {
			var f Finding
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				if *verbose {
					fmt.Fprintln(os.Stderr, "[tg_notify] skip malformed line:", trunc(line, 200))
				}
				continue
			}
			if *verbose {
				fmt.Fprintf(os.Stderr, "[tg_notify] line: conf=%s src=%s type=%s url=%s\n",
					f.Confidence, f.DiscoverySource, f.ReflectionType, trunc(f.URL, 120))
			}
			if !isConfirmed(f) {
				continue
			}
			key := dedupKey(f)
			if seen[key] {
				continue
			}
			seen[key] = true
			pending = append(pending, f)
			queued++
		}
		return queued
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			drainLines() // best effort: pick up anything appended in the last 300ms
			flush()
			close(queue)
			select {
			case <-senderDone:
			case <-time.After(15 * time.Second):
				fmt.Fprintln(os.Stderr,
					"[tg_notify] WARN: sender still busy at shutdown; exiting anyway")
			}
			release()
			fmt.Println("[tg_notify] stopped")
			return
		case <-ticker.C:
			drainLines()
			flush()
		}
	}
}
