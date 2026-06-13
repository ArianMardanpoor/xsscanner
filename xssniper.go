package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Telegram Configuration ───────────────────────────────────────────────────

type Telegram struct {
	Token  string
	ChatID string
}

func loadEnv() {
	candidates := []string{".env"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if os.Getenv(key) == "" {
					os.Setenv(key, val)
				}
			}
		}
		f.Close()
	}
}

func newTelegram() *Telegram {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	chatID := os.Getenv("TELEGRAM_CHAT_ID")
	if token == "" || chatID == "" {
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID}
}

func (tg *Telegram) notify(targetURL string, findings []string, scanType string) {
	if tg == nil {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🚨 <b>%s XSS Finding!</b>\n\n", scanType))
	sb.WriteString(fmt.Sprintf("🎯 <b>Target:</b> <code>%s</code>\n", escapeHTML(targetURL)))
	sb.WriteString(fmt.Sprintf("📅 <b>Time:</b> %s\n", ts))
	sb.WriteString(fmt.Sprintf("🔢 <b>Count:</b> %d unique endpoint(s)\n\n", len(findings)))

	for i, f := range findings {
		cleanLine := stripANSI(f)
		if len(cleanLine) > 3500 {
			cleanLine = cleanLine[:3500] + "..."
		}
		sb.WriteString(fmt.Sprintf("<code>%d. %s</code>\n", i+1, escapeHTML(cleanLine)))
	}

	payload := map[string]interface{}{
		"chat_id":                  tg.ChatID,
		"text":                     sb.String(),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	body, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.Token)
	http.Post(apiURL, "application/json", bytes.NewReader(body))
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── UI and Logging ────────────────────────────────────────────────────────────

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	purple = "\033[35m"
	cyan   = "\033[36m"
	gray   = "\033[90m"
	white  = "\033[97m"
)

var (
	outputDir      string
	nucleiTemplate string
	domTemplate    string
	canaryTemplate string
	concurrency    int
	workers        int
	mu             sync.Mutex
	tg             *Telegram
	allCrawledURLs []string
)

func logLine(level, color, format string, args ...interface{}) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[%s]%s %s\n", gray, ts, reset, color, level, reset, fmt.Sprintf(format, args...))
}

func stripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return re.ReplaceAllString(str, "")
}

func runPhase(cmdStr string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdStr)
	out, err := cmd.Output()
	return string(out), err
}

// ── Core Logic ────────────────────────────────────────────────────────────────

func processURL(targetURL string, index, total int) {
	logLine("TARGET", white, "[%d/%d] %s", index, total, targetURL)
	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(targetURL, "_")

	// Phase 1: Katana Crawl (Live Discovery)
	logLine("PHASE", yellow, "1/5 Crawling for deep discovery...")
	katanaOutput := filepath.Join(outputDir, safe+"-katana.txt")
	// Advanced Katana Logic (inspired by nice_katana)
	// Using jsluice, automatic form fill, and heavy extension filtering
	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip"
	katanaCmd := fmt.Sprintf("katana -u %s -d 2 -js-crawl -jsluice -known-files all -automatic-form-fill -extension-filter %s -silent -o %s", targetURL, extFilter, katanaOutput)
	runPhase(katanaCmd)

	file, _ := os.Open(katanaOutput)
	sc := bufio.NewScanner(file)
	var targets []string
	for sc.Scan() {
		if u := strings.TrimSpace(sc.Text()); u != "" {
			targets = append(targets, u)
			mu.Lock()
			allCrawledURLs = append(allCrawledURLs, u)
			mu.Unlock()
		}
	}
	file.Close()
	if len(targets) == 0 {
		targets = append(targets, targetURL)
	}

	// Phase 2: Canary Probe (Harmless Detection)
	logLine("PHASE", cyan, "2/5 Canary Probing (GET, POST, JSON, Headers)...")
	probeInput := filepath.Join(outputDir, safe+"-probe-in.txt")
	os.WriteFile(probeInput, []byte(strings.Join(targets, "\n")), 0644)
	probeOutput := filepath.Join(outputDir, safe+"-probe-out.txt")
	runPhase(fmt.Sprintf("go run x9_v2.go -probe -json -headers -i %s -o %s", probeInput, probeOutput))

	// Phase 3: Filter Vulnerable Parameters
	logLine("PHASE", blue, "3/5 Filtering reflective parameters...")
	filterResults, _ := runPhase(fmt.Sprintf("nuclei -l %s -t %s -silent", probeOutput, canaryTemplate))
	if filterResults == "" {
		logLine("INFO", gray, "No reflective parameters found. Skipping heavy attacks.")
		return
	}

	attackInput := filepath.Join(outputDir, safe+"-atk-in.txt")
	os.WriteFile(attackInput, []byte(filterResults), 0644)

	// Phase 4: Heavy Attack (Reflection & DOM)
	logLine("PHASE", purple, "4/5 Executing Heavy Attacks & DOM Scan...")
	finalX9 := filepath.Join(outputDir, safe+"-final.txt")
	runPhase(fmt.Sprintf("go run x9_v2.go -i %s -json -headers -o %s -c %d", attackInput, finalX9, concurrency))

	// Reflection Scan
	if findings, _ := runPhase(fmt.Sprintf("nuclei -l %s -t %s -silent", finalX9, nucleiTemplate)); findings != "" {
		lines := strings.Split(strings.TrimSpace(findings), "\n")
		logLine("VULN", red, "Found %d Reflections!", len(lines))
		tg.notify(targetURL, lines, "Reflection")
	}

	// DOM Scan (Headless)
	if dom, _ := runPhase(fmt.Sprintf("nuclei -l %s -t %s -headless -silent", finalX9, domTemplate)); dom != "" {
		lines := strings.Split(strings.TrimSpace(dom), "\n")
		logLine("VULN", red, "Found %d DOM XSS!", len(lines))
		tg.notify(targetURL, lines, "DOM")
	}
}

func main() {
	urlFile := flag.String("l", "", "URL list file (use '-' for stdin)")
	flag.StringVar(&outputDir, "o", "./output", "Output directory")
	flag.StringVar(&nucleiTemplate, "t", "xss_template_v2.yaml", "Reflection template")
	flag.StringVar(&domTemplate, "dom", "dom_xss.yaml", "DOM template")
	flag.StringVar(&canaryTemplate, "canary", "canary_matcher.yaml", "Canary template")
	flag.IntVar(&concurrency, "c", 10, "x9 concurrency per URL")
	flag.IntVar(&workers, "w", 3, "Parallel URL workers (concurrency for targets)")
	flag.Parse()

	loadEnv()
	tg = newTelegram()
	os.MkdirAll(outputDir, 0755)

	var urls []string
	var scanner *bufio.Scanner
	if *urlFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else if *urlFile != "" {
		file, err := os.Open(*urlFile)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		flag.Usage()
		os.Exit(1)
	}

	for scanner.Scan() {
		if u := strings.TrimSpace(scanner.Text()); u != "" {
			urls = append(urls, u)
		}
	}

	logLine("INFO", cyan, "Starting Pipeline for %d targets with %d workers...", len(urls), workers)

	// Worker Pool Implementation
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string, idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			processURL(target, idx+1, len(urls))
		}(u, i)
	}
	wg.Wait()

	// Phase 5: Final Second-Order XSS Check
	logLine("PHASE", white, "5/5 Final Second-Order Check on all discovered URLs...")
	finalIn := filepath.Join(outputDir, "all_crawled_discovery.txt")
	os.WriteFile(finalIn, []byte(strings.Join(allCrawledURLs, "\n")), 0644)
	if so, _ := runPhase(fmt.Sprintf("nuclei -l %s -t %s -silent", finalIn, nucleiTemplate)); so != "" {
		lines := strings.Split(strings.TrimSpace(so), "\n")
		logLine("VULN", red, "Found %d Second-Order XSS vulnerabilities!", len(lines))
		tg.notify("Global Second-Order Check", lines, "Second-Order")
	}

	fmt.Printf("\n%s[DONE]%s Full Recon & XSS Pipeline Complete.\n", green, reset)
}
