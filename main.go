package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ANSI Colors
const (
	M_gray   = "\033[90m"
	M_reset  = "\033[0m"
	M_purple = "\033[35m"
	M_bold   = "\033[1m"
	M_red    = "\033[31m"
	M_green  = "\033[32m"
	M_cyan   = "\033[36m"
)

var (
	// FIX BUG2B: Add regexes for URL filtering
	reNumeric     = regexp.MustCompile(`^\d+$`)
	reSemver      = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	reCSSValue    = regexp.MustCompile(`^\d+(px|em|rem|vh|vw|ms|fr|%)$`)
	reHighEntropy = regexp.MustCompile(`^[A-Za-z0-9_\-]{40,}$`)
	reUpper       = regexp.MustCompile(`[A-Z]`)
	reDigit       = regexp.MustCompile(`[0-9]`)
	reLower       = regexp.MustCompile(`[a-z]`)
)

// FIX BUG2B: Helper for high entropy segments
func isHighEntropySegment(s string) bool {
	if len(s) < 40 {
		return false
	}
	return reUpper.MatchString(s) && reDigit.MatchString(s) && reLower.MatchString(s)
}

// FIX BUG2B: Duplicate isGoodURL for main.go
func isGoodURL(rawURL string) bool {
	extensions := []string{".json", ".js", ".fnt", ".ogg", ".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv", ".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp", ".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf", ".txt", ".xml", ".zip"}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathSegments) == 0 || (len(pathSegments) == 1 && pathSegments[0] == "") {
		return true
	}
	lastSegment := pathSegments[len(pathSegments)-1]

	if reNumeric.MatchString(lastSegment) {
		return false
	}
	if reSemver.MatchString(lastSegment) {
		return false
	}
	if strings.Count(lastSegment, ".") >= 1 && len(pathSegments) <= 2 {
		return false
	}
	if reCSSValue.MatchString(lastSegment) {
		return false
	}
	for _, seg := range pathSegments {
		if isHighEntropySegment(seg) {
			return false
		}
	}

	return true
}

var (
	apiURL          = "http://localhost:3131/api/http"
	apiToken        = "a21uc0lzeTcK"
	oldTargetsFile  = "all_scanned_targets.txt"
	globalOutputDir = "./results"
)

func logMsg(msg string, color string) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[BRIDGE] %s%s\n", M_gray, ts, M_reset, color, msg, M_reset)
}

type APIResponse struct {
	Data []struct {
		URL      string `json:"url"`
		FinalURL string `json:"final_url"`
	} `json:"data"`
	Pages int `json:"pages"`
}

func fetchDataFromAPI(mode string) []string {
	logMsg(fmt.Sprintf("Connecting to API in %s mode...", strings.ToUpper(mode)), M_cyan)
	var allURLs []string
	currentPage := 1
	perPage := 500

	for {
		urlStr := fmt.Sprintf("%s?page=%d&per_page=%d", apiURL, currentPage, perPage)
		if mode == "fresh" {
			urlStr += "&only_changed=true"
		}

		req, _ := http.NewRequest("GET", urlStr, nil)
		req.Header.Set("X-API-Token", apiToken)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logMsg(fmt.Sprintf("API Error: %v", err), M_red)
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			logMsg(fmt.Sprintf("API returned status: %d", resp.StatusCode), M_red)
			break
		}

		var apiResp APIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			logMsg(fmt.Sprintf("JSON Decode Error: %v", err), M_red)
			break
		}

		for _, item := range apiResp.Data {
			target := item.FinalURL
			if target == "" {
				target = item.URL
			}
			if target != "" {
				allURLs = append(allURLs, target)
			}
		}

		if currentPage >= apiResp.Pages || apiResp.Pages == 0 {
			break
		}
		currentPage++
	}

	logMsg(fmt.Sprintf("Total unique URLs retrieved from API: %d", len(allURLs)), M_cyan)
	return allURLs
}

func getNewTargetsOnly(targets []string) []string {
	logMsg("Checking for new targets (Diffing)...", M_cyan)
	scanned := make(map[string]bool)
	file, err := os.Open(oldTargetsFile)
	if err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			scanned[strings.TrimSpace(scanner.Text())] = true
		}
		file.Close()
	}

	var newTargets []string
	for _, t := range targets {
		if !scanned[t] {
			newTargets = append(newTargets, t)
		}
	}
	return newTargets
}

func markAsScanned(urlStr string) {
	f, err := os.OpenFile(oldTargetsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(urlStr + "\n")
	logMsg(fmt.Sprintf("Target marked as scanned: %s", urlStr), M_green)
}

func runBinary(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func getSafeName(u string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(u, "_")
}

func processTarget(target string, isSingleTarget bool) {
	logMsg(fmt.Sprintf("--- Starting: %s ---", target), M_purple+M_bold)

	u, err := url.Parse(target)
	if err != nil {
		logMsg(fmt.Sprintf("Invalid URL: %s", target), M_red)
		return
	}
	hostname := u.Hostname()
	if hostname == "" {
		hostname = target
	}
	safeURL := getSafeName(target)

	// Results subdirectories
	passiveDir := filepath.Join(globalOutputDir, "passive")
	katanaDir := filepath.Join(globalOutputDir, "katana")
	paramsDir := filepath.Join(globalOutputDir, "params")

	os.MkdirAll(passiveDir, 0755)
	os.MkdirAll(katanaDir, 0755)
	os.MkdirAll(paramsDir, 0755)

	// Step 1: Run Passive, Katana, and Params in parallel
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_passive for %s", target), M_gray)
		runBinary("./nice_passive", "-o", passiveDir, hostname)
	}()

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_katana for %s", target), M_gray)
		runBinary("./nice_katana", "-o", katanaDir, target)
	}()

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_params for %s", target), M_gray)
		runBinary("./nice_params", "-u", target, "-d", paramsDir)
	}()

	wg.Wait()

	// Step 2: Aggregate results and run xssniper
	logMsg(fmt.Sprintf("Launching XSSniper for %s", target), M_cyan)

	jobFile := filepath.Join(globalOutputDir, fmt.Sprintf("job_%s.txt", safeURL+"_"+time.Now().Format("20060102150405")))
	paramFilePath := filepath.Join(paramsDir, hostname+"-param.txt")

	f, err := os.Create(jobFile)
	if err == nil {
		defer f.Close()
		f.WriteString(target + "\n")

		var targetHost string
		if isSingleTarget {
			targetHost = u.Host
		}

		// Helper to append file content carefully with optional filtering
		appendSafe := func(path string) {
			if pFile, err := os.Open(path); err == nil {
				scanner := bufio.NewScanner(pFile)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					// Bug 3: Filter results in single-target mode to exclude unrelated hosts
					if isSingleTarget {
						if lURL, err := url.Parse(line); err == nil {
							if lURL.Host != targetHost {
								continue
							}
						} else {
							continue
						}
					}
					if !isGoodURL(line) { // FIX BUG2B: Add quality check
						continue
					}
					f.WriteString(line + "\n")
				}
				pFile.Close()
			}
		}

		appendSafe(filepath.Join(passiveDir, hostname+".passive"))
		appendSafe(filepath.Join(katanaDir, safeURL+"-katana.txt"))
	}

	// Run xssniper
	args := []string{"-l", jobFile, "-p", paramFilePath, "-w", "3"}
	if isSingleTarget {
		args = append(args, "-u", target)
	}
	runBinary("./xssniper", args...)

	markAsScanned(target)
}

func main() {
	mode := flag.String("mode", "normal", "Scan mode: normal or fresh")
	inputFile := flag.String("i", "", "Input file with targets (skips API)")
	targetURL := flag.String("u", "", "Single target URL to scan")
	flag.Parse()

	var newTargets []string
	isSingleTarget := false

	if *targetURL != "" {
		newTargets = []string{*targetURL}
		logMsg(fmt.Sprintf("Single target mode: %s", *targetURL), M_cyan)
		isSingleTarget = true
	} else {
		var rawTargets []string
		if *inputFile != "" {
			file, err := os.Open(*inputFile)
			if err != nil {
				logMsg(fmt.Sprintf("Error opening input file: %v", err), M_red)
				return
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if t := strings.TrimSpace(scanner.Text()); t != "" {
					rawTargets = append(rawTargets, t)
				}
			}
			file.Close()
		} else {
			rawTargets = fetchDataFromAPI(*mode)
		}
		if len(rawTargets) == 0 {
			return
		}

		if *mode == "fresh" {
			newTargets = rawTargets
		} else {
			newTargets = getNewTargetsOnly(rawTargets)
		}
	}

	if len(newTargets) == 0 {
		logMsg("No targets to process.", M_green)
		return
	}

	logMsg(fmt.Sprintf("Ready to process %d targets in %s mode.", len(newTargets), strings.ToUpper(*mode)), M_cyan)
	for _, target := range newTargets {
		processTarget(target, isSingleTarget)
	}
}
