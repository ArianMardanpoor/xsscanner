package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	gray   = "\033[90m"
	reset  = "\033[0m"
	purple = "\033[35m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	cyan   = "\033[36m"
)

var (
	apiURL         = "http://localhost:3131/api/http"
	apiToken       = os.Getenv("WATCHTOWER_API_TOKEN")
	oldTargetsFile = "all_scanned_targets.txt"
	outputDir      = "./results"
)

func logMsg(msg string, color string) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%s[%s]%s %s[BRIDGE] %s%s\n", gray, ts, reset, color, msg, reset)
}

type APIResponse struct {
	Data []struct {
		URL      string `json:"url"`
		FinalURL string `json:"final_url"`
	} `json:"data"`
	Pages int `json:"pages"`
}

func fetchDataFromAPI(mode string) []string {
	logMsg(fmt.Sprintf("Connecting to API in %s mode...", strings.ToUpper(mode)), cyan)
	var allURLs []string
	currentPage := 1
	perPage := 500

	for {
		url := fmt.Sprintf("%s?page=%d&per_page=%d", apiURL, currentPage, perPage)
		if mode == "fresh" {
			url += "&only_changed=true"
		}

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-API-Token", apiToken)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logMsg(fmt.Sprintf("API Error: %v", err), red)
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			logMsg(fmt.Sprintf("API returned status: %d", resp.StatusCode), red)
			break
		}

		var apiResp APIResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			logMsg(fmt.Sprintf("JSON Decode Error: %v", err), red)
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

	logMsg(fmt.Sprintf("Total unique URLs retrieved from API: %d", len(allURLs)), cyan)
	return allURLs
}

func getNewTargetsOnly(targets []string) []string {
	logMsg("Checking for new targets (Diffing)...", cyan)
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

func markAsScanned(url string) {
	f, err := os.OpenFile(oldTargetsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(url + "\n")
	logMsg(fmt.Sprintf("Target marked as scanned: %s", url), green)
}

func runTool(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func processTarget(target string, mode string) {
	logMsg(fmt.Sprintf("--- Starting: %s ---", target), purple+bold)

	u, err := url.Parse(target)
	if err != nil {
		logMsg(fmt.Sprintf("Invalid URL: %s", target), red)
		return
	}
	hostname := u.Hostname()
	if hostname == "" {
		hostname = target
	}
	safeURL := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(target, "_")

	// Step 1: Run Passive, Katana, and Params in parallel
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_passive for %s", target), gray)
		runTool("go", "run", "nice_passive.go", hostname)
	}()

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_katana for %s", target), gray)
		runTool("go", "run", "nice_katana.go", target)
	}()

	go func() {
		defer wg.Done()
		logMsg(fmt.Sprintf("Running nice_params for %s", target), gray)
		runTool("go", "run", "nice_params.go", "-u", target)
	}()

	wg.Wait()

	// Step 2: Aggregate results and run xssniper
	logMsg(fmt.Sprintf("Launching XSSniper for %s", target), cyan)

	jobFile := filepath.Join(outputDir, fmt.Sprintf("job_%s.txt", hostname+"_"+time.Now().Format("20060102150405")))
	os.MkdirAll(outputDir, 0755)

	f, err := os.Create(jobFile)
	if err == nil {
		defer f.Close()
		f.WriteString(target + "\n")

		// 1. Passive results
		passiveFile := filepath.Join("results", "passive", hostname+".passive")
		if pFile, err := os.Open(passiveFile); err == nil {
			io.Copy(f, pFile)
			pFile.Close()
			f.WriteString("\n")
		}

		// 2. Katana results
		katanaFile := filepath.Join("results", "katana", safeURL+"-katana.txt")
		if kFile, err := os.Open(katanaFile); err == nil {
			io.Copy(f, kFile)
			kFile.Close()
			f.WriteString("\n")
		}

		// 3. Params results
		paramFile := filepath.Join("results", "params", hostname+"-param.txt")
		if prFile, err := os.Open(paramFile); err == nil {
			io.Copy(f, prFile)
			prFile.Close()
			f.WriteString("\n")
		}
	}

	// Run xssniper
	runTool("go", "run", "xssniper.go", "-l", jobFile, "-w", "3")

	if mode == "normal" {
		markAsScanned(target)
	}
}

func main() {
	mode := flag.String("mode", "normal", "Scan mode: normal or fresh")
	inputFile := flag.String("i", "", "Input file with targets (skips API)")
	flag.Parse()

	var rawTargets []string
	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			logMsg(fmt.Sprintf("Error opening input file: %v", err), red)
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

	var newTargets []string
	if *mode == "fresh" {
		newTargets = rawTargets
	} else {
		newTargets = getNewTargetsOnly(rawTargets)
	}

	if len(newTargets) == 0 {
		logMsg("No targets to process.", green)
		return
	}

	logMsg(fmt.Sprintf("Ready to process %d targets in %s mode.", len(newTargets), strings.ToUpper(*mode)), cyan)
	for _, target := range newTargets {
		processTarget(target, *mode)
	}
}
