package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ANSI Colors
const (
	P_gray  = "\033[90m"
	P_reset = "\033[0m"
)

var (
	// FIX BUG2A: Add regexes for URL filtering
	reNumeric     = regexp.MustCompile(`^\d+$`)
	reSemver      = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)
	reCSSValue    = regexp.MustCompile(`^\d+(px|em|rem|vh|vw|ms|fr|%)$`)
	reHighEntropy = regexp.MustCompile(`^[A-Za-z0-9_\-]{40,}$`)
	reUpper       = regexp.MustCompile(`[A-Z]`)
	reDigit       = regexp.MustCompile(`[0-9]`)
	reLower       = regexp.MustCompile(`[a-z]`)
)

// FIX BUG2A: Helper for high entropy segments
func isHighEntropySegment(s string) bool {
	if len(s) < 40 {
		return false
	}
	return reUpper.MatchString(s) && reDigit.MatchString(s) && reLower.MatchString(s)
}

func getHostname(rawURL string) string {
	if strings.HasPrefix(rawURL, "http") {
		u, err := url.Parse(rawURL)
		if err == nil {
			return u.Hostname()
		}
	}
	return rawURL
}

func isGoodURL(rawURL string) bool {
	// FIX BUG2A: Upgrade isGoodURL with more robust filters
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

	// NEW: reject pure numeric paths like /1, /404, /200
	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathSegments) == 0 || (len(pathSegments) == 1 && pathSegments[0] == "") {
		return true
	}
	lastSegment := pathSegments[len(pathSegments)-1]
	if reNumeric.MatchString(lastSegment) {
		return false
	}

	// NEW: reject semver-like paths like /1.8.3, /2.0.1
	if reSemver.MatchString(lastSegment) {
		return false
	}

	// NEW: reject paths that look like hostnames (contain dots, no slashes after)
	// e.g. /sq.airbnb.com /archive.org_bot
	if strings.Count(lastSegment, ".") >= 1 && len(pathSegments) <= 2 {
		return false
	}

	// NEW: reject CSS-like values
	if reCSSValue.MatchString(lastSegment) {
		return false
	}

	// NEW: reject media chunk URLs (high-entropy token paths)
	for _, seg := range pathSegments {
		if isHighEntropySegment(seg) {
			return false
		}
	}

	return true
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, stderr.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func runNicePassive(domain, outDir string) {
	fmt.Printf("%sgathering URLs passively for: %s%s\n", P_gray, domain, P_reset)

	// Ensure output directory exists
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	tempFile, err := os.Create(filepath.Join(os.TempDir(), fmt.Sprintf("passive_%s.txt", domain)))
	if err != nil {
		fmt.Printf("Error creating temp file: %v\n", err)
		return
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// 1. Initial URL
	tempFile.WriteString(fmt.Sprintf("https://%s/\n", domain))
	tempFile.Close()

	// 2. Waybackurls
	fmt.Printf("%sExecuting waybackurls for %s%s\n", P_gray, domain, P_reset)
	cmd := exec.Command("sh", "-c", "echo $DOMAIN | waybackurls | sort -u | uro")
	cmd.Env = append(os.Environ(), "DOMAIN="+domain)
	wbOut, err := cmd.Output()
	if err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.Write(wbOut)
		f.Close()
	}

	// 3. Gau
	fmt.Printf("%sExecuting gau for %s%s\n", P_gray, domain, P_reset)
	gauOut, err := runCommand("gau", domain, "--threads", "1", "--subs")
	if err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.WriteString(gauOut + "\n")
		f.Close()
	}

	fmt.Printf("%smerging results for: %s%s\n", P_gray, domain, P_reset)

	// Finalize: unique and filter extensions
	finalize(tempPath, domain, outDir)
}

func finalize(filePath, domain, outDir string) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening temp file: %v\n", err)
		return
	}
	defer file.Close()

	uniqueLines := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && isGoodURL(line) {
			uniqueLines[line] = true
		}
	}

	if len(uniqueLines) == 0 {
		fmt.Printf("%snothing found for %s%s\n", P_gray, domain, P_reset)
		return
	}

	outputPath := filepath.Join(outDir, domain+".passive")
	outFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outFile.Close()

	count := 0
	for line := range uniqueLines {
		outFile.WriteString(line + "\n")
		count++
	}

	fmt.Printf("%sdone for %s, results: %d saved to %s%s\n", P_gray, domain, count, outputPath, P_reset)
}

func main() {
	var outDir string
	flag.StringVar(&outDir, "o", "results/passive", "Output directory")
	flag.Parse()

	var lines []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
			file.Close()
		} else {
			lines = append(lines, arg)
		}
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				lines = append(lines, scanner.Text())
			}
		}
	}

	if len(lines) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  echo domain.com | nice_passive")
		fmt.Println("  nice_passive domain.com")
		fmt.Println("  nice_passive domains.txt")
		return
	}

	for _, line := range lines {
		domain := getHostname(strings.TrimSpace(line))
		if domain != "" {
			runNicePassive(domain, outDir)
		}
	}
}
