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
	"strings"
)

// ANSI Colors
const (
	gray  = "\033[90m"
	reset = "\033[0m"
)

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
	fmt.Printf("%sgathering URLs passively for: %s%s\n", gray, domain, reset)

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
	fmt.Printf("%sExecuting waybackurls for %s%s\n", gray, domain, reset)
	cmd := exec.Command("sh", "-c", "echo $DOMAIN | waybackurls | sort -u | uro")
	cmd.Env = append(os.Environ(), "DOMAIN="+domain)
	wbOut, err := cmd.Output()
	if err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.Write(wbOut)
		f.Close()
	}

	// 3. Gau
	fmt.Printf("%sExecuting gau for %s%s\n", gray, domain, reset)
	gauOut, err := runCommand("gau", domain, "--threads", "1", "--subs")
	if err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.WriteString(gauOut + "\n")
		f.Close()
	}

	fmt.Printf("%smerging results for: %s%s\n", gray, domain, reset)

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
		fmt.Printf("%snothing found for %s%s\n", gray, domain, reset)
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

	fmt.Printf("%sdone for %s, results: %d saved to %s%s\n", gray, domain, count, outputPath, reset)
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
