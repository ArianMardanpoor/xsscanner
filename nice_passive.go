// nice_passive.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"reconpipeline/utils"
)

const (
	P_gray  = "\033[90m"
	P_reset = "\033[0m"
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

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func runNicePassive(domain, outDir string) {
	fmt.Printf("%sgathering URLs passively for: %s%s\n", P_gray, domain, P_reset)

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

	tempFile.WriteString(fmt.Sprintf("https://%s/\n", domain))
	tempFile.Close()

	fmt.Printf("%sExecuting waybackurls for %s%s\n", P_gray, domain, P_reset)
	cmd := exec.Command("sh", "-c", "echo $DOMAIN | waybackurls | sort -u | uro")
	cmd.Env = append(os.Environ(), "DOMAIN="+domain)
	if wbOut, err := cmd.Output(); err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.Write(wbOut)
		f.Close()
	}

	fmt.Printf("%sExecuting gau for %s%s\n", P_gray, domain, P_reset)
	if gauOut, err := runCommand("gau", domain, "--threads", "1", "--subs"); err == nil {
		f, _ := os.OpenFile(tempPath, os.O_APPEND|os.O_WRONLY, 0644)
		f.WriteString(gauOut + "\n")
		f.Close()
	}

	// Final dedup pass over the FULL merged content of tempPath (both
	// waybackurls AND gau outputs combined). finalize()'s exact-string-line
	// dedup (uniqueLines map) collapses identical lines but does nothing
	// for near-duplicate URLs that share the same path but differ only by
	// query-param name/value — each such variant is a distinct string but
	// functionally redundant noise that would later pollute x9's
	// candidate-param-generation step with huge volumes of LOW-confidence
	// "candidate_generated" entries for what is really one endpoint.
	//
	// uro collapses those near-duplicates by (path + sorted param-name-set)
	// and keeps one representative URL per group. The waybackurls branch
	// already ran `uro` on its own subset above; this ADDITIONAL pass over
	// the combined file also collapses gau-sourced near-duplicates that
	// were never uro'd, plus any cross-source near-duplicates.
	//
	// Verified via `uro -h`: uro 1.0.2 supports `-i INPUT_FILE -o OUTPUT_FILE`,
	// so we use that mode directly (no shell pipe needed).
	dedupPath := tempPath + ".deduped"
	dedupCmd := exec.Command("uro", "-i", tempPath, "-o", dedupPath)
	if dedupOut, err := dedupCmd.CombinedOutput(); err != nil {
		// Same error-tolerance pattern as waybackurls/gau above: log a
		// warning and fall back to the un-deduped tempPath. Do NOT abort
		// the whole passive run over this — finalize() still runs the
		// exact-line dedup + IsGoodURL filter on whatever tempPath holds.
		fmt.Printf("%s[WARNING] uro final-pass failed for %s: %v (continuing with un-deduped output)%s\n",
			P_gray, domain, err, P_reset)
		if len(dedupOut) > 0 {
			fmt.Printf("%s[WARNING] uro output: %s%s\n", P_gray, strings.TrimSpace(string(dedupOut)), P_reset)
		}
	} else {
		// Replace tempPath with the deduped result so finalize() continues
		// to operate on tempPath unchanged. os.Rename is atomic on the
		// same filesystem (both files are in os.TempDir()).
		if err := os.Rename(dedupPath, tempPath); err != nil {
			// Fall back to copy+remove if rename failed (shouldn't happen
			// since both are in os.TempDir(), but be defensive).
			if data, readErr := os.ReadFile(dedupPath); readErr == nil {
				os.WriteFile(tempPath, data, 0644)
				os.Remove(dedupPath)
			}
		}
	}

	fmt.Printf("%smerging results for: %s%s\n", P_gray, domain, P_reset)
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
		if line == "" || !utils.IsGoodURL(line) {
			continue
		}
		// Strict subdomain scoping: only keep URLs whose host matches
		// the input domain or is a child of it (reject siblings/parents).
		if parsed, err := url.Parse(line); err == nil {
			if !utils.IsSameOrChildHost(parsed.Hostname(), domain) {
				continue
			}
		} else {
			continue
		}
		uniqueLines[line] = true
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
