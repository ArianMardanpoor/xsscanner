package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

// ANSI Colors
const (
	gray  = "\033[90m"
	reset = "\033[0m"
)

func runNiceKatana(targetURL, outDir string) {
	fmt.Printf("%srunning katana for: %s%s\n", gray, targetURL, reset)

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(targetURL, "_")
	katanaOutput := filepath.Join(outDir, safe+"-katana.txt")

	// Advanced Katana Logic
	extFilter := "json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip"

	fmt.Printf("%sExecuting Katana for %s%s\n", gray, targetURL, reset)
	cmd := exec.Command("katana",
		"-u", targetURL,
		"-d", "2",
		"-js-crawl",
		"-jsluice",
		"-known-files", "all",
		"-automatic-form-fill",
		"-extension-filter", extFilter,
		"-silent",
		"-o", katanaOutput,
	)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error running katana: %v\n", err)
		return
	}

	file, _ := os.Open(katanaOutput)
	count := 0
	if file != nil {
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			count++
		}
		file.Close()
	}

	fmt.Printf("%sdone for %s, results: %d saved to %s%s\n", gray, targetURL, count, katanaOutput, reset)
}

func main() {
	var outDir string
	flag.StringVar(&outDir, "o", "results/katana", "Output directory")
	flag.Parse()

	var targets []string
	if flag.NArg() > 0 {
		arg := flag.Arg(0)
		if info, err := os.Stat(arg); err == nil && !info.IsDir() {
			file, _ := os.Open(arg)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				targets = append(targets, scanner.Text())
			}
			file.Close()
		} else {
			targets = append(targets, arg)
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				targets = append(targets, scanner.Text())
			}
		}
	}

	if len(targets) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  echo domain.com | nice_katana")
		fmt.Println("  nice_katana domain.com")
		fmt.Println("  nice_katana domains.txt")
		return
	}

	for _, target := range targets {
		if target != "" {
			runNiceKatana(target, outDir)
		}
	}
}
