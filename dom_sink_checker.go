package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync" // FIX BUG3: Added sync for WaitGroup and Mutex
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// headerList implements flag.Value for the repeatable -header flag.
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

const canaryHook = `
    window.__capturedSinks = [];
    const pat = /x9canary[a-z]{3}/;
    function track(sink, val) {
        if (pat.test(String(val))) window.__capturedSinks.push(sink);
    }
    const origEval = window.eval;
    window.eval = function(c) { track('eval', c); try { return origEval(c); } catch(e) {} };
    const origST = window.setTimeout;
    window.setTimeout = function(f,d) { track('setTimeout',String(f)); try { return origST(f,d); } catch(e) {} };
    const origSI = window.setInterval;
    window.setInterval = function(f,d) { track('setInterval',String(f)); try { return origSI(f,d); } catch(e) {} };
    const origDW = document.write.bind(document);
    document.write = function(c) { track('document.write',c); return origDW(c); };
    const origDWL = document.writeln.bind(document);
    document.writeln = function(c) { track('document.writeln',c); return origDWL(c); };
    const origAddEventListener = window.addEventListener;
    window.addEventListener = function(type, listener, opts) {
        if (type === 'message' && typeof listener === 'function') {
            const wrapped = function(event) {
                try {
                    var d = event && event.data;
                    var s = typeof d === 'string' ? d : JSON.stringify(d);
                    track('postMessage', s);
                } catch(e) {}
                return listener.apply(this, arguments);
            };
            return origAddEventListener.call(this, type, wrapped, opts);
        }
        return origAddEventListener.call(this, type, listener, opts);
    };
    try {
        var omDesc = Object.getOwnPropertyDescriptor(window, 'onmessage') ||
                     Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
        var omStored = omDesc ? (omDesc.get ? omDesc.get.call(window) : omDesc.value) : null;
        Object.defineProperty(window, 'onmessage', {
            configurable: true,
            enumerable: true,
            get: function() { return omStored; },
            set: function(fn) {
                if (typeof fn !== 'function') { omStored = fn; return; }
                omStored = function(event) {
                    try {
                        var d = event && event.data;
                        var s = typeof d === 'string' ? d : JSON.stringify(d);
                        track('postMessage', s);
                    } catch(e) {}
                    return fn.apply(this, arguments);
                };
            }
        });
    } catch(e) {}
    ['localStorage','sessionStorage'].forEach(function(storageName) {
        try {
            var storage = window[storageName];
            var origSetItem = storage.setItem.bind(storage);
            storage.setItem = function(key, value) {
                track(storageName + '.setItem', value);
                return origSetItem(key, value);
            };
        } catch(e) {}
    });
    const OrigFunction = window.Function;
    window.Function = function(...args) {
        track('Function', args.join(','));
        return OrigFunction.apply(this, args);
    };
    window.Function.prototype = OrigFunction.prototype;
    var props = [
        [Element.prototype, 'innerHTML'],
        [Element.prototype, 'outerHTML'],
        [HTMLImageElement.prototype, 'src'],
        [HTMLScriptElement.prototype, 'src'],
        [HTMLIFrameElement.prototype, 'src'],
        [HTMLAnchorElement.prototype, 'href']
    ];
    props.forEach(function(item) {
        try {
            var proto = item[0], prop = item[1];
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set || !desc.get) return;
            Object.defineProperty(proto, prop, {
                configurable: true,
                get: function() { return desc.get.call(this); },
                set: function(v) { 
                    var s = String(v);
                    if (s === "null" || s === "undefined" || s === "" || s === "null") return desc.set.call(this, v);
                    track(prop, v); 
                    desc.set.call(this, v); 
                }
            });
        } catch(e) {}
    });
`

const xssHook = `
    window.__capturedSinks = [];
    const pat = /x9[a-z]{3}['"` + "`" + `\\;<{]/;
    function track(sink, val) {
        if (pat.test(String(val))) window.__capturedSinks.push(sink);
    }
    const origEval = window.eval;
    window.eval = function(c) { track('eval', c); try { return origEval(c); } catch(e) {} };
    const origST = window.setTimeout;
    window.setTimeout = function(f,d) { track('setTimeout',String(f)); try { return origST(f,d); } catch(e) {} };
    const origSI = window.setInterval;
    window.setInterval = function(f,d) { track('setInterval',String(f)); try { return origSI(f,d); } catch(e) {} };
    const origDW = document.write.bind(document);
    document.write = function(c) { track('document.write',c); return origDW(c); };
    const origDWL = document.writeln.bind(document);
    document.writeln = function(c) { track('document.writeln',c); return origDWL(c); };
    const origAddEventListener = window.addEventListener;
    window.addEventListener = function(type, listener, opts) {
        if (type === 'message' && typeof listener === 'function') {
            const wrapped = function(event) {
                try {
                    var d = event && event.data;
                    var s = typeof d === 'string' ? d : JSON.stringify(d);
                    track('postMessage', s);
                } catch(e) {}
                return listener.apply(this, arguments);
            };
            return origAddEventListener.call(this, type, wrapped, opts);
        }
        return origAddEventListener.call(this, type, listener, opts);
    };
    try {
        var omDesc = Object.getOwnPropertyDescriptor(window, 'onmessage') ||
                     Object.getOwnPropertyDescriptor(Window.prototype, 'onmessage');
        var omStored = omDesc ? (omDesc.get ? omDesc.get.call(window) : omDesc.value) : null;
        Object.defineProperty(window, 'onmessage', {
            configurable: true,
            enumerable: true,
            get: function() { return omStored; },
            set: function(fn) {
                if (typeof fn !== 'function') { omStored = fn; return; }
                omStored = function(event) {
                    try {
                        var d = event && event.data;
                        var s = typeof d === 'string' ? d : JSON.stringify(d);
                        track('postMessage', s);
                    } catch(e) {}
                    return fn.apply(this, arguments);
                };
            }
        });
    } catch(e) {}
    ['localStorage','sessionStorage'].forEach(function(storageName) {
        try {
            var storage = window[storageName];
            var origSetItem = storage.setItem.bind(storage);
            storage.setItem = function(key, value) {
                track(storageName + '.setItem', value);
                return origSetItem(key, value);
            };
        } catch(e) {}
    });
    const OrigFunction = window.Function;
    window.Function = function(...args) {
        track('Function', args.join(','));
        return OrigFunction.apply(this, args);
    };
    window.Function.prototype = OrigFunction.prototype;
    var props = [
        [Element.prototype, 'innerHTML'],
        [Element.prototype, 'outerHTML'],
        [HTMLImageElement.prototype, 'src'],
        [HTMLScriptElement.prototype, 'src'],
        [HTMLIFrameElement.prototype, 'src'],
        [HTMLAnchorElement.prototype, 'href']
    ];
    props.forEach(function(item) {
        try {
            var proto = item[0], prop = item[1];
            var desc = Object.getOwnPropertyDescriptor(proto, prop);
            if (!desc || !desc.set || !desc.get) return;
            Object.defineProperty(proto, prop, {
                configurable: true,
                get: function() { return desc.get.call(this); },
                set: function(v) { 
                    var s = String(v);
                    if (s === "null" || s === "undefined" || s === "" || s === "null") return desc.set.call(this, v);
                    track(prop, v); 
                    desc.set.call(this, v); 
                }
            });
        } catch(e) {}
    });
`

type DomSinkOutput struct {
	URL   string   `json:"url"`
	Sinks []string `json:"sinks"`
}

func safeClose(page *rod.Page) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[WARN] page close recovered: %v\n", r)
		}
	}()
	page.MustClose()
}

// FIX BUG3: Added outMu *sync.Mutex to protect standard output in parallel executions
func checkURL(browser *rod.Browser, targetURL, hookCode string, timeout int, outMu *sync.Mutex, pageHeaders []string) {
	page, err := browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] could not create page: %v\n", err)
		return
	}
	defer safeClose(page)

	// Global auth headers (-cookie/-header): applied right after page creation,
	// before EvalOnNewDocument / Navigate, so every request the page makes
	// carries them. (rod v0.116: SetExtraHeaders takes a []string of alternating
	// key,value pairs and returns a cleanup func — the headers stay active for
	// the page's whole lifetime, so the cleanup func is deliberately discarded.)
	if len(pageHeaders) > 0 {
		if _, err := page.SetExtraHeaders(pageHeaders); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] SetExtraHeaders failed for %s: %v\n", targetURL, err)
		}
	}

	if _, err := page.EvalOnNewDocument(hookCode); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] EvalOnNewDocument failed: %v\n", err)
		return
	}

	err = page.Timeout(time.Duration(timeout) * time.Second).Navigate(targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] navigate failed for %s: %v\n", targetURL, err)
		return
	}

	page.Timeout(time.Duration(timeout) * time.Second).WaitLoad()
	time.Sleep(200 * time.Millisecond)

	result, err := page.Eval(`() => [...new Set(window.__capturedSinks || [])].join(",")`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] eval failed: %v\n", err)
		return
	}

	sinksStr := result.Value.String()
	if sinksStr != "" {
		var sinks []string
		for _, sink := range strings.Split(sinksStr, ",") {
			sink = strings.TrimSpace(sink)
			if sink != "" {
				sinks = append(sinks, sink)
			}
		}
		if len(sinks) > 0 {
			output := DomSinkOutput{
				URL:   targetURL,
				Sinks: sinks,
			}
			jsonData, err := json.Marshal(output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] marshal failed: %v\n", err)
				return
			}
			// FIX BUG3: Use outMu lock to prevent output interleaving from multiple goroutines
			outMu.Lock()
			fmt.Println(string(jsonData))
			outMu.Unlock()
		}
	}
}

func main() {
	xssMode := flag.Bool("xss", false, "Use break-char pattern instead of canary pattern")
	timeout := flag.Int("timeout", 15, "Timeout per page in seconds")
	inputFile := flag.String("l", "", "Input file with URLs")
	// FIX BUG3: Added new flag for concurrency control
	concurrency := flag.Int("c", 4, "number of concurrent browser pages to check in parallel")
	authCookie := flag.String("cookie", "", "Raw Cookie header value sent with every headless page request, e.g. \"session=abc123; other=val\"")
	var authHeaders headerList
	flag.Var(&authHeaders, "header", "Extra HTTP header sent with every headless page request, format \"Name: Value\" (repeatable)")
	flag.Parse()

	// Global auth headers (-cookie/-header): parsed into an alternating
	// key,value,... slice applied per-page via rod's SetExtraHeaders.
	var pageHeaders []string
	if *authCookie != "" {
		pageHeaders = append(pageHeaders, "Cookie", *authCookie)
	}
	for _, e := range authHeaders {
		if idx := strings.Index(e, ":"); idx > 0 {
			k := strings.TrimSpace(e[:idx])
			v := strings.TrimSpace(e[idx+1:])
			if k != "" && v != "" {
			pageHeaders = append(pageHeaders, k, v)
			} else {
				fmt.Fprintf(os.Stderr, "[WARN] ignoring -header %q with empty name or value\n", e)
			}
		} else {
			fmt.Fprintf(os.Stderr, "[WARN] ignoring malformed -header %q (expected \"Name: Value\")\n", e)
		}
	}

	hookCode := canaryHook
	if *xssMode {
		hookCode = xssHook
	}

	u := launcher.New().NoSandbox(true).MustLaunch()
	browser := rod.New().ControlURL(u).MustConnect()
	defer browser.MustClose()

	var scanner *bufio.Scanner
	if *inputFile == "" || *inputFile == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] cannot open file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}

	// FIX BUG3: Created Mutex for thread-safe printing
	var outMu sync.Mutex

	// FIX BUG3: Implemented worker pool based on curl_reflect_checker.go pattern
	c := *concurrency
	if c < 1 {
		c = 1
	}

	urls := make(chan string, c*2)
	var wg sync.WaitGroup

	for i := 0; i < c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urls {
				safeCheckURL(browser, u, hookCode, *timeout, &outMu, pageHeaders)
			}
		}()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.HasPrefix(line, "http") {
			// FIX BUG3: Push URL to channel instead of executing sequentially
			urls <- line
		}
	}

	// FIX BUG3: Close channel and wait for all workers to finish
	close(urls)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] reading input: %v\n", err)
		os.Exit(1)
	}
}

// FIX BUG3: Added outMu *sync.Mutex to parameter list
func safeCheckURL(browser *rod.Browser, targetURL, hookCode string, timeout int, outMu *sync.Mutex, pageHeaders []string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[WARN] checkURL panic for %s: %v\n", targetURL, r)
		}
	}()
	checkURL(browser, targetURL, hookCode, timeout, outMu, pageHeaders)
}
