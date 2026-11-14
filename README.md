# xsscanner — deliverables (change 4: x8 removal / fallparams-only + chunked testing)

This change rebuilds the discovery and param-testing pipeline. x8 is gone
entirely; fallparams is the only server-side parameter-discovery engine; and
the final test phase tests every discovered path against fixed-size chunks of
the target-wide parameter set instead of the old per-path own/all scopes.

| File | What it is |
|---|---|
| `main.go` | xsscanner main — chunked test loop, `-chunk` flag, fallparams flag forwarding, query-string harvesting |
| `nice_params.go` | fallparams-only param discovery (x8 removed); `-fallparams-depth` / `-fallparams-crawl-duration` flags |
| `pkg/discoveryutil/discoveryutil.go` | `MergeAndFilter` + final uro-style semantic dedup pass (path + param-name set) |
| `xssniper.go` | unchanged — still consumes `-p <paramFile>`; only the file's content changed (a chunk instead of own/all) |
| `nice_passive.go` / `xsscanner_discover.go` | unchanged — both automatically benefit from the shared `discoveryutil.MergeAndFilter` semantic dedup |
| `pkg/reporter/reporter.go` | unchanged — `Scope` in waf-blocked.json now carries the chunk key instead of own/all |

## What changed

### 1) Semantic (uro-style) dedup in the discovery merge
`discoveryutil.MergeAndFilter` (used by BOTH `main.go`'s normal crawl mode
and `xsscanner_discover`) now runs, after the existing exact-string dedup, a
final `uro -i <tmp> -o <tmp>` pass over the merged list:
- Each source (nice_passive / nice_katana) already uro's its OWN output, but
  near-duplicates that span both sources (or survive filtering) were never
  collapsed — two URLs with the same path and param-name set but different
  values both survived the merge. The new pass collapses them.
- The uro result is used as a KEEP-SET and the surviving URLs are re-emitted
  in their ORIGINAL first-seen order — the target URL stays line 0 and the
  resume-cache key contract (`paths-params.json` keys are exact URL strings)
  is preserved exactly.
- uro is invoked over a temp file (the function only has an in-memory list);
  if uro is missing or fails, a warning goes to stderr and the exact-string
  deduped list is returned — never a crash.

### 2) Query-string param harvesting across the whole discovery list
Every URL in the discovery list (passive OR katana, whether or not it gets
phased) contributes its query-string parameter names — via the existing
`queryParamKeys()` (with `isValidParamName` validation) — to
`allDiscoveredParams`, the target-wide aggregate. fallparams output joins the
same set through the per-path phase loop. The aggregate is written to
`<safeURL>-all-params.txt` (one param per line, sorted, no duplicates) and is
the single source the test chunks are built from.

### 3) nice_params: x8 removed, fallparams-only
- Removed entirely: `runX8`, `extractX8Params`, `x8ParamRegex`, `x8FoundRegex`,
  `cleanupRegex`, the `-no-x8`, `-r` (raw request), `-w` (wordlist) flags,
  `cfg.ReqFile`, `cfg.NoX8`, `cfg.Wordlist`, `buildCombinedWordlist`, the
  `param.txt` / `X8_WORDLIST_PATH` wordlist fallback chain, and
  `checkTool("x8")` in `main()`.
- `runFallparams` is the only engine. Its output is not a wordlist to feed
  anywhere — it IS the discovered parameter list for the URL.
- fallparams is always invoked with `-crawl` (crawl is its discovery engine;
  the old opt-in `-crawl` flag survives only as a default-true debug knob),
  plus `-d <depth>` (default 2, fallparams' own default, passed explicitly)
  and `-ct <seconds>` (default 120s crawl cap; 0 = omit and use fallparams'
  default). Both are settable from nice_params itself
  (`-fallparams-depth`, `-fallparams-crawl-duration`) and forwarded from
  xsscanner's top-level flags of the same names.
- The WAF/block preflight check is unchanged (it is independent of the
  discovery engine that runs after it).
- `Result.X8Params` was removed; `res.FallParams` is the only output source
  for both `-json-out` and `<HOST>-param.txt`.

### 4) Chunked testing in xsscanner (main.go)
- The old two models are GONE: `-allparam` (two-phase own→all) and the
  default interleaved per-path own-params mode. `shouldTestPath`, the own/all
  skip table, `testScopeOwn`/`testScopeAll` and `currentScope` were deleted.
- New flow in `processTarget`:
  1. Phase every path in `discoveryList` with nice_params (unchanged WAF
     block-guard, unchanged `paths-params.json` resume cache).
  2. Harvest query-string keys of every discoveryList URL into the aggregate.
  3. Sort the aggregate (`sortedKeys`), split into chunks of `-chunk` params
     (default 50) — the sorted order IS the chunk order (no shuffle; chunk
     ordering does not matter, and determinism keeps cache keys stable).
  4. For every path × every chunk: one `xssniper -u <path> -p <chunkFile>`
     call. The chunk file is `param_chunk_<pathHash>_<chunkHash>.txt`,
     deleted right after the call (cleanup sweeps stragglers).
- Resume/skip-cache: `<safeURL>-test-state.json` now maps
  `path -> [chunkKey, ...]` where `chunkKey` is the first 10 hex chars of
  sha1 over the chunk's params joined with `,`. Content-based keys mean: when
  newly discovered params shift chunk boundaries, unchanged chunks keep their
  key and stay SKIPPED; only genuinely new/changed chunks are retested.
  `-force` rebuilds everything.
- WAF/block-guard carries `blockCounter` forward across every (path, chunk)
  xssniper call exactly as before; on threshold the rest of the path×chunk
  loop aborts and the path is recorded in `waf-blocked.json` with
  `stage="test"`, `scope=<chunk key>` (the field that used to carry
  "own"/"all").
- The purpose of the chunk phase is a canary/reflection sweep: xssniper
  tests every param in the file it receives via `-p`; no "the file must be
  this path's own params" assumption exists inside xssniper (verified —
  `paramFile` is only forwarded to `x9 -p` and read line-by-line).

## Build & test
```
bash build.sh                                   # per-tool: go build -o <name> <file>.go
go test ./pkg/reporter/ ./pkg/blockguard/ ./pkg/discoveryutil/
```
Notes:
- `nice_katana.go` was NOT in the uploaded zip (build.sh line for it fails
  until the file is restored); everything else builds and all package tests
  pass (`reporter`, `blockguard`, `discoveryutil` incl. the new semantic-dedup
  test, which skips itself when no uro binary is on PATH).
- Manual end-to-end verification (echo server + stub uro/fallparams):
  discovery dedup collapses near-duplicates; `all-params.txt` contains
  query-string keys ∪ fallparams output; xssniper runs ceil(params/chunk)
  times per path; a re-run skips every tested chunk (0 invocations); changing
  `-chunk` or growing the param set retests exactly the chunks whose content
  changed; `-force` re-runs everything.

## Flags summary (this change)
- xsscanner NEW: `-chunk <int>` (default 50; replaces `-allparam`, which was
  removed), `-fallparams-depth <int>` (default 2), `-fallparams-crawl-duration
  <int>` (default 120 seconds).
- xsscanner REMOVED: `-allparam`.
- nice_params NEW: `-fallparams-depth`, `-fallparams-crawl-duration`;
  `-crawl` is now default-true.
- nice_params REMOVED: `-no-x8`, `-w`, `-r`.
- nice_params KEPT (debug): `-no-fall` (skips fallparams — the only engine,
  so nothing will be found), `-keep-temp`, `-max-params`.

Earlier deliverable docs (auth forwarding, DOM sink coverage, backtick
breakout, crawl-stage resume) remain accurate; see the table above for the
file-level summary of that earlier work.




# xsscanner — VPS Setup Guide

## 0. پیش‌نیاز سرور
- Ubuntu 22.04 / 24.04 (یا Debian مشابه) با حداقل 2 vCPU / 4GB RAM
- دسترسی root یا sudo
- یه دامنه یا IP که به سرور وصله (برای proxy/telegram اختیاریه)

---

## 1. آپدیت پایه و پکیج‌های سیستمی

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git build-essential unzip jq python3 python3-pip python3-venv \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 ca-certificates
```

> پکیج‌های `libnss3` و بقیه مربوط به Chromium headless هستن که `dom_sink_checker` و `nice_katana` (برای js-crawl) لازم دارن.

---

## 2. نصب Go (نسخه 1.21+)

```bash
cd /tmp
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz

echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

go version
```

---

## 3. نصب ابزارهای Go-based (katana, waybackurls, gau)

```bash
# Katana (crawler اصلی nice_katana)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# waybackurls (passive discovery)
go install github.com/tomnomnom/waybackurls@latest

# gau (passive discovery)
go install github.com/lc/gau/v2/cmd/gau@latest

```

بعد از نصب چک کن همه در PATH هستن:
```bash
which katana waybackurls gau
```

---

## 4. نصب uro (پایتون - برای dedup معنایی URLها)

```bash
pip3 install --user uro  --break-system-packages
echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
source ~/.bashrc

uro --help
```

---

## 5. نصب fallparams (موتور کشف پارامتر)

```bash
go install github.com/ImAyrix/fallparams@latest
# یا اگه از سورس خاصی نصبش می‌کنی:
# git clone <fallparams-repo-url>
# cd fallparams && go build -o fallparams .
# sudo mv fallparams /usr/local/bin/

fallparams -h
```

⚠️ نکته مهم: کد `nice_params.go` یه بار `fallparams -h` رو اجرا می‌کنه تا ببینه از فلگ `-H`/`-header` پشتیبانی می‌کنه یا نه. اگه نسخه‌ای که نصب کردی این فلگ رو نداره، auth headerها (cookie و غیره) بهش پاس داده نمیشن (warning میده ولی کرش نمی‌کنه).

---

## 6. نصب Chromium برای go-rod (dom_sink_checker)

go-rod خودش در اولین اجرا سعی می‌کنه Chromium رو دانلود کنه (`launcher.New().NoSandbox(true).MustLaunch()`)، ولی روی سرورهای بدون GUI بهتره از قبل نصبش کنی تا دانلود خودکار fail نکنه:

```bash
sudo apt install -y chromium-browser || sudo apt install -y chromium
```

اگه سرور پکیج chromium نداشت (بعضی توزیع‌ها ندارن)، می‌تونی از snap استفاده کنی:
```bash
sudo snap install chromium
```

---

## 7. کلون کردن و بیلد پروژه

```bash
cd /opt
mkdir -p ~/tools && cd ~/tools
git clone https://github.com/ArianMardanpoor/xsscanner
cd xsscanner

go mod tidy
bash build.sh
```

بعد از بیلد باید این باینری‌ها ساخته شده باشن: