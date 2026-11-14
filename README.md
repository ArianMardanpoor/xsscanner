# xsscanner — deliverables (change 6: runtime — katana timeout visibility + probe-once-per-path)

This change attacks the two time sinks identified in the real-target run log
(webapp.nozbe.com, 34m11s total):

1. **katana timeout → silent stale-cache fallback** — the crawl hit the
   15-minute batch timeout, `nice_katana` exited zero without writing its
   staging file, and the discovery merge silently consumed the PREVIOUS run's
   cached `-katana.txt` with no indication the results were stale. Plus the
   timeout itself was a hardcoded formula with no knob, and the main cost
   driver (`-js-crawl` + `-jsluice` + `-automatic-form-fill` all on) had no
   speed-over-coverage escape hatch.
2. **probe phase repeated per chunk** — for a fixed path, xssniper's
   chunk-independent probe work (x9 probe-file generation + the
   `curl_reflect_checker` GET/JSON/header sweep + location check, ~25-30s per
   path) ran once per (path × chunk) pair instead of once per path: with
   chunk size 50 and 138 aggregate params (3 chunks), every path's constant
   cost was tripled — 7 paths × 3 chunks = 21 full probes instead of
   7 probes + 14 confirm-only runs.

| File | What changed |
|---|---|
| `nice_katana.go` | **NEW FLAGS** `-batch-timeout <duration>` (override the 15m/target-capped-at-3h global batch timeout; invalid values fall back to the formula) and `-light-mode` (drop `-js-crawl`, `-jsluice` and `-automatic-form-fill` — the dominant crawl-time cost on JS-heavy targets; coverage is reduced, speed is not). Timeout/failure log lines now also report `light-mode=` status |
| `main.go` | **NEW** `[KATANA-TIMEOUT]` loud warning when a failed/timed-out crawl falls back to a previous run's cached `-katana.txt` for the discovery merge (mtime + line count included, so stale results are never mistaken for fresh ones). **NEW FLAG** `-katana-batch-timeout` / `-katana-light-mode` forwarded to every nice_katana invocation. **NEW FLAG** `-probe-only-once` (see below). `runPathTest` gained the probe-mode handshake (`-probe-cache` on a path's first tested chunk, `-reuse-probe` on later chunks) |
| `xsscanner_discover.go` | Same `[KATANA-TIMEOUT]` cache-fallback warning + `-katana-batch-timeout` / `-katana-light-mode` forwards as main.go (the two binaries share the crawl_cache, so both must warn identically) |
| `xssniper.go` | **REFACTOR (Option A)**: `processURLFast` split into `populateFromProbeFiles`/`probeURL` (phases 1-3 only: probe generation + reflection sweep, chunk-independent) and `confirmAndAttack` (phase 4 only: confirmParameter + attack loop, chunk-scoped). NEW FLAGS `-probe-cache <dir>` / `-reuse-probe <dir>` / `-probe-params <file>` implement the probe-reuse handshake; a probe-summary JSON (`<safeName>-probe-summary.json`) carries the probe artifacts between invocations. Missing/corrupt summary → automatic fresh-probe fallback (reuse is an optimization, never a correctness dependency). Legacy no-flag behavior is byte-for-byte the old full pipeline |
| `probeonce_test.go` | **NEW** — probe-summary round-trip (every field confirmAndAttack depends on survives write→load), on-disk JSON key contract (the -probe-cache/-reuse-probe handshake), missing/corrupt-summary fresh-probe fallback, skip-artifacts-never-cached |

## What changed

### 1) nice_katana: `-batch-timeout` and `-light-mode`
- The global batch timeout was `15*len(targets)` minutes hard-capped at 3h
  with no override. `-batch-timeout 10m` (any Go duration) now replaces the
  formula — a heavy single target can fail fast and retry instead of eating
  the whole budget, or get a longer leash when coverage matters more than
  wall-clock time. Empty/invalid/non-positive values keep the old formula
  (fully backward compatible; the startup line prints the effective value).
- `-light-mode` removes `-js-crawl`, `-jsluice` and `-automatic-form-fill`
  from the katana invocation. Those three features together are the reason
  JS-heavy targets (the nozbe profile: `jsluice=true` in the timeout log
  line) outrun the budget — every discovered .js is fetched, parsed and
  endpoint-extracted, and every HTML form is analyzed and auto-filled. In
  light mode katana walks plain links only: parameters that live exclusively
  in JS files or `<form>` inputs are missed this run, but the crawl
  completes in a fraction of the time. Full mode (default) is unchanged.
- Both knobs are forwarded from the orchestrators: `xsscanner
  -katana-batch-timeout 20m -katana-light-mode ...` and the same flags on
  `xsscanner_discover`.

### 2) Loud `[KATANA-TIMEOUT]` cache-fallback warning
`nice_katana` deliberately exits zero even when katana itself timed out (it
logs and returns without writing the staging file), and the resume design
means a previous run's `<safeURL>-katana.txt` may still sit in
`results/crawl_cache/`. The discovery merge consumes whatever is there —
previously with zero indication it was stale. Now, whenever a crawl attempt
ends without writing its `.done` sentinel while a cached `-katana.txt`
exists, both `main.go` and `xsscanner_discover.go` print:

```
[KATANA-TIMEOUT] <target>: fresh crawl did not complete this run — falling
back to cached <file> (mtime <ts>, <n> line(s)) for the discovery merge;
discovery results may be incomplete/stale and the crawl will be retried on
the next run
```

The `.done` sentinel logic, the retry-on-next-run semantics and the
`crawl_cache/` layout are all unchanged — only the visibility changed.

### 3) probe-once-per-path (`-probe-only-once`, Option A refactor)
- **The split**: `processURLFast` is gone. `populateFromProbeFiles`
  (exported via the thin `probeURL` wrapper) runs the chunk-independent
  phases 1-3 and returns enriched `ProbeArtifacts` (now carrying the raw
  `P3Findings` map); `confirmAndAttack(art, restrictToParamFile)` runs the
  chunk-dependent phase 4. In legacy mode (no probe flags) the main loop
  calls probe → confirm back-to-back per URL, reproducing the old behavior
  exactly (same log lines, same findings, same WAF/block-guard gating).
- **The handshake** (driven by xsscanner's chunked test loop under
  `-probe-only-once`): the first actually-tested chunk of a path invokes
  `xssniper -probe-cache <dir> -probe-params <full param list>` (fresh
  probe; artifacts persisted as `<safeName(path)>-probe-summary.json`),
  later chunks invoke `xssniper -reuse-probe <dir>` (artifacts loaded;
  straight to confirm+attack restricted to the chunk's params via `-p`).
  Per-path cost: `N_chunks × (probe + confirm)` → `probe + N_chunks × confirm`.
- **Full-set probe coverage**: `-probe-params` carries the target-wide FULL
  sorted param list (xsscanner writes it to
  `probe_cache/probe_params.txt` before the test loop) so the single shared
  probe canaries EVERY chunk's params — without it, later chunks' params
  would never receive a canary (the probe would only cover chunk 1).
- **Confirm asymmetry (deliberate, verified empirically)**: the PROBING
  invocation confirms ALL phase-3 findings (legacy behavior). Phase-3
  findings routinely include params that live in NO chunk (x9's built-in
  default list, the path's own query-string params) — strict chunk-scoping
  on the probing run would silently downgrade those from confirmed to
  likely (reproduced on the echo-server test, then fixed). Only the
  `-reuse-probe` invocations chunk-scope their confirm (their whole purpose
  is covering their chunk), and only the probing invocation runs the
  candidate-header confirm loop (headers come from the shared probe, not
  from any chunk). The union of all invocations' confirms is a superset of
  the legacy single-run confirm.
- **WAF/block-guard preserved verbatim**: the counter still starts from
  `-block-counter-start`, still updates through `recordResponse` on every
  request, still gates the confirm loop / attack stage / DOM stage at the
  same points, and still reports `{blockDetected, blockCounterEnd}` via
  `-block-status-out` at the end of every invocation — the later-chunk runs
  (which make zero probe requests but full confirm requests) participate in
  the same shared counter exactly as before. `waf-blocked.json`,
  `paths-params.json`, `test-state.json` formats are untouched.
- **Never a correctness dependency**: a missing or corrupt probe summary
  makes the reuse run fall back to a fresh probe (logged) — the optimization
  degrades to legacy behavior, it can never lose findings.
- **Resume interplay**: chunk-level skip via test-state consumes nothing, so
  a path's first ACTUALLY-tested chunk probes (whether or not earlier chunks
  were skipped as already-tested). The probe cache lives under the target's
  `xssniper_out/` dir and is removed with it at cleanup — no new persistent
  state files.

## Expected runtime impact (the nozbe profile)
| Stage | Before | After |
|---|---|---|
| katana crawl | 15m timeout hit, silent stale-cache fallback, next run re-crawls from scratch | `-katana-batch-timeout` right-sizes the budget; `-katana-light-mode` cuts the dominant JS/form-processing cost; stale fallback (if it still happens) is loud and dated |
| test phase | 7 paths × 3 chunks × (~25-30s probe + confirm) ≈ 21 full probes | `-probe-only-once`: 7 probes + 14 confirm-only runs ≈ **-12 to -15 minutes** on this profile |

## Build & test
```
bash build.sh                                   # per-tool: go build -o <name> <file>.go
go test ./pkg/reporter/ ./pkg/blockguard/ ./pkg/discoveryutil/
go test xssniper.go probeonce_test.go           # probe-once split unit tests
go test nice_params.go fallparams_test.go       # (unchanged, still passing)
```
Manual end-to-end verification (selective-reflection local server, 2 paths ×
2 chunks with `-chunk 2`): legacy mode probes once per (path × chunk) — 4
full probes; `-probe-only-once` runs exactly 1 fresh probe per path (2 fresh
+ 2 `[PROBE-REUSE] ... loaded cached probe artifacts` reuses), and the
probing invocations report the SAME confirmed findings as the legacy run
(`id/name/next/q [confirmed]` — a first draft that chunk-scoped the probing
run's confirm downgraded these to [likely]; the asymmetry above is the fix,
re-verified). test-state.json records every completed chunk exactly as
before; an invocation killed mid-chunk leaves its chunk unrecorded and the
next run retries it (verified by killing a run mid-attack).

## Flags summary (this change)
- xsscanner NEW: `-katana-batch-timeout <duration>` (forwarded),
  `-katana-light-mode` (forwarded), `-probe-only-once` (default off —
  legacy per-chunk full pipeline preserved).
- xsscanner_discover NEW: `-katana-batch-timeout`, `-katana-light-mode`
  (same forwards).
- nice_katana NEW: `-batch-timeout <duration>`, `-light-mode`.
- xssniper NEW (driven by xsscanner; rarely used by hand):
  `-probe-cache <dir>`, `-reuse-probe <dir>`, `-probe-params <file>`.
- No changes to waf-blocked.json / paths-params.json / test-state.json
  formats; no changes to the .done-sentinel crawl resume contract.

Change 5's table (still accurate for everything not touched here):
`nice_params.go` — fallparams output capture (explicit `-o`, both channels
parsed, loud both-empty warning); `pkg/spadetect/spadetect.go` — SPA
false-positive fix (low visible text alone no longer classifies SPA);
`fallparams_test.go` / `pkg/spadetect/spadetect_test.go` — the matching
regression tests. Change 4's table: `pkg/discoveryutil/discoveryutil.go` —
`MergeAndFilter` + uro-style semantic dedup; `pkg/reporter/reporter.go` —
`Scope` in waf-blocked.json carries the chunk key. Payload generation,
WAF/block-guard counter logic, chunking, and pkg/reflectctx are all untouched
by this change.

## Detailed notes from change 5 (context)

### nice_params: x8 removed, fallparams-only (change 5)
- Removed entirely: `runX8`, `extractX8Params`, `x8ParamRegex`,
  `x8FoundRegex`, `cleanupRegex`, the `-no-x8`, `-r`, `-w` flags,
  `cfg.ReqFile`, `cfg.NoX8`, `cfg.Wordlist`, `buildCombinedWordlist`, the
  `param.txt` / `X8_WORDLIST_PATH` fallback chain, `checkTool("x8")`.
- `runFallparams` is the only engine; invoked with `-crawl`, `-d <depth>`
  (default 2) and `-ct <seconds>` (default 120s; 0 = fallparams default).
  Settable from nice_params (`-fallparams-depth`,
  `-fallparams-crawl-duration`) and forwarded from xsscanner's same-named
  top-level flags. The WAF/block preflight check is unchanged.
- `Result.X8Params` removed; `res.FallParams` is the only output source for
  both `-json-out` and `<HOST>-param.txt`.

### Chunked testing in xsscanner (change 4, unchanged by this change)
- The old `-allparam` two-phase and interleaved own-params models are gone;
  after discovery, the target-wide aggregate param set is sorted, split into
  `-chunk`-sized chunks, and every path is tested against every chunk (one
  xssniper call per pair, chunk file `param_chunk_<pathHash>_<chunkHash>.txt`).
- Resume: `test-state.json` maps `path -> [chunkKey, ...]`, chunkKey = first
  10 hex chars of sha1 over the chunk's params joined with `,` — content-based,
  so unchanged chunks stay skipped when new params shift boundaries. `-force`
  rebuilds everything.
- WAF/block-guard carries `blockCounter` forward across every (path, chunk)
  call; on threshold the loop aborts and the path is recorded in
  `waf-blocked.json` with `stage="test"`, `scope=<chunk key>`.
- xssniper makes no "the -p file is this path's own params" assumption —
  every param in the file it receives is tested (a canary/reflection sweep
  of the parameter space).

---





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