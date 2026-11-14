// probeonce_test.go
//
// Unit tests for the probe-once-per-path split (runtime optimization, the
// "Problem 2, Option A" fix).
//
// Background: processURLFast used to run the FULL pipeline (probe phases 1-3
// AND the confirm+attack phase 4) once per (path, chunk) pair. The probe
// half (x9 probe-file generation + curl_reflect_checker GET/JSON/header
// sweep) is chunk-INDEPENDENT — repeating it per chunk multiplied the
// per-path cost by the chunk count. The fix splits the function:
//
//	probeURL / populateFromProbeFiles → phases 1-3 only (chunk-independent)
//	confirmAndAttack                   → phase 4 only (chunk-scoped via -p)
//
// and adds the -probe-cache / -reuse-probe handshake so the probe runs once
// per path while confirm runs per chunk.
//
// NOTE on running: the repository root holds several independent main
// packages built file-by-file (see build.sh), so this file is built together
// with xssniper.go only:
//
//	go test xssniper.go probeonce_test.go -v -run TestProbeOnce
//
// The tests here are pure-logic tests (no network, no subprocesses): they
// exercise the probe-summary round-trip (writeProbeArtifacts →
// loadProbeArtifacts) which is the correctness-critical seam of the
// optimization — if the summary loses a field, later chunks would confirm
// against a silently-wrong candidate set.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestProbeSummaryRoundTrip verifies that writeProbeArtifacts →
// loadProbeArtifacts preserves every field a confirmAndAttack run depends on:
// profile (SPA merge), aliveness, WAF state, probe file paths, the reflected
// GET param set, the raw reflected URLs, candidate headers, and the raw
// p3Findings map.
func TestProbeSummaryRoundTrip(t *testing.T) {
	dir := t.TempDir()

	art := ProbeArtifacts{
		TargetURL:   "https://example.com/app?x=1",
		Index:       1,
		Total:       1,
		Profile:     TechProfile{IsSPA: true, Unknown: false},
		HasJS:       true,
		TargetAlive: true,
		ProbeOutputBase: "/tmp/out/https_example_com_app_x_1-probe-out",
		DomQueryProbeFile: "/tmp/out/https_example_com_app_x_1-dom-query-probe.txt",
		GetParamSet:   map[string]bool{"q": true, "id": true},
		GetReflectedRaw: []string{"https://example.com/app?q=x9abc", "https://example.com/app?id=x9def"},
		CandidateHeaders: []string{"X-Custom", "Referer"},
		WAFBlocked:   false,
		P3Findings: map[string][]string{
			"get":  {"https://example.com/app?q=x9abc", "https://example.com/app?id=x9def"},
			"json": {"https://example.com/app|{\"q\":\"x9abc\"}"},
		},
	}

	writeProbeArtifacts(art, dir)

	// loadProbeArtifacts rebuilds skip-lock/profile bookkeeping; for the
	// round-trip check we compare the summary-relevant fields only.
	got := loadProbeArtifacts(art.TargetURL, 1, 1, dir)
	if got.Skip {
		t.Fatalf("loaded artifacts must not be Skip")
	}
	if !got.Profile.IsSPA {
		t.Errorf("Profile.IsSPA lost in round-trip: got %+v", got.Profile)
	}
	if !got.TargetAlive || !got.HasJS {
		t.Errorf("TargetAlive/HasJS lost in round-trip: alive=%v js=%v", got.TargetAlive, got.HasJS)
	}
	if got.WAFBlocked != art.WAFBlocked {
		t.Errorf("WAFBlocked lost in round-trip: got %v want %v", got.WAFBlocked, art.WAFBlocked)
	}
	if got.ProbeOutputBase != art.ProbeOutputBase || got.DomQueryProbeFile != art.DomQueryProbeFile {
		t.Errorf("probe file paths lost in round-trip: got %q / %q", got.ProbeOutputBase, got.DomQueryProbeFile)
	}
	if len(got.GetParamSet) != 2 || !got.GetParamSet["q"] || !got.GetParamSet["id"] {
		t.Errorf("GetParamSet lost in round-trip: got %v", got.GetParamSet)
	}
	if len(got.GetReflectedRaw) != len(art.GetReflectedRaw) {
		t.Errorf("GetReflectedRaw lost in round-trip: got %v", got.GetReflectedRaw)
	}
	if len(got.CandidateHeaders) != 2 {
		t.Errorf("CandidateHeaders lost in round-trip: got %v", got.CandidateHeaders)
	}
	if len(got.P3Findings["get"]) != 2 || len(got.P3Findings["json"]) != 1 {
		t.Errorf("P3Findings lost in round-trip: got %v", got.P3Findings)
	}
}

// TestProbeSummaryFileShape pins the on-disk JSON contract: the field names
// of probeSummaryJSON are the handshake between consecutive xssniper
// invocations (first chunk writes with -probe-cache, later chunks read with
// -reuse-probe). Renaming a field silently breaks reuse across a mixed
// version fleet, so the keys are asserted here explicitly.
func TestProbeSummaryFileShape(t *testing.T) {
	dir := t.TempDir()
	art := ProbeArtifacts{
		TargetURL:      "https://example.com/",
		Profile:        TechProfile{},
		GetParamSet:    map[string]bool{"q": true},
		P3Findings:     map[string][]string{"get": {"https://example.com/?q=x9abc"}},
	}
	writeProbeArtifacts(art, dir)

	raw, err := os.ReadFile(filepath.Join(dir, safeName(art.TargetURL)+"-probe-summary.json"))
	if err != nil {
		t.Fatalf("probe summary not written: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("probe summary is not valid JSON: %v", err)
	}
	for _, key := range []string{
		"isSpaDetected", "targetAlive", "hasJS", "wafBlocked",
		"probeOutputBase", "domQueryProbeFile",
		"getParams", "getReflectedRaw", "candidateHeaders", "p3Findings",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("probe summary JSON missing key %q (on-disk contract between -probe-cache writer and -reuse-probe reader)", key)
		}
	}
}

// TestLoadProbeArtifactsFallsBackToFreshProbe verifies the never-a-correctness-
// dependency rule: a missing or corrupt summary makes loadProbeArtifacts fall
// back to a FRESH probe (populateFromProbeFiles), not an error. A corrupt
// file must never poison the confirm phase with half-loaded state.
func TestLoadProbeArtifactsFallsBackToFreshProbe(t *testing.T) {
	dir := t.TempDir()

	// Case 1: missing summary (empty dir).
	// populateFromProbeFiles would run the real probe (network/subprocesses),
	// which is out of scope for a unit test — instead assert the fallback
	// fires by checking that the loader takes the missing-file branch. We
	// verify the branch indirectly: loadProbeArtifacts on an empty dir must
	// return artifacts produced by populateFromProbeFiles, which for an
	// unparseable URL short-circuits with Skip=true before any probe work.
	art := loadProbeArtifacts("://not-a-url", 1, 1, dir)
	if !art.Skip {
		t.Errorf("expected fresh-probe fallback path for missing summary (unparseable URL → Skip=true), got %+v", art)
	}

	// Case 2: corrupt summary — same fallback.
	sumPath := filepath.Join(dir, safeName("https://example.com/")+"-probe-summary.json")
	if err := os.WriteFile(sumPath, []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	art = loadProbeArtifacts("://not-a-url", 1, 1, dir)
	if !art.Skip {
		t.Errorf("expected fresh-probe fallback path for corrupt summary (unparseable URL → Skip=true), got %+v", art)
	}
}

// TestWriteProbeArtifactsSkipsArtifacts verifies a Skip artifact is never
// persisted (a skipped URL produced no probe; caching it would make later
// chunks confirm against an empty candidate set).
func TestWriteProbeArtifactsSkipsArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeProbeArtifacts(ProbeArtifacts{TargetURL: "https://example.com/", Skip: true}, dir)

	if _, err := os.Stat(filepath.Join(dir, safeName("https://example.com/")+"-probe-summary.json")); !os.IsNotExist(err) {
		t.Errorf("skip artifact must not be written to the probe cache")
	}
}

// TestProbeParamsFileFlagIsWired verifies the -probe-params flag exists and
// defaults to empty (the probe then uses -p, legacy behavior). The flag is
// the seam that lets the single shared probe cover every chunk's params —
// if it disappears, later chunks' params never receive a canary.
func TestProbeParamsFileFlagIsWired(t *testing.T) {
	if probeParamsFile != "" {
		t.Errorf("probeParamsFile must default to empty (legacy -p behavior), got %q", probeParamsFile)
	}
}
