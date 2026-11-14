// Package blockguard provides a single shared block/WAF classification
// primitive used by both the phase stage (nice_params) and the test stage
// (xssniper) of the xsscanner per-path sequential loop.
//
// The classification is deliberately conservative: only HTTP responses that
// strongly indicate a block/WAF are flagged (403/429/503 status codes, or
// bodies whose first 8 KiB contain a known WAF-challenge fingerprint).
// Anything else (200/3xx/404/500/etc. with no fingerprint match) is NOT
// suspicious — the per-target consecutive-suspicious counter that drives the
// abort logic in main.go resets to zero on every non-suspicious response so a
// transient blip never tips a target into "blocked" territory.
package blockguard

import (
	"bytes"
	"strings"
)

// wafFingerprints is the body-fingerprint list previously hard-coded inside
// xssniper.go's detectWAFChallenge(). It is moved here so both nice_params.go
// and xssniper.go can call the SAME logic without duplicating the list.
//
// All comparisons are case-insensitive against the lower-cased body window
// (the body is lower-cased once per call inside IsSuspiciousResponse).
var wafFingerprints = []string{
	"cf-browser-verification",
	"attention required! | cloudflare",
	"just a moment...",
	"request unsuccessful. incapsula",
	"__cf_chl_",
	"sucuri_cloudproxy_js",
}

// IsSuspiciousResponse classifies a single HTTP response as a block/WAF
// signal.
//
//   - statusCode 403, 429 or 503 → suspicious (the canonical WAF/block codes).
//   - Otherwise, reuse the WAF-challenge body-fingerprint check (the
//     fingerprint list + the Akamai "access denied" check previously inside
//     xssniper.go's detectWAFChallenge).
//   - Anything else (200/3xx/404/500/etc., no fingerprint match) is NOT
//     suspicious.
//
// A nil body is treated as empty.
func IsSuspiciousResponse(statusCode int, body []byte) bool {
	if statusCode == 403 || statusCode == 429 || statusCode == 503 {
		return true
	}

	limit := 8192
	if len(body) < limit {
		limit = len(body)
	}
	window := bytes.ToLower(body[:limit])

	for _, fp := range wafFingerprints {
		if bytes.Contains(window, []byte(fp)) {
			return true
		}
	}

	// Akamai "access denied" check: requires BOTH substrings present.
	if bytes.Contains(window, []byte("access denied")) && bytes.Contains(window, []byte("akamai")) {
		return true
	}

	return false
}

// IsSuspiciousResponseStatus is a body-less convenience variant for callers
// that already know the status code but did not fetch a body (e.g. a HEAD
// probe). Purely a statusCode check; never inspects a body.
func IsSuspiciousResponseStatus(statusCode int) bool {
	return statusCode == 403 || statusCode == 429 || statusCode == 503
}

// Classify is a small helper that returns a short human-readable label for the
// reason a response was flagged suspicious (or "" if not suspicious). Useful
// for log lines.
func Classify(statusCode int, body []byte) string {
	if statusCode == 403 || statusCode == 429 || statusCode == 503 {
		switch statusCode {
		case 403:
			return "403-forbidden"
		case 429:
			return "429-too-many-requests"
		case 503:
			return "503-service-unavailable"
		}
		return "suspicious-status"
	}
	if body == nil {
		return ""
	}
	limit := 8192
	if len(body) < limit {
		limit = len(body)
	}
	window := bytes.ToLower(body[:limit])
	for _, fp := range wafFingerprints {
		if bytes.Contains(window, []byte(fp)) {
			return "waf-fingerprint:" + strings.ReplaceAll(fp, " ", "_")
		}
	}
	if bytes.Contains(window, []byte("access denied")) && bytes.Contains(window, []byte("akamai")) {
		return "waf-fingerprint:akamai_access_denied"
	}
	return ""
}
