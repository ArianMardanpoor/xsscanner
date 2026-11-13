package blockguard

import (
	"bytes"
	"testing"
)

func TestIsSuspiciousResponse_StatusCodes(t *testing.T) {
	cases := []struct {
		name       string
		statusCode int
		body       []byte
		want       bool
	}{
		{"200 no fp", 200, []byte("<html>hello</html>"), false},
		{"301 no fp", 301, []byte(""), false},
		{"404 no fp", 404, []byte("not found"), false},
		{"500 no fp", 500, []byte("internal error"), false},
		{"403 even with empty body", 403, []byte(""), true},
		{"403 with normal body", 403, []byte("<html>forbidden</html>"), true},
		{"429 even with empty body", 429, []byte(""), true},
		{"503 even with empty body", 503, []byte(""), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsSuspiciousResponse(c.statusCode, c.body)
			if got != c.want {
				t.Errorf("IsSuspiciousResponse(%d, %q) = %v; want %v", c.statusCode, string(c.body), got, c.want)
			}
		})
	}
}

func TestIsSuspiciousResponse_Fingerprints(t *testing.T) {
	fingerprints := []string{
		"cf-browser-verification",
		"Attention Required! | Cloudflare",
		"Just a moment...",
		"Request unsuccessful. Incapsula",
		"__cf_chl_",
		"sucuri_cloudproxy_js",
	}
	for _, fp := range fingerprints {
		t.Run("fp:"+fp, func(t *testing.T) {
			body := []byte("<html><body>" + fp + "</body></html>")
			if !IsSuspiciousResponse(200, body) {
				t.Errorf("IsSuspiciousResponse(200, body with %q) = false; want true (fingerprint match)", fp)
			}
		})
	}

	t.Run("akamai access denied", func(t *testing.T) {
		body := []byte(`<html><body>Access Denied. You don't have permission to access. Akamai Reference #1234</body></html>`)
		if !IsSuspiciousResponse(200, body) {
			t.Errorf("IsSuspiciousResponse(200, body with akamai access denied) = false; want true")
		}
	})

	t.Run("access denied without akamai", func(t *testing.T) {
		body := []byte(`<html><body>Access Denied. You don't have permission.</body></html>`)
		if IsSuspiciousResponse(200, body) {
			t.Errorf("IsSuspiciousResponse(200, body with access denied but no akamai) = true; want false")
		}
	})
}

func TestIsSuspiciousResponse_BodyWindowTruncated(t *testing.T) {
	// A fingerprint past the 8 KiB body window is not seen.
	pad := bytes.Repeat([]byte("x"), 8192)
	body := append(pad, []byte("Just a moment...")...)
	if IsSuspiciousResponse(200, body) {
		t.Errorf("IsSuspiciousResponse(200, fingerprint past window) = true; want false")
	}
	// Within the window: detected.
	body = append([]byte("Just a moment..."), pad...)
	if !IsSuspiciousResponse(200, body) {
		t.Errorf("IsSuspiciousResponse(200, fingerprint inside window) = false; want true")
	}
}

func TestIsSuspiciousResponse_NilBody(t *testing.T) {
	if IsSuspiciousResponse(200, nil) {
		t.Errorf("IsSuspiciousResponse(200, nil) = true; want false")
	}
	if !IsSuspiciousResponse(403, nil) {
		t.Errorf("IsSuspiciousResponse(403, nil) = false; want true (status code trumps nil body)")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		statusCode int
		body       []byte
		wantPrefix string
	}{
		{403, []byte(""), "403-forbidden"},
		{429, []byte(""), "429-too-many-requests"},
		{503, []byte(""), "503-service-unavailable"},
		{200, []byte("Just a moment..."), "waf-fingerprint:"},
		{200, []byte("nothing suspicious"), ""},
	}
	for _, c := range cases {
		got := Classify(c.statusCode, c.body)
		if c.wantPrefix == "" {
			if got != "" {
				t.Errorf("Classify(%d, %q) = %q; want empty", c.statusCode, string(c.body), got)
			}
		} else {
			if !bytes.HasPrefix([]byte(got), []byte(c.wantPrefix)) {
				t.Errorf("Classify(%d, %q) = %q; want prefix %q", c.statusCode, string(c.body), got, c.wantPrefix)
			}
		}
	}
}
