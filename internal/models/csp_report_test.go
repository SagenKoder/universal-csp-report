package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseCSPReport_ChromeFormats(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		userAgent      string
		expectedFields map[string]string
	}{
		{
			name: "Chrome standard CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/page",
					"referrer": "https://example.com/referrer",
					"violated-directive": "script-src 'self'",
					"original-policy": "default-src 'self'; script-src 'self'",
					"blocked-uri": "https://evil.com/script.js",
					"status-code": 200,
					"script-sample": "console.log('evil')",
					"line-number": 42,
					"column-number": 15,
					"source-file": "https://example.com/inline-script"
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/page",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "https://evil.com/script.js",
				"browser_type":       "chrome",
			},
		},
		{
			name: "Chrome CSP report with inline violation",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/inline-test",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "inline",
					"original-policy": "script-src 'self'",
					"script-sample": "alert('inline script')",
					"line-number": 23,
					"column-number": 5
				}
			}`,
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/inline-test",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "inline",
				"browser_type":       "chrome",
			},
		},
		{
			name: "Chrome CSP report with eval violation",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/eval-test",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "eval",
					"original-policy": "script-src 'self'",
					"script-sample": "eval('malicious code')",
					"line-number": 1,
					"column-number": 1
				}
			}`,
			userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/eval-test",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "eval",
				"browser_type":       "chrome",
			},
		},
		{
			name: "Chrome CSP report with style violation",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/style-test",
					"violated-directive": "style-src 'self'",
					"blocked-uri": "https://fonts.googleapis.com/css",
					"original-policy": "default-src 'self'; style-src 'self'"
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/style-test",
				"violated_directive": "style-src 'self'",
				"blocked_uri":        "https://fonts.googleapis.com/css",
				"browser_type":       "chrome",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.BrowserType != tt.expectedFields["browser_type"] {
				t.Errorf("BrowserType = %v, want %v", report.BrowserType, tt.expectedFields["browser_type"])
			}

			if report.ParsedReport.DocumentURI != tt.expectedFields["document_uri"] {
				t.Errorf("DocumentURI = %v, want %v", report.ParsedReport.DocumentURI, tt.expectedFields["document_uri"])
			}

			if report.ParsedReport.ViolatedDirective != tt.expectedFields["violated_directive"] {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, tt.expectedFields["violated_directive"])
			}

			if report.ParsedReport.BlockedURI != tt.expectedFields["blocked_uri"] {
				t.Errorf("BlockedURI = %v, want %v", report.ParsedReport.BlockedURI, tt.expectedFields["blocked_uri"])
			}
		})
	}
}

func TestParseCSPReport_FirefoxFormats(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		userAgent      string
		expectedFields map[string]string
	}{
		{
			name: "Firefox standard CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/firefox-page",
					"referrer": "",
					"violated-directive": "script-src 'self'",
					"original-policy": "default-src 'self'; script-src 'self'",
					"blocked-uri": "https://malicious.com/script.js"
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/firefox-page",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "https://malicious.com/script.js",
				"browser_type":       "firefox",
			},
		},
		{
			name: "Firefox CSP report with camelCase fields",
			jsonData: `{
				"cspReport": {
					"documentURI": "https://example.com/firefox-camel",
					"violatedDirective": "img-src 'self'",
					"blockedURI": "https://tracker.com/pixel.gif",
					"originalPolicy": "default-src 'self'; img-src 'self'"
				}
			}`,
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/firefox-camel",
				"violated_directive": "img-src 'self'",
				"blocked_uri":        "https://tracker.com/pixel.gif",
				"browser_type":       "firefox",
			},
		},
		{
			name: "Firefox CSP report with inline style violation",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/inline-style",
					"violated-directive": "style-src 'self'",
					"blocked-uri": "inline",
					"original-policy": "style-src 'self'",
					"script-sample": "background: red;",
					"line-number": 15
				}
			}`,
			userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/inline-style",
				"violated_directive": "style-src 'self'",
				"blocked_uri":        "inline",
				"browser_type":       "firefox",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.BrowserType != tt.expectedFields["browser_type"] {
				t.Errorf("BrowserType = %v, want %v", report.BrowserType, tt.expectedFields["browser_type"])
			}

			if report.ParsedReport.DocumentURI != tt.expectedFields["document_uri"] {
				t.Errorf("DocumentURI = %v, want %v", report.ParsedReport.DocumentURI, tt.expectedFields["document_uri"])
			}

			if report.ParsedReport.ViolatedDirective != tt.expectedFields["violated_directive"] {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, tt.expectedFields["violated_directive"])
			}

			if report.ParsedReport.BlockedURI != tt.expectedFields["blocked_uri"] {
				t.Errorf("BlockedURI = %v, want %v", report.ParsedReport.BlockedURI, tt.expectedFields["blocked_uri"])
			}
		})
	}
}

func TestParseCSPReport_SafariFormats(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		userAgent      string
		expectedFields map[string]string
	}{
		{
			name: "Safari standard CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/safari-page",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://ads.com/tracker.js",
					"original-policy": "default-src 'self'"
				}
			}`,
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/safari-page",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "https://ads.com/tracker.js",
				"browser_type":       "safari",
			},
		},
		{
			name: "Safari iOS CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://mobile.example.com/page",
					"violated-directive": "connect-src 'self'",
					"blocked-uri": "wss://websocket.example.com",
					"original-policy": "connect-src 'self'"
				}
			}`,
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			expectedFields: map[string]string{
				"document_uri":       "https://mobile.example.com/page",
				"violated_directive": "connect-src 'self'",
				"blocked_uri":        "wss://websocket.example.com",
				"browser_type":       "safari",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.BrowserType != tt.expectedFields["browser_type"] {
				t.Errorf("BrowserType = %v, want %v", report.BrowserType, tt.expectedFields["browser_type"])
			}

			if report.ParsedReport.DocumentURI != tt.expectedFields["document_uri"] {
				t.Errorf("DocumentURI = %v, want %v", report.ParsedReport.DocumentURI, tt.expectedFields["document_uri"])
			}

			if report.ParsedReport.ViolatedDirective != tt.expectedFields["violated_directive"] {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, tt.expectedFields["violated_directive"])
			}

			if report.ParsedReport.BlockedURI != tt.expectedFields["blocked_uri"] {
				t.Errorf("BlockedURI = %v, want %v", report.ParsedReport.BlockedURI, tt.expectedFields["blocked_uri"])
			}
		})
	}
}

func TestParseCSPReport_EdgeFormats(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		userAgent      string
		expectedFields map[string]string
	}{
		{
			name: "Edge Chromium CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/edge-page",
					"violated-directive": "object-src 'none'",
					"blocked-uri": "https://example.com/plugin.swf",
					"original-policy": "object-src 'none'",
					"status-code": 200
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/edge-page",
				"violated_directive": "object-src 'none'",
				"blocked_uri":        "https://example.com/plugin.swf",
				"browser_type":       "edge",
			},
		},
		{
			name: "Edge Legacy CSP report",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/legacy-edge",
					"violated-directive": "frame-src 'self'",
					"blocked-uri": "https://iframe.malicious.com",
					"original-policy": "frame-src 'self'"
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/legacy-edge",
				"violated_directive": "frame-src 'self'",
				"blocked_uri":        "https://iframe.malicious.com",
				"browser_type":       "edge",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.BrowserType != tt.expectedFields["browser_type"] {
				t.Errorf("BrowserType = %v, want %v", report.BrowserType, tt.expectedFields["browser_type"])
			}

			if report.ParsedReport.DocumentURI != tt.expectedFields["document_uri"] {
				t.Errorf("DocumentURI = %v, want %v", report.ParsedReport.DocumentURI, tt.expectedFields["document_uri"])
			}

			if report.ParsedReport.ViolatedDirective != tt.expectedFields["violated_directive"] {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, tt.expectedFields["violated_directive"])
			}

			if report.ParsedReport.BlockedURI != tt.expectedFields["blocked_uri"] {
				t.Errorf("BlockedURI = %v, want %v", report.ParsedReport.BlockedURI, tt.expectedFields["blocked_uri"])
			}
		})
	}
}

func TestParseCSPReport_ReportToAPI(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		userAgent      string
		expectedFields map[string]string
	}{
		{
			name: "Report-To API CSP report",
			jsonData: `{
				"body": {
					"document-uri": "https://example.com/report-to",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://analytics.com/track.js",
					"original-policy": "script-src 'self'",
					"disposition": "enforce"
				}
			}`,
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/report-to",
				"violated_directive": "script-src 'self'",
				"blocked_uri":        "https://analytics.com/track.js",
				"browser_type":       "chrome",
			},
		},
		{
			name: "Report-To API with snake_case fields",
			jsonData: `{
				"body": {
					"document_uri": "https://example.com/snake-case",
					"violated_directive": "img-src 'self'",
					"blocked_uri": "https://cdn.example.com/image.jpg",
					"original_policy": "img-src 'self'",
					"effective_directive": "img-src",
					"disposition": "report"
				}
			}`,
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
			expectedFields: map[string]string{
				"document_uri":       "https://example.com/snake-case",
				"violated_directive": "img-src 'self'",
				"blocked_uri":        "https://cdn.example.com/image.jpg",
				"browser_type":       "chrome",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.BrowserType != tt.expectedFields["browser_type"] {
				t.Errorf("BrowserType = %v, want %v", report.BrowserType, tt.expectedFields["browser_type"])
			}

			if report.ParsedReport.DocumentURI != tt.expectedFields["document_uri"] {
				t.Errorf("DocumentURI = %v, want %v", report.ParsedReport.DocumentURI, tt.expectedFields["document_uri"])
			}

			if report.ParsedReport.ViolatedDirective != tt.expectedFields["violated_directive"] {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, tt.expectedFields["violated_directive"])
			}

			if report.ParsedReport.BlockedURI != tt.expectedFields["blocked_uri"] {
				t.Errorf("BlockedURI = %v, want %v", report.ParsedReport.BlockedURI, tt.expectedFields["blocked_uri"])
			}
		})
	}
}

func TestParseCSPReport_MalformedAndEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		userAgent   string
		expectError bool
		description string
	}{
		{
			name:        "Empty JSON",
			jsonData:    `{}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle empty JSON gracefully",
		},
		{
			name:        "Invalid JSON",
			jsonData:    `{invalid json}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: true,
			description: "Should return error for invalid JSON",
		},
		{
			name: "Missing required fields",
			jsonData: `{
				"csp-report": {
					"blocked-uri": "https://example.com/script.js"
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle missing required fields",
		},
		{
			name: "Null values",
			jsonData: `{
				"csp-report": {
					"document-uri": null,
					"violated-directive": null,
					"blocked-uri": "https://example.com/script.js"
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle null values",
		},
		{
			name: "Mixed data types",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://example.com/script.js",
					"line-number": "not-a-number",
					"status-code": "200"
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle mixed data types gracefully",
		},
		{
			name: "Very large script sample",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "inline",
					"script-sample": "` + strings.Repeat("a", 1000) + `"
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle very large script samples",
		},
		{
			name: "Unicode characters",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/测试页面",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://example.com/スクリプト.js"
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle Unicode characters",
		},
		{
			name: "Deeply nested structure",
			jsonData: `{
				"report": {
					"csp-report": {
						"document-uri": "https://example.com/nested",
						"violated-directive": "script-src 'self'",
						"blocked-uri": "https://example.com/script.js"
					}
				}
			}`,
			userAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			expectError: false,
			description: "Should handle non-standard nesting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), tt.userAgent, "192.168.1.1")

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none: %s", tt.description)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v - %s", err, tt.description)
			}

			if !tt.expectError && err == nil {
				if report == nil {
					t.Errorf("Expected report but got nil: %s", tt.description)
				} else if report.HumanReadable == "" {
					t.Errorf("Expected human readable text but got empty: %s", tt.description)
				}
			}
		})
	}
}

func TestParseCSPReport_AllDirectiveTypes(t *testing.T) {
	directives := []string{
		"default-src", "script-src", "style-src", "img-src", "connect-src",
		"font-src", "object-src", "media-src", "frame-src", "child-src",
		"form-action", "frame-ancestors", "base-uri", "manifest-src",
		"worker-src", "prefetch-src", "navigate-to", "upgrade-insecure-requests",
		"block-all-mixed-content", "require-sri-for", "trusted-types",
		"require-trusted-types-for", "sandbox",
	}

	for _, directive := range directives {
		t.Run("Directive_"+directive, func(t *testing.T) {
			jsonData := `{
				"csp-report": {
					"document-uri": "https://example.com/test",
					"violated-directive": "` + directive + ` 'self'",
					"blocked-uri": "https://example.com/resource",
					"original-policy": "` + directive + ` 'self'"
				}
			}`

			report, err := ParseCSPReport([]byte(jsonData), "Mozilla/5.0 Chrome/120.0.0.0", "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			if report.ParsedReport.ViolatedDirective != directive+" 'self'" {
				t.Errorf("ViolatedDirective = %v, want %v", report.ParsedReport.ViolatedDirective, directive+" 'self'")
			}
		})
	}
}

func TestHumanReadableGeneration(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		contains []string
	}{
		{
			name: "Complete violation info",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/page",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://evil.com/script.js",
					"source-file": "https://example.com/app.js",
					"line-number": 42,
					"column-number": 15,
					"script-sample": "console.log('test')"
				}
			}`,
			contains: []string{
				"Violated directive: script-src 'self'",
				"Blocked URI: https://evil.com/script.js",
				"Document: https://example.com/page",
				"Source: https://example.com/app.js:42:15",
				"Script sample: console.log('test')",
			},
		},
		{
			name: "Minimal violation info",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/minimal",
					"violated-directive": "img-src 'self'",
					"blocked-uri": "https://tracker.com/pixel.gif"
				}
			}`,
			contains: []string{
				"Violated directive: img-src 'self'",
				"Blocked URI: https://tracker.com/pixel.gif",
				"Document: https://example.com/minimal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := ParseCSPReport([]byte(tt.jsonData), "Mozilla/5.0 Chrome/120.0.0.0", "192.168.1.1")
			if err != nil {
				t.Fatalf("ParseCSPReport() error = %v", err)
			}

			humanReadable := report.HumanReadable
			for _, expected := range tt.contains {
				if !contains(humanReadable, expected) {
					t.Errorf("HumanReadable does not contain '%s'. Got: %s", expected, humanReadable)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestBrowserDetection(t *testing.T) {
	tests := []struct {
		userAgent    string
		expectedType string
	}{
		{
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expectedType: "chrome",
		},
		{
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
			expectedType: "firefox",
		},
		{
			userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			expectedType: "safari",
		},
		{
			userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			expectedType: "edge",
		},
		{
			userAgent:    "Some unknown browser",
			expectedType: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expectedType, func(t *testing.T) {
			detected := detectBrowserType(tt.userAgent)
			if detected != tt.expectedType {
				t.Errorf("detectBrowserType(%s) = %s, want %s", tt.userAgent, detected, tt.expectedType)
			}
		})
	}
}

func TestJSONMarshaling(t *testing.T) {
	jsonData := `{
		"csp-report": {
			"document-uri": "https://example.com/test",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "https://example.com/script.js"
		}
	}`

	report, err := ParseCSPReport([]byte(jsonData), "Mozilla/5.0 Chrome/120.0.0.0", "192.168.1.1")
	if err != nil {
		t.Fatalf("ParseCSPReport() error = %v", err)
	}

	// Test that the report can be marshaled back to JSON
	_, err = json.Marshal(report)
	if err != nil {
		t.Errorf("Failed to marshal report to JSON: %v", err)
	}

	// Test that raw report is preserved
	if report.RawReport == nil {
		t.Error("RawReport should not be nil")
	}

	if report.RawReport["csp-report"] == nil {
		t.Error("RawReport should preserve original structure")
	}
}
