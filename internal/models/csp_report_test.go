package models

import (
	"strings"
	"testing"
)

func TestParseCSPReports_StandardFormat(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected ParsedCSPReport
	}{
		{
			name: "Standard CSP format with kebab-case",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/page.html",
					"referrer": "https://example.com/",
					"violated-directive": "script-src 'self'",
					"effective-directive": "script-src",
					"original-policy": "default-src 'self'",
					"blocked-uri": "https://evil.com/script.js",
					"status-code": 200,
					"source-file": "https://example.com/page.html",
					"line-number": 10,
					"column-number": 5
				}
			}`,
			expected: ParsedCSPReport{
				DocumentURI:        "https://example.com/page.html",
				Referrer:           "https://example.com/",
				ViolatedDirective:  "script-src 'self'",
				EffectiveDirective: "script-src",
				OriginalPolicy:     "default-src 'self'",
				BlockedURI:         "https://evil.com/script.js",
				SourceFile:         "https://example.com/page.html",
			},
		},
		{
			name: "Firefox camelCase format",
			jsonData: `{
				"cspReport": {
					"documentURI": "https://example.com/page",
					"violatedDirective": "img-src 'self'",
					"blockedURI": "data",
					"lineNumber": 25,
					"sha256": "sha256-abcd1234"
				}
			}`,
			expected: ParsedCSPReport{
				DocumentURI:       "https://example.com/page",
				ViolatedDirective: "img-src 'self'",
				BlockedURI:        "data",
				SHA256:            "sha256-abcd1234",
			},
		},
		{
			name: "Legacy WebKit format with url variations",
			jsonData: `{
				"csp-report": {
					"document-url": "https://example.com/legacy",
					"blocked-url": "https://fonts.googleapis.com/css",
					"violated-directive": "style-src 'self'",
					"line-number": "25",
					"column-number": "10"
				}
			}`,
			expected: ParsedCSPReport{
				DocumentURI:       "https://example.com/legacy",
				BlockedURI:        "https://fonts.googleapis.com/css",
				ViolatedDirective: "style-src 'self'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports, err := ParseCSPReports([]byte(tt.jsonData), "test-agent", "127.0.0.1")
			if err != nil {
				t.Fatalf("Failed to parse report: %v", err)
			}

			if len(reports) != 1 {
				t.Fatalf("Expected 1 report, got %d", len(reports))
			}

			report := reports[0]
			parsed := report.ParsedReport

			if parsed.DocumentURI != tt.expected.DocumentURI {
				t.Errorf("DocumentURI: expected %s, got %s", tt.expected.DocumentURI, parsed.DocumentURI)
			}
			if parsed.ViolatedDirective != tt.expected.ViolatedDirective {
				t.Errorf("ViolatedDirective: expected %s, got %s", tt.expected.ViolatedDirective, parsed.ViolatedDirective)
			}
			if parsed.BlockedURI != tt.expected.BlockedURI {
				t.Errorf("BlockedURI: expected %s, got %s", tt.expected.BlockedURI, parsed.BlockedURI)
			}
			if tt.expected.SHA256 != "" && parsed.SHA256 != tt.expected.SHA256 {
				t.Errorf("SHA256: expected %s, got %s", tt.expected.SHA256, parsed.SHA256)
			}
		})
	}
}

func TestParseCSPReports_ChromeBatchFormat(t *testing.T) {
	jsonData := `[
		{
			"type": "csp-violation",
			"age": 10,
			"url": "https://example.com/page.html",
			"user_agent": "Mozilla/5.0",
			"body": {
				"blockedURL": "https://cdn.evil.com/script.js",
				"columnNumber": 0,
				"disposition": "enforce",
				"documentURL": "https://example.com/page.html",
				"effectiveDirective": "script-src-elem",
				"lineNumber": 0,
				"originalPolicy": "script-src 'self'",
				"referrer": "https://example.com/",
				"statusCode": 0,
				"violatedDirective": "script-src-elem"
			}
		},
		{
			"type": "csp-violation",
			"age": 150,
			"url": "https://example.com/page.html",
			"user_agent": "Mozilla/5.0",
			"body": {
				"blockedURL": "inline",
				"columnNumber": 42,
				"disposition": "enforce",
				"documentURL": "https://example.com/page.html",
				"effectiveDirective": "style-src-elem",
				"lineNumber": 58,
				"sample": "body { background: red; }",
				"violatedDirective": "style-src-elem"
			}
		}
	]`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse batch reports: %v", err)
	}

	if len(reports) != 2 {
		t.Fatalf("Expected 2 reports, got %d", len(reports))
	}

	// Check first report
	report1 := reports[0].ParsedReport
	if report1.DocumentURI != "https://example.com/page.html" {
		t.Errorf("Report 1 DocumentURI: expected https://example.com/page.html, got %s", report1.DocumentURI)
	}
	if report1.BlockedURI != "https://cdn.evil.com/script.js" {
		t.Errorf("Report 1 BlockedURI: expected https://cdn.evil.com/script.js, got %s", report1.BlockedURI)
	}
	if report1.EffectiveDirective != "script-src-elem" {
		t.Errorf("Report 1 EffectiveDirective: expected script-src-elem, got %s", report1.EffectiveDirective)
	}

	// Check second report
	report2 := reports[1].ParsedReport
	if report2.BlockedURI != "inline" {
		t.Errorf("Report 2 BlockedURI: expected inline, got %s", report2.BlockedURI)
	}
	if report2.ScriptSample != "body { background: red; }" {
		t.Errorf("Report 2 ScriptSample: expected 'body { background: red; }', got %s", report2.ScriptSample)
	}
}

func TestParseCSPReports_ReportToSingleFormat(t *testing.T) {
	jsonData := `{
		"type": "csp-violation",
		"age": 0,
		"url": "https://example.com/checkout",
		"user_agent": "Mozilla/5.0",
		"body": {
			"blockedURL": "wss://realtime.untrusted.com/socket",
			"disposition": "report",
			"documentURL": "https://example.com/checkout",
			"effectiveDirective": "connect-src",
			"originalPolicy": "default-src 'self'; connect-src 'self' https://api.example.com",
			"violatedDirective": "connect-src"
		}
	}`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse Report-To format: %v", err)
	}

	if len(reports) != 1 {
		t.Fatalf("Expected 1 report, got %d", len(reports))
	}

	parsed := reports[0].ParsedReport
	if parsed.BlockedURI != "wss://realtime.untrusted.com/socket" {
		t.Errorf("BlockedURI: expected wss://realtime.untrusted.com/socket, got %s", parsed.BlockedURI)
	}
	if parsed.Disposition != "report" {
		t.Errorf("Disposition: expected report, got %s", parsed.Disposition)
	}
}

func TestParseCSPReports_SpecialBlockedURIValues(t *testing.T) {
	tests := []struct {
		name        string
		blockedURI  string
		expected    string
		description string
	}{
		{
			name:        "Empty string becomes inline",
			blockedURI:  "",
			expected:    "inline",
			description: "Empty blocked-uri should be normalized to 'inline'",
		},
		{
			name:        "self becomes quoted",
			blockedURI:  "self",
			expected:    "'self'",
			description: "Unquoted self should be quoted",
		},
		{
			name:        "unsafe-eval becomes quoted",
			blockedURI:  "unsafe-eval",
			expected:    "'unsafe-eval'",
			description: "Unquoted unsafe-eval should be quoted",
		},
		{
			name:        "eval remains as is",
			blockedURI:  "eval",
			expected:    "eval",
			description: "eval keyword should remain unchanged",
		},
		{
			name:        "data URI remains as is",
			blockedURI:  "data",
			expected:    "data",
			description: "data keyword should remain unchanged",
		},
		{
			name:        "blob URI remains as is",
			blockedURI:  "blob",
			expected:    "blob",
			description: "blob keyword should remain unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData := `{
				"csp-report": {
					"document-uri": "https://example.com/test",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "` + tt.blockedURI + `"
				}
			}`

			reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
			if err != nil {
				t.Fatalf("Failed to parse report: %v", err)
			}

			parsed := reports[0].ParsedReport
			if parsed.BlockedURI != tt.expected {
				t.Errorf("%s: expected '%s', got '%s'", tt.description, tt.expected, parsed.BlockedURI)
			}
		})
	}
}

func TestParseCSPReports_StringNumberParsing(t *testing.T) {
	jsonData := `{
		"csp-report": {
			"document-uri": "https://example.com/test",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "inline",
			"line-number": "42",
			"column-number": "15",
			"status-code": "200"
		}
	}`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse report: %v", err)
	}

	parsed := reports[0].ParsedReport

	if parsed.LineNumber == nil || *parsed.LineNumber != 42 {
		t.Errorf("LineNumber: expected 42, got %v", parsed.LineNumber)
	}
	if parsed.ColumnNumber == nil || *parsed.ColumnNumber != 15 {
		t.Errorf("ColumnNumber: expected 15, got %v", parsed.ColumnNumber)
	}
	if parsed.StatusCode == nil || *parsed.StatusCode != 200 {
		t.Errorf("StatusCode: expected 200, got %v", parsed.StatusCode)
	}
}

func TestParseCSPReports_AllFieldVariations(t *testing.T) {
	// Test that all field name variations are properly extracted
	variations := []struct {
		fieldName string
		jsonData  string
	}{
		{
			fieldName: "documentURL variation",
			jsonData: `{
				"body": {
					"documentURL": "https://example.com/test",
					"violatedDirective": "script-src"
				}
			}`,
		},
		{
			fieldName: "document_url snake_case",
			jsonData: `{
				"csp-report": {
					"document_url": "https://example.com/test",
					"violated_directive": "script-src"
				}
			}`,
		},
		{
			fieldName: "sample instead of script-sample",
			jsonData: `{
				"csp-report": {
					"document-uri": "https://example.com/test",
					"violated-directive": "script-src",
					"sample": "alert(1)"
				}
			}`,
		},
		{
			fieldName: "blockedURL camelCase",
			jsonData: `{
				"body": {
					"documentURL": "https://example.com/test",
					"violatedDirective": "script-src",
					"blockedURL": "https://evil.com/script.js"
				}
			}`,
		},
	}

	for _, tt := range variations {
		t.Run(tt.fieldName, func(t *testing.T) {
			reports, err := ParseCSPReports([]byte(tt.jsonData), "test-agent", "127.0.0.1")
			if err != nil {
				t.Fatalf("Failed to parse report with %s: %v", tt.fieldName, err)
			}

			parsed := reports[0].ParsedReport
			if parsed.DocumentURI == "" {
				t.Errorf("%s: DocumentURI should not be empty", tt.fieldName)
			}
			if parsed.ViolatedDirective == "" {
				t.Errorf("%s: ViolatedDirective should not be empty", tt.fieldName)
			}
		})
	}
}

func TestParseCSPReports_HumanReadableOutput(t *testing.T) {
	tests := []struct {
		name     string
		parsed   *ParsedCSPReport
		expected string
	}{
		{
			name: "Inline script violation",
			parsed: &ParsedCSPReport{
				ViolatedDirective: "script-src 'self'",
				BlockedURI:        "inline",
				DocumentURI:       "https://example.com/page",
				SourceFile:        "https://example.com/page",
				LineNumber:        intPtr(42),
				ColumnNumber:      intPtr(15),
			},
			expected: "Violated directive: script-src 'self' | Blocked URI: inline (inline script or style) | Document: https://example.com/page | Source: https://example.com/page:42:15",
		},
		{
			name: "Eval violation",
			parsed: &ParsedCSPReport{
				ViolatedDirective: "script-src 'self'",
				BlockedURI:        "eval",
				DocumentURI:       "https://example.com/app",
			},
			expected: "Violated directive: script-src 'self' | Blocked URI: eval (eval() or similar) | Document: https://example.com/app",
		},
		{
			name: "Data URI violation",
			parsed: &ParsedCSPReport{
				ViolatedDirective: "img-src 'self'",
				BlockedURI:        "data",
				DocumentURI:       "https://example.com/gallery",
			},
			expected: "Violated directive: img-src 'self' | Blocked URI: data (data: URI) | Document: https://example.com/gallery",
		},
		{
			name: "Only effective directive",
			parsed: &ParsedCSPReport{
				EffectiveDirective: "style-src-elem",
				BlockedURI:         "https://fonts.googleapis.com/css",
				DocumentURI:        "https://example.com/style",
			},
			expected: "Effective directive: style-src-elem | Blocked URI: https://fonts.googleapis.com/css | Document: https://example.com/style",
		},
		{
			name: "Long script sample truncated",
			parsed: &ParsedCSPReport{
				ViolatedDirective: "script-src 'self'",
				BlockedURI:        "inline",
				DocumentURI:       "https://example.com/test",
				ScriptSample:      "function veryLongFunctionNameThatExceedsTheHundredCharacterLimitAndWillBeTruncatedToMakeItMoreReadableInTheOutput() { console.log('test'); }",
			},
			expected: "Violated directive: script-src 'self' | Blocked URI: inline (inline script or style) | Document: https://example.com/test | Script sample: function veryLongFunctionNameThatExceedsTheHundredCharacterLimitAndWillBeTruncatedToMakeItMoreReadab...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateHumanReadable(tt.parsed)
			if result != tt.expected {
				t.Errorf("Human readable output mismatch:\nExpected: %s\nGot:      %s", tt.expected, result)
			}
		})
	}
}

func TestParseCSPReports_ErrorHandling(t *testing.T) {
	tests := []struct {
		name          string
		jsonData      string
		shouldError   bool
		errorContains string
	}{
		{
			name:          "Invalid JSON",
			jsonData:      `{invalid json}`,
			shouldError:   true,
			errorContains: "failed to parse JSON",
		},
		{
			name:          "Empty JSON object",
			jsonData:      `{}`,
			shouldError:   false,
			errorContains: "",
		},
		{
			name:          "Missing required fields",
			jsonData:      `{"csp-report": {}}`,
			shouldError:   false,
			errorContains: "",
		},
		{
			name: "Invalid report in batch",
			jsonData: `[
				{"type": "csp-violation", "body": {"documentURL": "test", "violatedDirective": "test"}},
				"invalid report",
				{"type": "csp-violation", "body": {"documentURL": "test2", "violatedDirective": "test2"}}
			]`,
			shouldError:   false,
			errorContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports, err := ParseCSPReports([]byte(tt.jsonData), "test-agent", "127.0.0.1")

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error containing '%s', but got nil", tt.errorContains)
				} else if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil && len(reports) == 0 {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestParseCSPReports_AllDirectiveTypes(t *testing.T) {
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

func TestParseCSPReports_MixedBatchWithErrors(t *testing.T) {
	// Test a batch where some reports are valid and some are invalid
	jsonData := `[
		{
			"type": "csp-violation",
			"body": {
				"documentURL": "https://example.com/valid1",
				"violatedDirective": "script-src 'self'"
			}
		},
		"this is not a valid report",
		{
			"type": "csp-violation",
			"body": {
				"documentURL": "https://example.com/valid2",
				"violatedDirective": "img-src 'self'"
			}
		},
		null,
		{
			"type": "csp-violation",
			"body": {
				"documentURL": "https://example.com/valid3",
				"violatedDirective": "style-src 'self'"
			}
		}
	]`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse mixed batch: %v", err)
	}

	// Should have 5 reports total (3 valid + 2 error reports)
	if len(reports) != 5 {
		t.Fatalf("Expected 5 reports, got %d", len(reports))
	}

	// Check that we have 3 valid reports
	validCount := 0
	errorCount := 0
	for _, report := range reports {
		if len(report.ProcessingErrors) == 0 && report.ParsedReport.DocumentURI != "" {
			validCount++
		} else {
			errorCount++
		}
	}

	if validCount != 3 {
		t.Errorf("Expected 3 valid reports, got %d", validCount)
	}
	if errorCount != 2 {
		t.Errorf("Expected 2 error reports, got %d", errorCount)
	}
}

func TestParseCSPReports_VeryLargeReport(t *testing.T) {
	// Test handling of very large script samples
	largeScript := strings.Repeat("console.log('test');", 1000)
	jsonData := `{
		"csp-report": {
			"document-uri": "https://example.com/large",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "inline",
			"script-sample": "` + largeScript + `"
		}
	}`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse large report: %v", err)
	}

	parsed := reports[0].ParsedReport
	if parsed.ScriptSample != largeScript {
		t.Error("Large script sample was not preserved")
	}

	// Check that human readable truncates it
	humanReadable := reports[0].HumanReadable
	if !strings.Contains(humanReadable, "...") {
		t.Error("Human readable should truncate large script samples")
	}
}

func TestParseCSPReports_UnicodeHandling(t *testing.T) {
	jsonData := `{
		"csp-report": {
			"document-uri": "https://example.com/测试页面",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "https://example.com/スクリプト.js",
			"script-sample": "console.log('🔒 Security test')"
		}
	}`

	reports, err := ParseCSPReports([]byte(jsonData), "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("Failed to parse Unicode report: %v", err)
	}

	parsed := reports[0].ParsedReport
	if parsed.DocumentURI != "https://example.com/测试页面" {
		t.Errorf("Unicode in DocumentURI not preserved: %s", parsed.DocumentURI)
	}
	if parsed.BlockedURI != "https://example.com/スクリプト.js" {
		t.Errorf("Unicode in BlockedURI not preserved: %s", parsed.BlockedURI)
	}
	if parsed.ScriptSample != "console.log('🔒 Security test')" {
		t.Errorf("Unicode in ScriptSample not preserved: %s", parsed.ScriptSample)
	}
}

// Helper functions
func intPtr(i int) *int {
	return &i
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
