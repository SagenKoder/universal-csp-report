package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type CSPReport struct {
	ID               string                 `json:"id"`
	Timestamp        time.Time              `json:"timestamp"`
	UserAgent        string                 `json:"user_agent"`
	RemoteAddr       string                 `json:"remote_addr"`
	BrowserType      string                 `json:"browser_type"`
	ParsedReport     *ParsedCSPReport       `json:"parsed_report"`
	RawReport        map[string]interface{} `json:"raw_report"`
	HumanReadable    string                 `json:"human_readable"`
	ProcessingErrors []string               `json:"processing_errors,omitempty"`
}

type ParsedCSPReport struct {
	DocumentURI       string   `json:"document_uri"`
	Referrer          string   `json:"referrer,omitempty"`
	ViolatedDirective string   `json:"violated_directive"`
	OriginalPolicy    string   `json:"original_policy,omitempty"`
	BlockedURI        string   `json:"blocked_uri"`
	StatusCode        *int     `json:"status_code,omitempty"`
	ScriptSample      string   `json:"script_sample,omitempty"`
	LineNumber        *int     `json:"line_number,omitempty"`
	ColumnNumber      *int     `json:"column_number,omitempty"`
	SourceFile        string   `json:"source_file,omitempty"`
	Disposition       string   `json:"disposition,omitempty"`
	EffectiveDirective string  `json:"effective_directive,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

func ParseCSPReport(rawData []byte, userAgent, remoteAddr string) (*CSPReport, error) {
	var rawReport map[string]interface{}
	if err := json.Unmarshal(rawData, &rawReport); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	report := &CSPReport{
		ID:          generateID(),
		Timestamp:   time.Now().UTC(),
		UserAgent:   userAgent,
		RemoteAddr:  remoteAddr,
		BrowserType: detectBrowserType(userAgent),
		RawReport:   rawReport,
	}

	parsed, errors := extractCSPData(rawReport)
	report.ParsedReport = parsed
	report.ProcessingErrors = errors
	report.HumanReadable = generateHumanReadable(parsed)

	return report, nil
}

func extractCSPData(rawReport map[string]interface{}) (*ParsedCSPReport, []string) {
	var errors []string
	parsed := &ParsedCSPReport{}

	cspReport := extractNestedReport(rawReport)
	if cspReport == nil {
		errors = append(errors, "no CSP report data found in request")
		return parsed, errors
	}

	parsed.DocumentURI = extractString(cspReport, "document-uri", "documentURI", "document_uri")
	parsed.Referrer = extractString(cspReport, "referrer")
	parsed.ViolatedDirective = extractString(cspReport, "violated-directive", "violatedDirective", "violated_directive")
	parsed.OriginalPolicy = extractString(cspReport, "original-policy", "originalPolicy", "original_policy")
	parsed.BlockedURI = extractString(cspReport, "blocked-uri", "blockedURI", "blocked_uri")
	parsed.ScriptSample = extractString(cspReport, "script-sample", "scriptSample", "script_sample")
	parsed.SourceFile = extractString(cspReport, "source-file", "sourceFile", "source_file")
	parsed.Disposition = extractString(cspReport, "disposition")
	parsed.EffectiveDirective = extractString(cspReport, "effective-directive", "effectiveDirective", "effective_directive")

	if statusCode := extractInt(cspReport, "status-code", "statusCode", "status_code"); statusCode != nil {
		parsed.StatusCode = statusCode
	}

	if lineNumber := extractInt(cspReport, "line-number", "lineNumber", "line_number"); lineNumber != nil {
		parsed.LineNumber = lineNumber
	}

	if columnNumber := extractInt(cspReport, "column-number", "columnNumber", "column_number"); columnNumber != nil {
		parsed.ColumnNumber = columnNumber
	}

	if parsed.DocumentURI == "" {
		errors = append(errors, "missing document-uri")
	}
	if parsed.ViolatedDirective == "" {
		errors = append(errors, "missing violated-directive")
	}

	parsed.Errors = errors
	return parsed, errors
}

func extractNestedReport(rawReport map[string]interface{}) map[string]interface{} {
	if cspReport, ok := rawReport["csp-report"].(map[string]interface{}); ok {
		return cspReport
	}
	
	if cspReport, ok := rawReport["cspReport"].(map[string]interface{}); ok {
		return cspReport
	}

	if cspReport, ok := rawReport["body"].(map[string]interface{}); ok {
		return cspReport
	}

	return rawReport
}

func extractString(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

func extractInt(data map[string]interface{}, keys ...string) *int {
	for _, key := range keys {
		if val, ok := data[key]; ok {
			switch v := val.(type) {
			case int:
				return &v
			case float64:
				intVal := int(v)
				return &intVal
			case string:
				if v != "" {
					continue
				}
			}
		}
	}
	return nil
}

func detectBrowserType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "edg/") || strings.Contains(ua, "edge/"):
		return "edge"
	case strings.Contains(ua, "firefox"):
		return "firefox"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		return "safari"
	case strings.Contains(ua, "chrome"):
		return "chrome"
	default:
		return "unknown"
	}
}

func generateHumanReadable(parsed *ParsedCSPReport) string {
	if parsed == nil {
		return "Failed to parse CSP report"
	}

	var parts []string
	
	if parsed.ViolatedDirective != "" {
		parts = append(parts, fmt.Sprintf("Violated directive: %s", parsed.ViolatedDirective))
	}
	
	if parsed.BlockedURI != "" {
		parts = append(parts, fmt.Sprintf("Blocked URI: %s", parsed.BlockedURI))
	}
	
	if parsed.DocumentURI != "" {
		parts = append(parts, fmt.Sprintf("Document: %s", parsed.DocumentURI))
	}
	
	if parsed.SourceFile != "" {
		location := parsed.SourceFile
		if parsed.LineNumber != nil {
			location += fmt.Sprintf(":%d", *parsed.LineNumber)
		}
		if parsed.ColumnNumber != nil {
			location += fmt.Sprintf(":%d", *parsed.ColumnNumber)
		}
		parts = append(parts, fmt.Sprintf("Source: %s", location))
	}
	
	if parsed.ScriptSample != "" {
		parts = append(parts, fmt.Sprintf("Script sample: %s", parsed.ScriptSample))
	}

	if len(parts) == 0 {
		return "CSP violation (no details available)"
	}

	return strings.Join(parts, " | ")
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}