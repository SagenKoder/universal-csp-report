package models

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	DocumentURI        string   `json:"document_uri"`
	Referrer           string   `json:"referrer,omitempty"`
	ViolatedDirective  string   `json:"violated_directive"`
	OriginalPolicy     string   `json:"original_policy,omitempty"`
	BlockedURI         string   `json:"blocked_uri"`
	StatusCode         *int     `json:"status_code,omitempty"`
	ScriptSample       string   `json:"script_sample,omitempty"`
	LineNumber         *int     `json:"line_number,omitempty"`
	ColumnNumber       *int     `json:"column_number,omitempty"`
	SourceFile         string   `json:"source_file,omitempty"`
	Disposition        string   `json:"disposition,omitempty"`
	EffectiveDirective string   `json:"effective_directive,omitempty"`
	SHA256             string   `json:"sha256,omitempty"`
	Errors             []string `json:"errors,omitempty"`
}

// ReportToFormat represents the Report-To API format
type ReportToFormat struct {
	Type      string                 `json:"type"`
	Age       int                    `json:"age"`
	URL       string                 `json:"url"`
	UserAgent string                 `json:"user_agent"`
	Body      map[string]interface{} `json:"body"`
}

// ParseCSPReports handles both single reports and arrays of reports
func ParseCSPReports(rawData []byte, userAgent, remoteAddr string) ([]*CSPReport, error) {
	var reports []*CSPReport

	// First, try to unmarshal as an array (Chrome batch format)
	var reportArray []interface{}
	if err := json.Unmarshal(rawData, &reportArray); err == nil {
		// It's an array - process each report
		for i, rawReport := range reportArray {
			if reportMap, ok := rawReport.(map[string]interface{}); ok {
				report := parseIndividualReport(reportMap, userAgent, remoteAddr)
				if report != nil {
					reports = append(reports, report)
				}
			} else {
				// Log error but continue processing other reports
				reports = append(reports, &CSPReport{
					ID:               generateID(),
					Timestamp:        time.Now().UTC(),
					UserAgent:        userAgent,
					RemoteAddr:       remoteAddr,
					BrowserType:      detectBrowserType(userAgent),
					ProcessingErrors: []string{fmt.Sprintf("invalid report format at index %d", i)},
				})
			}
		}
	} else {
		// Not an array - try as single object
		var rawReport map[string]interface{}
		if err := json.Unmarshal(rawData, &rawReport); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		report := parseIndividualReport(rawReport, userAgent, remoteAddr)
		if report != nil {
			reports = append(reports, report)
		}
	}

	if len(reports) == 0 {
		return nil, fmt.Errorf("no valid CSP reports found")
	}

	return reports, nil
}

// ParseCSPReport maintains backward compatibility for single report parsing
func ParseCSPReport(rawData []byte, userAgent, remoteAddr string) (*CSPReport, error) {
	reports, err := ParseCSPReports(rawData, userAgent, remoteAddr)
	if err != nil {
		return nil, err
	}
	if len(reports) == 0 {
		return nil, fmt.Errorf("no valid CSP report found")
	}
	return reports[0], nil
}

func parseIndividualReport(rawReport map[string]interface{}, userAgent, remoteAddr string) *CSPReport {
	report := &CSPReport{
		ID:          generateID(),
		Timestamp:   time.Now().UTC(),
		UserAgent:   userAgent,
		RemoteAddr:  remoteAddr,
		BrowserType: detectBrowserType(userAgent),
		RawReport:   rawReport,
	}

	// Check if this is a Report-To format
	if reportType, ok := rawReport["type"].(string); ok && reportType == "csp-violation" {
		// Handle Report-To format
		parsed, errors := extractReportToData(rawReport)
		report.ParsedReport = parsed
		report.ProcessingErrors = errors
	} else {
		// Handle standard CSP report format
		parsed, errors := extractCSPData(rawReport)
		report.ParsedReport = parsed
		report.ProcessingErrors = errors
	}

	report.HumanReadable = generateHumanReadable(report.ParsedReport)
	return report
}

func extractReportToData(rawReport map[string]interface{}) (*ParsedCSPReport, []string) {
	var errors []string
	parsed := &ParsedCSPReport{}

	// Extract the body which contains the actual CSP report
	body, ok := rawReport["body"].(map[string]interface{})
	if !ok {
		errors = append(errors, "Report-To format missing body field")
		return parsed, errors
	}

	// Extract fields from the body with all possible variations
	parsed.DocumentURI = extractString(body, "documentURL", "document-url", "document-uri", "documentURI", "document_uri", "document_url")
	parsed.Referrer = extractString(body, "referrer")
	parsed.ViolatedDirective = extractString(body, "violatedDirective", "violated-directive", "violated_directive")
	parsed.OriginalPolicy = extractString(body, "originalPolicy", "original-policy", "original_policy")
	parsed.BlockedURI = normalizeBlockedURI(extractString(body, "blockedURL", "blockedURI", "blocked-url", "blocked-uri", "blocked_uri", "blocked_url"))
	parsed.ScriptSample = extractString(body, "sample", "script-sample", "scriptSample", "script_sample")
	parsed.SourceFile = extractString(body, "sourceFile", "source-file", "source_file")
	parsed.Disposition = extractString(body, "disposition")
	parsed.EffectiveDirective = extractString(body, "effectiveDirective", "effective-directive", "effective_directive")

	if statusCode := extractInt(body, "statusCode", "status-code", "status_code"); statusCode != nil {
		parsed.StatusCode = statusCode
	}

	if lineNumber := extractInt(body, "lineNumber", "line-number", "line_number"); lineNumber != nil {
		parsed.LineNumber = lineNumber
	}

	if columnNumber := extractInt(body, "columnNumber", "column-number", "column_number"); columnNumber != nil {
		parsed.ColumnNumber = columnNumber
	}

	if parsed.DocumentURI == "" {
		errors = append(errors, "missing document-uri")
	}
	if parsed.ViolatedDirective == "" && parsed.EffectiveDirective == "" {
		errors = append(errors, "missing violated-directive or effective-directive")
	}

	parsed.Errors = errors
	return parsed, errors
}

func extractCSPData(rawReport map[string]interface{}) (*ParsedCSPReport, []string) {
	var errors []string
	parsed := &ParsedCSPReport{}

	cspReport := extractNestedReport(rawReport)
	if cspReport == nil {
		errors = append(errors, "no CSP report data found in request")
		return parsed, errors
	}

	// Extract all possible field variations
	parsed.DocumentURI = extractString(cspReport, "document-uri", "documentURI", "document_uri", "document-url", "documentURL", "document_url")
	parsed.Referrer = extractString(cspReport, "referrer")
	parsed.ViolatedDirective = extractString(cspReport, "violated-directive", "violatedDirective", "violated_directive")
	parsed.OriginalPolicy = extractString(cspReport, "original-policy", "originalPolicy", "original_policy")
	parsed.BlockedURI = normalizeBlockedURI(extractString(cspReport, "blocked-uri", "blockedURI", "blocked_uri", "blocked-url", "blockedURL", "blocked_url"))
	parsed.ScriptSample = extractString(cspReport, "script-sample", "scriptSample", "script_sample", "sample")
	parsed.SourceFile = extractString(cspReport, "source-file", "sourceFile", "source_file")
	parsed.Disposition = extractString(cspReport, "disposition")
	parsed.EffectiveDirective = extractString(cspReport, "effective-directive", "effectiveDirective", "effective_directive")
	parsed.SHA256 = extractString(cspReport, "sha256")

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
	if parsed.ViolatedDirective == "" && parsed.EffectiveDirective == "" {
		errors = append(errors, "missing violated-directive or effective-directive")
	}

	// If violated directive is missing but effective directive exists, use it
	if parsed.ViolatedDirective == "" && parsed.EffectiveDirective != "" {
		parsed.ViolatedDirective = parsed.EffectiveDirective
	}

	parsed.Errors = errors
	return parsed, errors
}

func extractNestedReport(rawReport map[string]interface{}) map[string]interface{} {
	// Standard wrapper
	if cspReport, ok := rawReport["csp-report"].(map[string]interface{}); ok {
		return cspReport
	}

	// Firefox variation
	if cspReport, ok := rawReport["cspReport"].(map[string]interface{}); ok {
		return cspReport
	}

	// Report-To single format
	if cspReport, ok := rawReport["body"].(map[string]interface{}); ok {
		return cspReport
	}

	// No wrapper - return as is
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
				// Parse string numbers
				if v != "" {
					if intVal, err := strconv.Atoi(v); err == nil {
						return &intVal
					}
				}
			}
		}
	}
	return nil
}

// normalizeBlockedURI handles special blocked-uri values
func normalizeBlockedURI(uri string) string {
	if uri == "" {
		return "inline"
	}

	// Normalize common special values
	switch strings.ToLower(uri) {
	case "self":
		return "'self'"
	case "unsafe-eval":
		return "'unsafe-eval'"
	case "unsafe-inline":
		return "'unsafe-inline'"
	}

	return uri
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
	} else if parsed.EffectiveDirective != "" {
		parts = append(parts, fmt.Sprintf("Effective directive: %s", parsed.EffectiveDirective))
	}

	if parsed.BlockedURI != "" {
		// Add context for special values
		blockedDesc := parsed.BlockedURI
		switch parsed.BlockedURI {
		case "inline":
			blockedDesc = "inline (inline script or style)"
		case "eval":
			blockedDesc = "eval (eval() or similar)"
		case "data":
			blockedDesc = "data (data: URI)"
		case "blob":
			blockedDesc = "blob (blob: URI)"
		case "filesystem":
			blockedDesc = "filesystem (filesystem: URI)"
		}
		parts = append(parts, fmt.Sprintf("Blocked URI: %s", blockedDesc))
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
		sample := parsed.ScriptSample
		if len(sample) > 100 {
			sample = sample[:100] + "..."
		}
		parts = append(parts, fmt.Sprintf("Script sample: %s", sample))
	}

	if len(parts) == 0 {
		return "CSP violation (no details available)"
	}

	return strings.Join(parts, " | ")
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
