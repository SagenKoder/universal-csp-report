#!/bin/bash

# Comprehensive test for ALL CSP report formats documented in CSP-REPORT-FORMATS.md

echo "Running COMPLETE CSP report format tests for all browser variations..."
echo "============================================================"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test a report and check response
test_report() {
    local test_name="$1"
    local content_type="$2"
    local user_agent="$3"
    local data="$4"
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    
    response=$(curl -s -w "\n%{http_code}" -X POST http://localhost:8080/csp-report \
        -H "Content-Type: $content_type" \
        -H "User-Agent: $user_agent" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "204" ]]; then
        echo -e "${GREEN}✓ Success (HTTP $http_code)${NC}"
        if [[ -n "$body" ]]; then
            echo "$body" | jq . 2>/dev/null || echo "$body"
        fi
    else
        echo -e "${RED}✗ Failed (HTTP $http_code)${NC}"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    fi
    echo "---"
}

# 1. Standard CSP Report Format (CSP 1.0/2.0)
test_report "Standard CSP format with kebab-case" \
    "application/csp-report" \
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/page.html",
            "referrer": "https://example.com/",
            "violated-directive": "script-src '\''self'\''",
            "effective-directive": "script-src",
            "original-policy": "default-src '\''self'\''; script-src '\''self'\''; object-src '\''none'\''",
            "blocked-uri": "https://evil.com/malicious.js",
            "status-code": 200,
            "source-file": "https://example.com/page.html",
            "line-number": 10,
            "column-number": 5,
            "script-sample": ""
        }
    }'

# 2. Chrome/Edge Batch Format
test_report "Chrome batch format (multiple reports)" \
    "application/reports+json" \
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0" \
    '[
        {
            "type": "csp-violation",
            "age": 10,
            "url": "https://example.com/page.html",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "body": {
                "blockedURL": "https://cdn.evil.com/script.js",
                "columnNumber": 0,
                "disposition": "enforce",
                "documentURL": "https://example.com/page.html",
                "effectiveDirective": "script-src-elem",
                "lineNumber": 0,
                "originalPolicy": "script-src '\''self'\'' https://trusted.com; object-src '\''none'\''",
                "referrer": "https://example.com/",
                "sample": "",
                "sourceFile": "",
                "statusCode": 0,
                "violatedDirective": "script-src-elem"
            }
        },
        {
            "type": "csp-violation",
            "age": 150,
            "url": "https://example.com/page.html",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "body": {
                "blockedURL": "inline",
                "columnNumber": 42,
                "disposition": "enforce",
                "documentURL": "https://example.com/page.html",
                "effectiveDirective": "style-src-elem",
                "lineNumber": 58,
                "originalPolicy": "style-src '\''self'\'' '\''unsafe-inline'\''",
                "referrer": "",
                "sample": "body { background: red; }",
                "sourceFile": "https://example.com/page.html",
                "statusCode": 200,
                "violatedDirective": "style-src-elem"
            }
        }
    ]'

# 3. Firefox Modern Format with camelCase
test_report "Firefox modern format with camelCase" \
    "application/csp-report" \
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0" \
    '{
        "cspReport": {
            "blockedURI": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My...",
            "columnNumber": 307,
            "documentURI": "https://example.com/profile",
            "lineNumber": 18,
            "originalPolicy": "default-src '\''self'\''; img-src '\''self'\'' https:",
            "referrer": "https://example.com/home",
            "scriptSample": "",
            "sourceFile": "https://example.com/js/app.js",
            "violatedDirective": "img-src",
            "sha256": "sha256-abcd1234efgh5678ijkl9012mnop3456qrst7890"
        }
    }'

# 4. Report-To API Format (Single Report)
test_report "Report-To API single report format" \
    "application/reports+json" \
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0" \
    '{
        "type": "csp-violation",
        "age": 0,
        "url": "https://example.com/checkout",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "body": {
            "blockedURL": "wss://realtime.untrusted.com/socket",
            "columnNumber": 0,
            "disposition": "report",
            "documentURL": "https://example.com/checkout",
            "effectiveDirective": "connect-src",
            "lineNumber": 0,
            "originalPolicy": "default-src '\''self'\''; connect-src '\''self'\'' https://api.example.com",
            "referrer": "",
            "sample": "",
            "sourceFile": "",
            "statusCode": 0,
            "violatedDirective": "connect-src"
        }
    }'

# 5. Legacy WebKit Format with "url" instead of "uri"
test_report "Legacy WebKit format with -url suffix" \
    "application/csp-report" \
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36" \
    '{
        "csp-report": {
            "document-url": "https://example.com/legacy",
            "referrer": "",
            "violated-directive": "style-src '\''self'\''",
            "original-policy": "default-src '\''self'\''; style-src '\''self'\''",
            "blocked-url": "https://fonts.googleapis.com/css",
            "source-file": "https://example.com/legacy",
            "line-number": "25",
            "column-number": "10"
        }
    }'

# 6. Inline Script Violation (empty blocked-uri)
test_report "Inline script violation with empty blocked-uri" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/",
            "referrer": "",
            "violated-directive": "script-src '\''self'\''",
            "effective-directive": "script-src",
            "original-policy": "script-src '\''self'\'' '\''nonce-abc123'\''",
            "blocked-uri": "",
            "source-file": "https://example.com/",
            "line-number": 45,
            "column-number": 8,
            "script-sample": "alert('\''Hello World'\'')",
            "status-code": 200
        }
    }'

# 7. Eval Violation
test_report "Eval violation" \
    "application/csp-report" \
    "Mozilla/5.0 Firefox/120.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/app",
            "referrer": "https://example.com/",
            "violated-directive": "script-src '\''self'\''",
            "effective-directive": "script-src",
            "original-policy": "script-src '\''self'\''",
            "blocked-uri": "eval",
            "source-file": "https://example.com/js/utils.js",
            "line-number": 102,
            "column-number": 15,
            "status-code": 200
        }
    }'

# 8. Data URI Violation
test_report "Data URI violation" \
    "application/csp-report" \
    "Mozilla/5.0 Safari/605.1.15" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/gallery",
            "referrer": "",
            "violated-directive": "img-src '\''self'\'' https:",
            "effective-directive": "img-src",
            "original-policy": "default-src '\''self'\''; img-src '\''self'\'' https:",
            "blocked-uri": "data",
            "status-code": 200
        }
    }'

# 9. Blob URI Violation
test_report "Blob URI violation" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/editor",
            "referrer": "",
            "violated-directive": "worker-src '\''self'\''",
            "effective-directive": "worker-src",
            "original-policy": "default-src '\''self'\''; worker-src '\''self'\''",
            "blocked-uri": "blob",
            "source-file": "https://example.com/js/editor.js",
            "line-number": 234,
            "column-number": 12,
            "status-code": 200
        }
    }'

# 10. WebSocket Violation
test_report "WebSocket (wss://) violation" \
    "application/csp-report" \
    "Mozilla/5.0 Edge/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/chat",
            "referrer": "",
            "violated-directive": "connect-src '\''self'\'' https:",
            "effective-directive": "connect-src",
            "original-policy": "default-src '\''self'\''; connect-src '\''self'\'' https:",
            "blocked-uri": "wss://chat.example.com/socket",
            "status-code": 0
        }
    }'

# 11. Field name variations - snake_case
test_report "Field variations with snake_case" \
    "application/json" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document_uri": "https://example.com/snake-test",
            "violated_directive": "script-src '\''self'\''",
            "blocked_uri": "https://evil.com/script.js",
            "original_policy": "script-src '\''self'\''",
            "source_file": "https://example.com/app.js",
            "line_number": 42,
            "column_number": 15,
            "status_code": 200,
            "script_sample": "eval('\''code'\'')"
        }
    }'

# 12. Mixed field variations
test_report "Mixed field name variations" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "body": {
            "documentURL": "https://example.com/mixed",
            "violated-directive": "img-src '\''self'\''",
            "blockedURI": "https://cdn.example.com/image.jpg",
            "original_policy": "img-src '\''self'\''",
            "effectiveDirective": "img-src",
            "line-number": "123",
            "columnNumber": 45,
            "sample": "background-image: url(https://cdn.example.com/image.jpg)"
        }
    }'

# 13. Chrome inline violation
test_report "Chrome inline violation format" \
    "application/reports+json" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "type": "csp-violation",
        "body": {
            "blockedURL": "inline",
            "documentURL": "https://example.com/inline-test",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "script-src '\''self'\''",
            "violatedDirective": "script-src-elem",
            "sample": "document.write('\''unsafe'\'')"
        }
    }'

# 14. Special values - self
test_report "Special blocked-uri value: self" \
    "application/csp-report" \
    "Mozilla/5.0 Firefox/120.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/test",
            "violated-directive": "script-src '\''none'\''",
            "blocked-uri": "self"
        }
    }'

# 15. Special values - unsafe-eval
test_report "Special blocked-uri value: unsafe-eval" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/test",
            "violated-directive": "script-src '\''self'\''",
            "blocked-uri": "unsafe-eval"
        }
    }'

# 16. String numbers (legacy format)
test_report "String numbers from legacy browsers" \
    "application/csp-report" \
    "Mozilla/5.0 (compatible; MSIE 11.0)" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/legacy",
            "violated-directive": "script-src '\''self'\''",
            "blocked-uri": "inline",
            "line-number": "42",
            "column-number": "15",
            "status-code": "200"
        }
    }'

# 17. Unicode content
test_report "Unicode content in various fields" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/测试页面",
            "violated-directive": "script-src '\''self'\''",
            "blocked-uri": "https://example.com/スクリプト.js",
            "script-sample": "console.log('\''🔒 Security test 你好 مرحبا'\'')"
        }
    }'

# 18. Very large script sample
test_report "Very large script sample (truncation test)" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": "https://example.com/large",
            "violated-directive": "script-src '\''self'\''",
            "blocked-uri": "inline",
            "script-sample": "function veryLongFunctionNameThatExceedsTheHundredCharacterLimitAndWillBeTruncatedToMakeItMoreReadableInTheOutput() { console.log('\''This is a very long script sample that should be truncated in the human readable output but preserved in full in the parsed data structure for analysis purposes'\''); }"
        }
    }'

# 19. Null and missing fields
test_report "Null values and missing fields" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {
            "document-uri": null,
            "violated-directive": "script-src",
            "blocked-uri": "https://example.com/script.js",
            "line-number": null
        }
    }'

# 20. Empty report wrapper
test_report "Empty CSP report wrapper" \
    "application/csp-report" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "csp-report": {}
    }'

# 21. No wrapper (direct fields)
test_report "No wrapper - direct fields" \
    "application/json" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '{
        "document-uri": "https://example.com/direct",
        "violated-directive": "script-src '\''self'\''",
        "blocked-uri": "https://evil.com/script.js"
    }'

# 22. Mixed batch with invalid reports
test_report "Mixed batch with some invalid reports" \
    "application/reports+json" \
    "Mozilla/5.0 Chrome/120.0.0.0" \
    '[
        {
            "type": "csp-violation",
            "body": {
                "documentURL": "https://example.com/valid1",
                "violatedDirective": "script-src '\''self'\''"
            }
        },
        "this is not a valid report",
        {
            "type": "csp-violation",
            "body": {
                "documentURL": "https://example.com/valid2",
                "violatedDirective": "img-src '\''self'\''"
            }
        },
        null,
        {
            "type": "csp-violation",
            "body": {
                "documentURL": "https://example.com/valid3",
                "violatedDirective": "style-src '\''self'\''"
            }
        }
    ]'

# Check health status
echo -e "\n${YELLOW}=== Health Check ===${NC}"
curl -s http://localhost:8080/health | jq .

# Check final metrics
echo -e "\n${YELLOW}=== Final Metrics ===${NC}"
curl -s http://localhost:8080/metrics | jq .

echo -e "\n${GREEN}Comprehensive test completed!${NC}"
echo "All CSP report format variations have been tested."