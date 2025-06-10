#!/bin/bash

# Test script to verify CSP report processing

echo "Testing Universal CSP Report Processor..."

# Function to test CSP report
test_csp_report() {
    local description="$1"
    local payload="$2"
    local user_agent="$3"
    
    echo "Testing: $description"
    
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -X POST http://localhost:8080/csp-report \
        -H "Content-Type: application/json" \
        -H "User-Agent: $user_agent" \
        -d "$payload")
    
    http_code=$(echo "$response" | tail -n1 | sed 's/HTTP_CODE://')
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "200" ]; then
        echo "✅ SUCCESS: $description"
        echo "   Response: $body"
    else
        echo "❌ FAILED: $description (HTTP $http_code)"
        echo "   Response: $body"
    fi
    echo ""
}

# Wait for server to start
echo "Waiting for server to start..."
sleep 3

# Test health endpoint
echo "Testing health endpoint..."
health_response=$(curl -s http://localhost:8080/health)
echo "Health: $health_response"
echo ""

# Test Chrome CSP report
test_csp_report "Chrome CSP Violation" '{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src '\''self'\''",
    "blocked-uri": "https://evil.com/script.js",
    "original-policy": "script-src '\''self'\''"
  }
}' "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Test Firefox CSP report
test_csp_report "Firefox CSP Violation" '{
  "csp-report": {
    "document-uri": "https://example.com/firefox",
    "violated-directive": "img-src '\''self'\''",
    "blocked-uri": "https://tracker.com/pixel.gif"
  }
}' "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0"

# Test Report-To API format
test_csp_report "Report-To API Format" '{
  "body": {
    "document-uri": "https://example.com/report-to",
    "violated-directive": "script-src '\''self'\''",
    "blocked-uri": "https://analytics.com/track.js",
    "disposition": "enforce"
  }
}' "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Test malformed report
test_csp_report "Malformed Report" '{
  "invalid": "json"
}' "Mozilla/5.0 Chrome/120.0.0.0"

# Test metrics endpoint
echo "Testing metrics endpoint..."
metrics_response=$(curl -s http://localhost:8080/metrics)
echo "Metrics: $metrics_response"
echo ""

echo "All tests completed!"