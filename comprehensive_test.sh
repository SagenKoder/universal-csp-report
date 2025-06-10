#!/bin/bash

# Comprehensive test using test_payloads.json

echo "Running comprehensive CSP report format tests..."

# Test Chrome reports
echo "=== Testing Chrome Reports ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -d '{
    "csp-report": {
      "document-uri": "https://example.com/page",
      "referrer": "https://google.com",
      "violated-directive": "script-src '\''self'\''",
      "original-policy": "default-src '\''self'\''; script-src '\''self'\''",
      "blocked-uri": "https://evil.com/script.js",
      "status-code": 200,
      "script-sample": "console.log('\''malicious'\'')",
      "line-number": 42,
      "column-number": 15,
      "source-file": "https://example.com/inline-script"
    }
  }' | jq .

# Test Firefox camelCase format
echo "=== Testing Firefox camelCase Format ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0" \
  -d '{
    "cspReport": {
      "documentURI": "https://example.com/firefox-camel",
      "violatedDirective": "img-src '\''self'\''",
      "blockedURI": "https://tracker.com/pixel.gif",
      "originalPolicy": "default-src '\''self'\''; img-src '\''self'\''"
    }
  }' | jq .

# Test Safari format
echo "=== Testing Safari Format ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15" \
  -d '{
    "csp-report": {
      "document-uri": "https://example.com/safari-page",
      "violated-directive": "script-src '\''self'\''",
      "blocked-uri": "https://ads.com/tracker.js",
      "original-policy": "default-src '\''self'\''"
    }
  }' | jq .

# Test Edge format
echo "=== Testing Edge Format ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" \
  -d '{
    "csp-report": {
      "document-uri": "https://example.com/edge-page",
      "violated-directive": "object-src '\''none'\''",
      "blocked-uri": "https://example.com/plugin.swf",
      "original-policy": "object-src '\''none'\''",
      "status-code": 200
    }
  }' | jq .

# Test Report-To API with snake_case
echo "=== Testing Report-To API with snake_case ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36" \
  -d '{
    "body": {
      "document_uri": "https://example.com/snake-case",
      "violated_directive": "img-src '\''self'\''",
      "blocked_uri": "https://cdn.example.com/image.jpg",
      "original_policy": "img-src '\''self'\''",
      "effective_directive": "img-src",
      "disposition": "report"
    }
  }' | jq .

# Test Unicode content
echo "=== Testing Unicode Content ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 Chrome/120.0.0.0" \
  -d '{
    "csp-report": {
      "document-uri": "https://example.com/测试页面",
      "violated-directive": "script-src '\''self'\''",
      "blocked-uri": "https://example.com/スクリプト.js",
      "script-sample": "alert('\''مرحبا بالعالم'\'');"
    }
  }' | jq .

# Test trusted-types violation
echo "=== Testing Trusted Types Violation ==="
curl -s -X POST http://localhost:8080/csp-report \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 Chrome/120.0.0.0" \
  -d '{
    "csp-report": {
      "document-uri": "https://secure.example.com/tt",
      "violated-directive": "trusted-types default",
      "blocked-uri": "trusted-types-policy-violation",
      "original-policy": "trusted-types default; require-trusted-types-for '\''script'\''",
      "script-sample": "element.innerHTML = userContent",
      "line-number": 45,
      "column-number": 8
    }
  }' | jq .

# Check final metrics
echo "=== Final Metrics ==="
curl -s http://localhost:8080/metrics | jq .

echo "Comprehensive test completed!"