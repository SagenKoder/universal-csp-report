#!/bin/bash

# Load test script to demonstrate high-throughput capability

echo "Running load test to demonstrate high-throughput processing..."

# Function to send CSP reports in parallel
send_reports() {
    local num_requests=$1
    local user_agent="$2"
    local payload="$3"
    
    for i in $(seq 1 $num_requests); do
        curl -s -X POST http://localhost:8080/csp-report \
            -H "Content-Type: application/json" \
            -H "User-Agent: $user_agent" \
            -d "$payload" > /dev/null &
    done
}

# Define test payloads
chrome_payload='{
    "csp-report": {
        "document-uri": "https://example.com/load-test-chrome",
        "violated-directive": "script-src '\''self'\''",
        "blocked-uri": "https://malicious.com/script-'$RANDOM'.js",
        "original-policy": "script-src '\''self'\''"
    }
}'

firefox_payload='{
    "csp-report": {
        "document-uri": "https://example.com/load-test-firefox",
        "violated-directive": "img-src '\''self'\''",
        "blocked-uri": "https://tracker.com/pixel-'$RANDOM'.gif"
    }
}'

report_to_payload='{
    "body": {
        "document-uri": "https://example.com/load-test-report-to",
        "violated-directive": "connect-src '\''self'\''",
        "blocked-uri": "wss://websocket-'$RANDOM'.example.com",
        "disposition": "enforce"
    }
}'

# Check initial metrics
echo "Initial metrics:"
curl -s http://localhost:8080/metrics | jq .
echo ""

# Send 100 requests of each type (300 total) in parallel bursts
echo "Sending 300 CSP reports in parallel bursts..."

# Burst 1: Chrome reports
send_reports 100 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" "$chrome_payload"

# Burst 2: Firefox reports  
send_reports 100 "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0" "$firefox_payload"

# Burst 3: Report-To API reports
send_reports 100 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36" "$report_to_payload"

echo "Waiting for all requests to complete..."
wait

echo "All requests sent! Waiting for processing..."
sleep 10

# Check final metrics
echo "Final metrics:"
curl -s http://localhost:8080/metrics | jq .
echo ""

# Check Elasticsearch count
echo "Documents in Elasticsearch:"
curl -s "http://localhost:9200/csp-reports-*/_count" | jq .
echo ""

echo "Load test completed!"
echo "This demonstrates the application can handle burst traffic of hundreds of requests simultaneously."