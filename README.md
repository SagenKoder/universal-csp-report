# Universal CSP Report Processor

[![CI/CD Pipeline](https://github.com/SagenKoder/universal-csp-report/actions/workflows/ci.yml/badge.svg)](https://github.com/SagenKoder/universal-csp-report/actions/workflows/ci.yml)
[![Security Scanning](https://github.com/SagenKoder/universal-csp-report/actions/workflows/security.yml/badge.svg)](https://github.com/SagenKoder/universal-csp-report/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SagenKoder/universal-csp-report)](https://goreportcard.com/report/github.com/SagenKoder/universal-csp-report)
[![codecov](https://codecov.io/gh/SagenKoder/universal-csp-report/branch/master/graph/badge.svg)](https://codecov.io/gh/SagenKoder/universal-csp-report)
[![Docker Pulls](https://img.shields.io/docker/pulls/ghcr.io/sagenkoder/universal-csp-report)](https://github.com/SagenKoder/universal-csp-report/pkgs/container/universal-csp-report)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance Go application that processes Content Security Policy (CSP) violation reports from all major browsers. It handles the inconsistencies between different browser implementations and provides both human-readable output and structured Elasticsearch indexing.

## Features

- **Universal Browser Support**: Dynamically handles CSP reports from Chrome, Firefox, Safari, and Edge
- **High Performance**: Supports bursts of 100,000+ requests per minute using goroutines and batch processing
- **Elasticsearch Integration**: Automatically indexes reports with daily indices and proper field mappings
- **Rate Limiting**: Built-in rate limiting to prevent abuse
- **Flexible Configuration**: Environment-based configuration with sensible defaults
- **Docker Ready**: Complete Docker setup with Elasticsearch and Kibana

## Architecture

- **HTTP Server**: Gin-based server with middleware for logging, rate limiting, and metrics
- **Batch Processor**: Worker pool pattern with configurable batch sizes and flush intervals
- **Dynamic Parsing**: Handles various CSP report formats from different browsers
- **Elasticsearch Storage**: Bulk indexing with daily indices and optimized mappings

## Quick Start

### Using Docker Compose

```bash
# Clone and start the stack
git clone https://github.com/SagenKoder/universal-csp-report.git
cd universal-csp-report
docker-compose up -d

# The service will be available at:
# - CSP Reports: http://localhost:8080/csp-report
# - Health Check: http://localhost:8080/health
# - Metrics: http://localhost:8080/metrics
# - Kibana: http://localhost:5601
```

### Using Pre-built Container

```bash
# Run with GitHub Container Registry image
docker run -p 8080:8080 \
  -e ELASTICSEARCH_ADDRESSES=http://your-elasticsearch:9200 \
  ghcr.io/sagenkoder/universal-csp-report:latest

# Or with docker-compose using the pre-built image
# (modify docker-compose.yml to use the ghcr.io image)
```

### Manual Setup

```bash
# Install dependencies
go mod download

# Set environment variables (copy from .env.example)
export ELASTICSEARCH_ADDRESSES=http://localhost:9200

# Run the application
go run main.go
```

## Configuration

All configuration is done via environment variables:

### Server Settings
- `SERVER_PORT`: HTTP server port (default: 8080)
- `PRODUCTION`: Production mode flag (default: false)
- `RATE_LIMIT`: Requests per second limit (default: 10000)
- `RATE_BURST`: Burst capacity (default: 20000)

### Processing Settings
- `WORKER_COUNT`: Number of worker goroutines (default: 10)
- `BATCH_SIZE`: Reports per batch (default: 100)
- `QUEUE_SIZE`: Internal queue size (default: 10000)
- `FLUSH_INTERVAL`: Batch flush interval in seconds (default: 5)

### Elasticsearch Settings
- `ELASTICSEARCH_ADDRESSES`: Comma-separated ES endpoints
- `ELASTICSEARCH_USERNAME`: Optional authentication
- `ELASTICSEARCH_PASSWORD`: Optional authentication
- `ELASTICSEARCH_INDEX_PREFIX`: Index name prefix (default: csp-reports)

## CSP Report Endpoints

The service accepts CSP reports on multiple endpoints:
- `POST /csp-report` - Standard CSP reporting endpoint
- `POST /csp` - Alternative endpoint

### Supported Report Formats

The processor handles various CSP report formats:

```javascript
// Chrome/Webkit format
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src 'self'",
    "blocked-uri": "https://evil.com/script.js",
    "original-policy": "default-src 'self'"
  }
}

// Firefox format
{
  "cspReport": {
    "documentURI": "https://example.com/page",
    "violatedDirective": "script-src 'self'",
    "blockedURI": "https://evil.com/script.js"
  }
}

// Report-To format
{
  "body": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src 'self'",
    "blocked-uri": "https://evil.com/script.js"
  }
}
```

## Monitoring

### Health Check
```bash
curl http://localhost:8080/health
```

### Metrics
```bash
curl http://localhost:8080/metrics
```

Returns processing statistics including queue size, processed totals, and error counts.

## Production Deployment

For production use:

1. **Scale Configuration**: Increase worker count and batch sizes
2. **Elasticsearch Cluster**: Use a proper ES cluster with replicas
3. **Load Balancing**: Deploy multiple instances behind a load balancer
4. **Monitoring**: Set up proper monitoring and alerting
5. **Security**: Configure authentication and network security

### Example Production Configuration

```bash
PRODUCTION=true
WORKER_COUNT=50
BATCH_SIZE=1000
QUEUE_SIZE=100000
RATE_LIMIT=100000
RATE_BURST=200000
```

## Data Structure

Processed reports are stored in Elasticsearch with this structure:

```json
{
  "id": "unique-report-id",
  "timestamp": "2024-01-01T12:00:00Z",
  "user_agent": "Mozilla/5.0...",
  "remote_addr": "192.168.1.1",
  "browser_type": "chrome",
  "parsed_report": {
    "document_uri": "https://example.com/page",
    "violated_directive": "script-src 'self'",
    "blocked_uri": "https://evil.com/script.js",
    "original_policy": "default-src 'self'"
  },
  "raw_report": { /* original report */ },
  "human_readable": "Violated directive: script-src 'self' | Blocked URI: https://evil.com/script.js"
}
```

## Performance Tuning

For high-traffic scenarios:

1. **Increase Workers**: More workers for parallel processing
2. **Larger Batches**: Reduce Elasticsearch overhead
3. **Shorter Flush Intervals**: Reduce memory usage
4. **Rate Limiting**: Protect against abuse
5. **Resource Allocation**: Ensure adequate CPU and memory

The application is designed to handle 100,000+ requests per minute with proper configuration and infrastructure.

## Development & CI/CD

### GitHub Actions Workflows

This project includes comprehensive CI/CD pipelines:

- **CI/CD Pipeline** (`ci.yml`): 
  - Multi-version Go testing (1.21, 1.22)
  - Code linting with golangci-lint
  - Security scanning with gosec and Trivy
  - Integration tests with Elasticsearch
  - Docker build and push to GitHub Container Registry
  - Cross-platform binary releases

- **Security Scanning** (`security.yml`):
  - Daily CodeQL analysis
  - Dependency vulnerability scanning with Nancy and govulncheck
  - Container security scanning
  - Snyk integration for additional security checks

- **Release Automation** (`release.yml`):
  - Automatic releases on git tags
  - Multi-platform binary builds (Linux, macOS, Windows on amd64/arm64)
  - Container images with SBOM generation
  - Automated changelog generation

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Push and create a pull request

All PRs trigger the full CI pipeline including tests, security scans, and integration tests.

### Container Registry

Official images are available at:
- `ghcr.io/sagenkoder/universal-csp-report:latest`
- `ghcr.io/sagenkoder/universal-csp-report:v1.0.0` (tagged versions)