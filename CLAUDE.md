# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Universal CSP Report Processor - A high-performance Go application that processes Content Security Policy violation reports from all major browsers, handling implementation inconsistencies and storing reports in Elasticsearch.

## Architecture

The application follows clean architecture principles:
- **HTTP Layer**: Gin framework server with middleware (rate limiting, logging, metrics)
- **Processing Layer**: Batch processor with configurable worker pools
- **Storage Layer**: Elasticsearch integration with daily index rotation
- **Models**: Unified CSP report structure handling browser variations

Key architectural decisions:
- Uses Go's internal package pattern to prevent external imports of core logic
- Implements worker pool pattern for high-throughput batch processing
- Abstracts storage interface to allow future storage backends

## Common Development Commands

### Build and Run
```bash
# Download dependencies (requires Go 1.23+)
go mod download

# Build application
go build -o universal-csp-report .

# Run directly (ensure .env file exists, copy from .env.example)
cp .env.example .env  # First time only
go run main.go

# Run with Docker Compose (includes Elasticsearch and Kibana)
docker-compose up -d
```

### Testing
```bash
# Run unit tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests (requires Elasticsearch)
./test_server.sh                      # Basic CSP report validation
./comprehensive_test.sh               # Tests common browser formats
./comprehensive_test_all_formats.sh   # Tests ALL format variations and edge cases

# Load testing (sends 300 parallel requests)
./load_test.sh

# Test data available in test_payloads.json for manual testing
```

### Linting and Type Checking
```bash
# Run golangci-lint (if installed)
golangci-lint run

# Run go vet
go vet ./...

# Format code
go fmt ./...
```

## Key Implementation Details

### CSP Report Handling
The processor now supports ALL CSP report formats documented in `internal/models/CSP-REPORT-FORMATS.md`:

**Fully supported formats**:
- ✅ Standard CSP format with `csp-report` wrapper (Safari, older browsers)
- ✅ Chrome/Edge batch format with `application/reports+json` (arrays of reports)
- ✅ Firefox modern format with camelCase fields
- ✅ Report-To API format (both single and batch)
- ✅ Legacy WebKit format with `-url` suffix variations
- ✅ All field name variations (kebab-case, camelCase, snake_case)
- ✅ Special blocked-uri values ("inline", "eval", "data", "blob", etc.)
- ✅ String number parsing from legacy browsers
- ✅ SHA256 field from Firefox reports
- ✅ Unicode content in all fields

**Key implementation features**:
- Automatic format detection based on content structure
- Batch processing for Chrome's array format
- Field name normalization across all variations
- Special value handling (empty string → "inline", unquoted CSP keywords)
- Graceful error handling for mixed batches
- Human-readable output with contextual descriptions

See `internal/models/CSP-REPORT-FORMATS.md` for the complete specification.

### Performance Considerations
- Default configuration handles ~10,000 requests/minute
- Production configuration can handle 100,000+ requests/minute
- Batch processing reduces Elasticsearch load
- Worker pool prevents memory exhaustion
- Rate limiting protects against abuse

### Elasticsearch Integration
- Creates daily indices with pattern `csp-reports-YYYY-MM-DD`
- Uses bulk API for efficient indexing
- Implements retry logic for transient failures
- Configures proper field mappings for search and aggregation

## Environment Configuration

Configuration is managed via environment variables. Copy `.env.example` to `.env` for local development.

Key environment variables:
- `ELASTICSEARCH_ADDRESSES`: Required for storage backend
- `WORKER_COUNT`: Scale based on expected load
- `BATCH_SIZE`: Balance between latency and throughput
- `RATE_LIMIT`: Protect against malicious clients
- `PRODUCTION`: Enables production optimizations
- `LOG_LEVEL`: Logging verbosity (debug, info, warn, error)

See `.env.example` for all available configuration options with defaults.

## Development Stack

The Docker Compose setup includes:
- **CSP Report Service**: The Go application on port 8080
- **Elasticsearch 8.11.1**: Data storage on port 9200
- **Kibana 8.11.1**: Data visualization on port 5601

Access points:
- CSP Reports: `http://localhost:8080/csp-report`
- Health Check: `http://localhost:8080/health`
- Metrics: `http://localhost:8080/metrics`
- Kibana Dashboard: `http://localhost:5601`

## CI/CD Pipeline

The project uses GitHub Actions for:
- Multi-version Go testing (1.21, 1.22)
- Security scanning (gosec, Trivy, CodeQL)
- Container builds and publishing to ghcr.io
- Automated releases with cross-platform binaries

Always ensure tests pass before committing changes that affect core functionality.