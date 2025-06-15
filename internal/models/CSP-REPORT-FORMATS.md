# CSP Report Formats Specification

## Overview

Content Security Policy (CSP) violation reports are sent by browsers when content violates the policy. Different browsers and versions send these reports in various formats. This document describes all known formats to enable building a generic handler.

## HTTP Headers

### Request Headers
- **Content-Type**: Varies by browser and format
    - `application/csp-report` - Standard CSP format
    - `application/reports+json` - Chrome's batched format
    - `application/json` - Generic JSON (some browsers)
    - `text/plain` - Legacy/misconfigured

- **User-Agent**: Browser identification
- **Origin**: Origin of the page that triggered the violation

### Response Headers
- Should return `204 No Content` on success
- Set appropriate CORS headers if needed

## Report Format Variations

### 1. Standard CSP Report Format (CSP 1.0/2.0)

**Used by**: Safari (all versions), Firefox (older versions), Chrome (older versions)  
**Content-Type**: `application/csp-report`  
**Structure**: Single JSON object with `csp-report` wrapper

```json
{
  "csp-report": {
    "document-uri": "https://example.com/page.html",
    "referrer": "https://example.com/",
    "violated-directive": "script-src 'self'",
    "effective-directive": "script-src",
    "original-policy": "default-src 'self'; script-src 'self'; object-src 'none'",
    "blocked-uri": "https://evil.com/malicious.js",
    "status-code": 200,
    "source-file": "https://example.com/page.html",
    "line-number": 10,
    "column-number": 5,
    "script-sample": ""
  }
}
```

### 2. Chrome/Edge Batch Format

**Used by**: Chrome 46+, Edge (Chromium-based)  
**Content-Type**: `application/reports+json`  
**Structure**: Array of report objects

```json
[
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
      "originalPolicy": "script-src 'self' https://trusted.com; object-src 'none'",
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
      "originalPolicy": "style-src 'self' 'unsafe-inline'",
      "referrer": "",
      "sample": "body { background: red; }",
      "sourceFile": "https://example.com/page.html",
      "statusCode": 200,
      "violatedDirective": "style-src-elem"
    }
  }
]
```

### 3. Firefox Modern Format

**Used by**: Firefox (recent versions)  
**Content-Type**: `application/csp-report` or `application/json`  
**Structure**: Similar to standard but may include additional fields

```json
{
  "csp-report": {
    "blocked-uri": "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My...",
    "column-number": 307,
    "document-uri": "https://example.com/profile",
    "line-number": 18,
    "original-policy": "default-src 'self'; img-src 'self' https:",
    "referrer": "https://example.com/home",
    "script-sample": "",
    "source-file": "https://example.com/js/app.js",
    "violated-directive": "img-src",
    "sha256": "sha256-abcd1234..."
  }
}
```

### 4. Report-To API Format (Single Report)

**Used by**: Chrome when using Report-To header but not batching  
**Content-Type**: `application/reports+json`  
**Structure**: Single report object (not in array)

```json
{
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
    "originalPolicy": "default-src 'self'; connect-src 'self' https://api.example.com",
    "referrer": "",
    "sample": "",
    "sourceFile": "",
    "statusCode": 0,
    "violatedDirective": "connect-src"
  }
}
```

### 5. Legacy WebKit Format

**Used by**: Older Safari/WebKit versions  
**Content-Type**: `application/csp-report`  
**Structure**: Uses "url" instead of "uri" in property names

```json
{
  "csp-report": {
    "document-url": "https://example.com/legacy",
    "referrer": "",
    "violated-directive": "style-src 'self'",
    "original-policy": "default-src 'self'; style-src 'self'",
    "blocked-url": "https://fonts.googleapis.com/css",
    "source-file": "https://example.com/legacy",
    "line-number": "25",
    "column-number": "10"
  }
}
```

## Special Case Violations

### 6. Inline Script Violation

**Blocked URI**: Empty string or "inline"  
**Common with**: Inline `<script>` tags without nonce/hash

```json
{
  "csp-report": {
    "document-uri": "https://example.com/",
    "referrer": "",
    "violated-directive": "script-src 'self'",
    "effective-directive": "script-src",
    "original-policy": "script-src 'self' 'nonce-abc123'",
    "blocked-uri": "",
    "source-file": "https://example.com/",
    "line-number": 45,
    "column-number": 8,
    "script-sample": "alert('Hello World')",
    "status-code": 200
  }
}
```

### 7. Eval Violation

**Blocked URI**: "eval"  
**Common with**: `eval()`, `Function()`, `setTimeout(string)`

```json
{
  "csp-report": {
    "document-uri": "https://example.com/app",
    "referrer": "https://example.com/",
    "violated-directive": "script-src 'self'",
    "effective-directive": "script-src",
    "original-policy": "script-src 'self'",
    "blocked-uri": "eval",
    "source-file": "https://example.com/js/utils.js",
    "line-number": 102,
    "column-number": 15,
    "status-code": 200
  }
}
```

### 8. Data URI Violation

**Blocked URI**: "data" or full data URI  
**Common with**: Base64 images, fonts

```json
{
  "csp-report": {
    "document-uri": "https://example.com/gallery",
    "referrer": "",
    "violated-directive": "img-src 'self' https:",
    "effective-directive": "img-src",
    "original-policy": "default-src 'self'; img-src 'self' https:",
    "blocked-uri": "data",
    "status-code": 200
  }
}
```

### 9. Blob URI Violation

**Blocked URI**: "blob" or blob URL  
**Common with**: Dynamic content creation

```json
{
  "csp-report": {
    "document-uri": "https://example.com/editor",
    "referrer": "",
    "violated-directive": "worker-src 'self'",
    "effective-directive": "worker-src",
    "original-policy": "default-src 'self'; worker-src 'self'",
    "blocked-uri": "blob",
    "source-file": "https://example.com/js/editor.js",
    "line-number": 234,
    "column-number": 12,
    "status-code": 200
  }
}
```

### 10. WebSocket Violation

**Blocked URI**: WebSocket URL (ws:// or wss://)  
**Directive**: Usually `connect-src`

```json
{
  "csp-report": {
    "document-uri": "https://example.com/chat",
    "referrer": "",
    "violated-directive": "connect-src 'self' https:",
    "effective-directive": "connect-src",
    "original-policy": "default-src 'self'; connect-src 'self' https:",
    "blocked-uri": "wss://chat.example.com/socket",
    "status-code": 0
  }
}
```

## Field Variations and Mappings

### Field Name Variations

Different browsers/versions use different field names for the same data:

| Standard Name | Variations | Description |
|--------------|------------|-------------|
| `document-uri` | `document-url`, `documentURL` | URL of the document where violation occurred |
| `blocked-uri` | `blocked-url`, `blockedURL` | Resource that was blocked |
| `violated-directive` | `violatedDirective` | The directive that was violated |
| `effective-directive` | `effectiveDirective` | The effective directive (CSP 2.0+) |
| `original-policy` | `originalPolicy` | The full CSP policy |
| `source-file` | `sourceFile` | File where violation occurred |
| `line-number` | `lineNumber` | Line number of violation |
| `column-number` | `columnNumber` | Column number of violation |
| `script-sample` | `sample` | Sample of violating code |
| `status-code` | `statusCode` | HTTP status code |

### Special Blocked URI Values

| Value | Meaning |
|-------|---------|
| Empty string `""` | Inline script/style |
| `"inline"` | Inline script/style (Chrome) |
| `"eval"` | eval() or similar |
| `"data"` | data: URI |
| `"blob"` | blob: URI |
| `"filesystem"` | filesystem: URI |
| `"self"` | Same-origin resource |
| `"unsafe-eval"` | Eval-like construct |
| `"unsafe-inline"` | Inline script/style |

### Data Type Variations

- **Numbers**: `line-number` and `column-number` may be:
    - Numbers: `42`
    - Strings: `"42"`
    - Undefined/null if not applicable

- **Status Code**:
    - `0` for cross-origin or failed requests
    - HTTP status codes for successful requests
    - May be omitted entirely

## Processing Guidelines

### 1. Content Type Detection

Check the `Content-Type` header first:
- If `application/reports+json`: Expect Chrome batch format (array)
- If `application/csp-report`: Expect standard format (single object)
- If `application/json`: Parse and detect format

### 2. Format Detection Logic

```typescript
function detectFormat(body: any): string {
  // Check if array (Chrome batch)
  if (Array.isArray(body)) {
    return "chrome-batch";
  }
  
  // Check for standard wrapper
  if (body["csp-report"]) {
    return "standard";
  }
  
  // Check for Report-To single format
  if (body.type === "csp-violation" && body.body) {
    return "report-to-single";
  }
  
  return "unknown";
}
```

### 3. Normalization Strategy

1. Extract the actual report object from its wrapper
2. Map field names to canonical names
3. Handle special blocked-uri values
4. Parse string numbers to integers
5. Set defaults for missing fields

### 4. Validation Considerations

- **Browser Extensions**: Filter reports from browser extensions
    - Chrome: `chrome-extension://`
    - Firefox: `moz-extension://`
    - Safari: `safari-extension://`

- **Development Tools**: Filter `devtools://` source files

- **False Positives**: Common sources include:
    - Browser prefetching
    - Password managers
    - Ad blockers
    - Translation services

## Summary

A robust CSP report handler must:

1. Accept multiple Content-Type headers
2. Handle both single reports and arrays
3. Normalize different field naming conventions
4. Parse string numbers from legacy formats
5. Handle special blocked-uri values correctly
6. Filter false positives from extensions
7. Validate report authenticity
8. Implement rate limiting to prevent abuse

The handler should normalize all formats into a consistent internal structure for processing, regardless of which browser or format sent the report.
