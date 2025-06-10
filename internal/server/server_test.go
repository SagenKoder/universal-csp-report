package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"universal-csp-report/internal/config"
	"universal-csp-report/internal/models"
	"universal-csp-report/internal/processor"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type mockStorage struct {
	reports [][]*models.CSPReport
}

func (m *mockStorage) StoreBatch(reports []*models.CSPReport) error {
	m.reports = append(m.reports, reports)
	return nil
}

func (m *mockStorage) Close() error {
	return nil
}

func createTestServer() *Server {
	cfg := config.ServerConfig{
		Port:         8080,
		Production:   false,
		ReadTimeout:  30,
		WriteTimeout: 30,
		IdleTimeout:  120,
		RateLimit:    1000,
		RateBurst:    2000,
	}

	processorCfg := config.BatchProcessorConfig{
		WorkerCount:   2,
		BatchSize:     10,
		QueueSize:     100,
		FlushInterval: 1,
	}

	logger := logrus.New()
	logger.SetLevel(logrus.WarnLevel) // Reduce noise in tests

	mockStore := &mockStorage{}
	batchProcessor := processor.New(processorCfg, mockStore, logger)

	return New(cfg, batchProcessor, logger)
}

func TestHandleCSPReport_ValidReports(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	tests := []struct {
		name           string
		requestBody    string
		userAgent      string
		expectedStatus int
	}{
		{
			name: "Chrome CSP report",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/page",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://evil.com/script.js",
					"original-policy": "script-src 'self'"
				}
			}`,
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Firefox CSP report",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/firefox",
					"violated-directive": "img-src 'self'",
					"blocked-uri": "https://tracker.com/pixel.gif"
				}
			}`,
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Safari CSP report",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/safari",
					"violated-directive": "style-src 'self'",
					"blocked-uri": "https://fonts.googleapis.com/css"
				}
			}`,
			userAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Edge CSP report",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/edge",
					"violated-directive": "object-src 'none'",
					"blocked-uri": "https://example.com/plugin.swf"
				}
			}`,
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Report-To API format",
			requestBody: `{
				"body": {
					"document-uri": "https://example.com/report-to",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://analytics.com/track.js",
					"disposition": "enforce"
				}
			}`,
			userAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/csp-report", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", tt.userAgent)

			w := httptest.NewRecorder()

			router := gin.New()
			router.POST("/csp-report", server.handleCSPReport)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Errorf("Failed to parse response JSON: %v", err)
			}

			if response["status"] != "received" {
				t.Errorf("Expected status 'received', got %v", response["status"])
			}
		})
	}
}

func TestHandleCSPReport_InvalidRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	tests := []struct {
		name           string
		requestBody    string
		userAgent      string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Empty body",
			requestBody:    "",
			userAgent:      "Mozilla/5.0 Chrome/120.0.0.0",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Empty request body",
		},
		{
			name:           "Invalid JSON",
			requestBody:    "{invalid json}",
			userAgent:      "Mozilla/5.0 Chrome/120.0.0.0",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid CSP report format",
		},
		{
			name:           "Non-JSON content",
			requestBody:    "this is not json",
			userAgent:      "Mozilla/5.0 Chrome/120.0.0.0",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid CSP report format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/csp-report", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", tt.userAgent)

			w := httptest.NewRecorder()

			router := gin.New()
			router.POST("/csp-report", server.handleCSPReport)
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Errorf("Failed to parse response JSON: %v", err)
			}

			if response["error"] != tt.expectedError {
				t.Errorf("Expected error '%s', got %v", tt.expectedError, response["error"])
			}
		})
	}
}

func TestHandleHealth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router := gin.New()
	router.GET("/health", server.handleHealth)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse response JSON: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", response["status"])
	}

	// Check that metrics are present
	requiredFields := []string{"queue_size", "processed_total", "errors_total"}
	for _, field := range requiredFields {
		if _, exists := response[field]; !exists {
			t.Errorf("Missing required field '%s' in health response", field)
		}
	}
}

func TestHandleMetrics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	router := gin.New()
	router.GET("/metrics", server.handleMetrics)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse response JSON: %v", err)
	}

	// Check that all expected metrics are present
	expectedFields := []string{"queue_size", "processed_total", "errors_total", "batches_total"}
	for _, field := range expectedFields {
		if _, exists := response[field]; !exists {
			t.Errorf("Missing expected field '%s' in metrics response", field)
		}
	}
}

func TestAlternativeEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	requestBody := `{
		"csp-report": {
			"document-uri": "https://example.com/test",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "https://example.com/script.js"
		}
	}`

	endpoints := []string{"/csp-report", "/csp"}

	for _, endpoint := range endpoints {
		t.Run("Endpoint_"+endpoint, func(t *testing.T) {
			req := httptest.NewRequest("POST", endpoint, bytes.NewBufferString(requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

			w := httptest.NewRecorder()

			router := gin.New()
			router.POST("/csp-report", server.handleCSPReport)
			router.POST("/csp", server.handleCSPReport)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		})
	}
}

func TestLargePayloads(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	// Create a large script sample
	largeScriptSample := strings.Repeat("a", 10000)

	requestBody := `{
		"csp-report": {
			"document-uri": "https://example.com/large",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "inline",
			"script-sample": "` + largeScriptSample + `"
		}
	}`

	req := httptest.NewRequest("POST", "/csp-report", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

	w := httptest.NewRecorder()

	router := gin.New()
	router.POST("/csp-report", server.handleCSPReport)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	requestBody := `{
		"csp-report": {
			"document-uri": "https://example.com/concurrent",
			"violated-directive": "script-src 'self'",
			"blocked-uri": "https://example.com/script.js"
		}
	}`

	router := gin.New()
	router.POST("/csp-report", server.handleCSPReport)

	// Launch multiple concurrent requests
	numRequests := 50
	results := make(chan int, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("POST", "/csp-report", bytes.NewBufferString(requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			results <- w.Code
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < numRequests; i++ {
		select {
		case code := <-results:
			if code == http.StatusOK {
				successCount++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	if successCount != numRequests {
		t.Errorf("Expected %d successful requests, got %d", numRequests, successCount)
	}
}

func TestSpecialCharactersAndEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := createTestServer()

	tests := []struct {
		name        string
		requestBody string
		description string
	}{
		{
			name: "Unicode characters",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/测试页面",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://example.com/スクリプト.js"
				}
			}`,
			description: "Should handle Unicode characters in URLs",
		},
		{
			name: "Special characters in script sample",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/special",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "inline",
					"script-sample": "alert('Hello \"World\"! \n\t\r');"
				}
			}`,
			description: "Should handle special characters and escapes",
		},
		{
			name: "URLs with encoded characters",
			requestBody: `{
				"csp-report": {
					"document-uri": "https://example.com/path%20with%20spaces",
					"violated-directive": "script-src 'self'",
					"blocked-uri": "https://example.com/script%2Ename.js"
				}
			}`,
			description: "Should handle URL-encoded characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/csp-report", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")

			w := httptest.NewRecorder()

			router := gin.New()
			router.POST("/csp-report", server.handleCSPReport)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("%s: Expected status %d, got %d", tt.description, http.StatusOK, w.Code)
			}
		})
	}
}
