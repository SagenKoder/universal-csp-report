package server

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"universal-csp-report/internal/config"
	"universal-csp-report/internal/models"
	"universal-csp-report/internal/processor"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

type Server struct {
	config    config.ServerConfig
	processor *processor.BatchProcessor
	logger    *logrus.Logger
	server    *http.Server
	limiter   *rate.Limiter
}

func New(cfg config.ServerConfig, proc *processor.BatchProcessor, logger *logrus.Logger) *Server {
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateBurst)

	return &Server{
		config:    cfg,
		processor: proc,
		logger:    logger,
		limiter:   limiter,
	}
}

func (s *Server) Start() error {
	if s.config.Production {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(s.loggingMiddleware())
	router.Use(s.rateLimitMiddleware())
	router.Use(s.metricsMiddleware())

	router.POST("/csp-report", s.handleCSPReport)
	router.POST("/csp", s.handleCSPReport)
	router.GET("/health", s.handleHealth)
	router.GET("/metrics", s.handleMetrics)

	s.server = &http.Server{
		Addr:         ":" + strconv.Itoa(s.config.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(s.config.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.IdleTimeout) * time.Second,
	}

	s.logger.Infof("Starting server on port %d", s.config.Port)
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down HTTP server...")
	return s.server.Shutdown(ctx)
}

func (s *Server) handleCSPReport(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		s.logger.WithError(err).Error("Failed to read request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Empty request body"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	remoteAddr := c.ClientIP()

	report, err := models.ParseCSPReport(body, userAgent, remoteAddr)
	if err != nil {
		s.logger.WithError(err).Error("Failed to parse CSP report")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSP report format"})
		return
	}

	if err := s.processor.Submit(report); err != nil {
		s.logger.WithError(err).Error("Failed to submit report for processing")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Processing error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "received"})
}

func (s *Server) handleHealth(c *gin.Context) {
	status := s.processor.GetStatus()
	c.JSON(http.StatusOK, gin.H{
		"status":          "healthy",
		"queue_size":      status.QueueSize,
		"processed_total": status.ProcessedTotal,
		"errors_total":    status.ErrorsTotal,
	})
}

func (s *Server) handleMetrics(c *gin.Context) {
	status := s.processor.GetStatus()
	c.JSON(http.StatusOK, status)
}

func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		s.logger.WithFields(logrus.Fields{
			"status":     param.StatusCode,
			"method":     param.Method,
			"path":       param.Path,
			"ip":         param.ClientIP,
			"latency":    param.Latency,
			"user_agent": param.Request.UserAgent(),
		}).Info("HTTP request")
		return ""
	})
}

func (s *Server) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.limiter.Allow() {
			s.logger.WithField("ip", c.ClientIP()).Warn("Rate limit exceeded")
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		duration := time.Since(start)

		s.logger.WithFields(logrus.Fields{
			"method":   c.Request.Method,
			"path":     c.Request.URL.Path,
			"status":   c.Writer.Status(),
			"duration": duration.Milliseconds(),
		}).Debug("Request processed")
	}
}
