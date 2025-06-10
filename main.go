package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"universal-csp-report/internal/config"
	"universal-csp-report/internal/processor"
	"universal-csp-report/internal/server"
	"universal-csp-report/internal/storage"

	"github.com/sirupsen/logrus"
)

func main() {
	cfg := config.Load()
	
	logger := logrus.New()
	logger.SetLevel(logrus.Level(cfg.LogLevel))
	logger.SetFormatter(&logrus.JSONFormatter{})

	esClient, err := storage.NewElasticsearchClient(cfg.Elasticsearch)
	if err != nil {
		logger.Fatalf("Failed to create Elasticsearch client: %v", err)
	}

	batchProcessor := processor.New(cfg.BatchProcessor, esClient, logger)
	batchProcessor.Start()

	httpServer := server.New(cfg.Server, batchProcessor, logger)

	go func() {
		if err := httpServer.Start(); err != nil {
			logger.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	logger.Info("Universal CSP Report processor started")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	batchProcessor.Stop()
	
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}