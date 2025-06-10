package main

import (
	"context"
	"flag"
	"fmt"
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

var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)

func main() {
	var showVersion = flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Universal CSP Report Processor\n")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	cfg := config.Load()

	logger := logrus.New()
	if cfg.LogLevel >= 0 && cfg.LogLevel <= 6 {
		logger.SetLevel(logrus.Level(cfg.LogLevel))
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout*time.Second)
	defer cancel()

	batchProcessor.Stop()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Errorf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}
