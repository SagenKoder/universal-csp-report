package config

import (
	"os"
	"strconv"
	"strings"
)

// Default configuration values
const (
	DefaultServerPort      = 8080
	DefaultReadTimeout     = 30
	DefaultWriteTimeout    = 30
	DefaultIdleTimeout     = 120
	DefaultRateLimit       = 10000
	DefaultRateBurst       = 20000
	DefaultWorkerCount     = 10
	DefaultBatchSize       = 100
	DefaultQueueSize       = 10000
	DefaultFlushInterval   = 5
	DefaultLogLevel        = 4  // Info level
	DefaultShutdownTimeout = 30 // seconds
	BatchChannelMultiplier = 2  // Buffer multiplier for batch channel
)

type Config struct {
	Server         ServerConfig         `json:"server"`
	BatchProcessor BatchProcessorConfig `json:"batch_processor"`
	Elasticsearch  ElasticsearchConfig  `json:"elasticsearch"`
	LogLevel       int                  `json:"log_level"`
}

type ServerConfig struct {
	Port         int  `json:"port"`
	Production   bool `json:"production"`
	ReadTimeout  int  `json:"read_timeout"`
	WriteTimeout int  `json:"write_timeout"`
	IdleTimeout  int  `json:"idle_timeout"`
	RateLimit    int  `json:"rate_limit"`
	RateBurst    int  `json:"rate_burst"`
}

type BatchProcessorConfig struct {
	WorkerCount   int `json:"worker_count"`
	BatchSize     int `json:"batch_size"`
	QueueSize     int `json:"queue_size"`
	FlushInterval int `json:"flush_interval"`
}

type ElasticsearchConfig struct {
	Addresses   []string `json:"addresses"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	IndexPrefix string   `json:"index_prefix"`
}

func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         getEnvInt("SERVER_PORT", DefaultServerPort),
			Production:   getEnvBool("PRODUCTION", false),
			ReadTimeout:  getEnvInt("SERVER_READ_TIMEOUT", DefaultReadTimeout),
			WriteTimeout: getEnvInt("SERVER_WRITE_TIMEOUT", DefaultWriteTimeout),
			IdleTimeout:  getEnvInt("SERVER_IDLE_TIMEOUT", DefaultIdleTimeout),
			RateLimit:    getEnvInt("RATE_LIMIT", DefaultRateLimit),
			RateBurst:    getEnvInt("RATE_BURST", DefaultRateBurst),
		},
		BatchProcessor: BatchProcessorConfig{
			WorkerCount:   getEnvInt("WORKER_COUNT", DefaultWorkerCount),
			BatchSize:     getEnvInt("BATCH_SIZE", DefaultBatchSize),
			QueueSize:     getEnvInt("QUEUE_SIZE", DefaultQueueSize),
			FlushInterval: getEnvInt("FLUSH_INTERVAL", DefaultFlushInterval),
		},
		Elasticsearch: ElasticsearchConfig{
			Addresses:   getEnvStringSlice("ELASTICSEARCH_ADDRESSES", []string{"http://localhost:9200"}),
			Username:    getEnvString("ELASTICSEARCH_USERNAME", ""),
			Password:    getEnvString("ELASTICSEARCH_PASSWORD", ""),
			IndexPrefix: getEnvString("ELASTICSEARCH_INDEX_PREFIX", "csp-reports"),
		},
		LogLevel: getEnvInt("LOG_LEVEL", DefaultLogLevel),
	}
}

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}
