package config

import (
	"os"
	"strconv"
	"strings"
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
			Port:         getEnvInt("SERVER_PORT", 8080),
			Production:   getEnvBool("PRODUCTION", false),
			ReadTimeout:  getEnvInt("SERVER_READ_TIMEOUT", 30),
			WriteTimeout: getEnvInt("SERVER_WRITE_TIMEOUT", 30),
			IdleTimeout:  getEnvInt("SERVER_IDLE_TIMEOUT", 120),
			RateLimit:    getEnvInt("RATE_LIMIT", 10000),
			RateBurst:    getEnvInt("RATE_BURST", 20000),
		},
		BatchProcessor: BatchProcessorConfig{
			WorkerCount:   getEnvInt("WORKER_COUNT", 10),
			BatchSize:     getEnvInt("BATCH_SIZE", 100),
			QueueSize:     getEnvInt("QUEUE_SIZE", 10000),
			FlushInterval: getEnvInt("FLUSH_INTERVAL", 5),
		},
		Elasticsearch: ElasticsearchConfig{
			Addresses:   getEnvStringSlice("ELASTICSEARCH_ADDRESSES", []string{"http://localhost:9200"}),
			Username:    getEnvString("ELASTICSEARCH_USERNAME", ""),
			Password:    getEnvString("ELASTICSEARCH_PASSWORD", ""),
			IndexPrefix: getEnvString("ELASTICSEARCH_INDEX_PREFIX", "csp-reports"),
		},
		LogLevel: getEnvInt("LOG_LEVEL", 4), // Info level
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