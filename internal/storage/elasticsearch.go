package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"universal-csp-report/internal/config"
	"universal-csp-report/internal/models"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

const (
	esConnectionTimeout = 10 * time.Second
	esBulkTimeout       = 30 * time.Second
)

type ElasticsearchStorage struct {
	client *elasticsearch.Client
	config config.ElasticsearchConfig
}

func NewElasticsearchClient(cfg config.ElasticsearchConfig) (Storage, error) {
	esCfg := elasticsearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
	}

	client, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), esConnectionTimeout)
	defer cancel()

	res, err := client.Info(client.Info.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Elasticsearch: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("elasticsearch connection error: %s", res.Status())
	}

	storage := &ElasticsearchStorage{
		client: client,
		config: cfg,
	}

	if err := storage.ensureIndexTemplate(); err != nil {
		return nil, fmt.Errorf("failed to ensure index template: %w", err)
	}

	return storage, nil
}

func (es *ElasticsearchStorage) StoreBatch(reports []*models.CSPReport) error {
	if len(reports) == 0 {
		return nil
	}

	var buf bytes.Buffer

	for _, report := range reports {
		indexName := es.getIndexName(report.Timestamp)

		meta := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": indexName,
				"_id":    report.ID,
			},
		}

		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		docBytes, err := json.Marshal(report)
		if err != nil {
			return fmt.Errorf("failed to marshal document: %w", err)
		}

		buf.Write(metaBytes)
		buf.WriteByte('\n')
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	ctx, cancel := context.WithTimeout(context.Background(), esBulkTimeout)
	defer cancel()

	req := esapi.BulkRequest{
		Body:    strings.NewReader(buf.String()),
		Refresh: "false",
	}

	res, err := req.Do(ctx, es.client)
	if err != nil {
		return fmt.Errorf("bulk request failed: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("bulk request error: %s", res.Status())
	}

	var bulkResponse struct {
		Errors bool                     `json:"errors"`
		Items  []map[string]interface{} `json:"items"`
	}

	if err := json.NewDecoder(res.Body).Decode(&bulkResponse); err != nil {
		return fmt.Errorf("failed to decode bulk response: %w", err)
	}

	if bulkResponse.Errors {
		return fmt.Errorf("bulk indexing had errors")
	}

	return nil
}

func (es *ElasticsearchStorage) Close() error {
	return nil
}

func (es *ElasticsearchStorage) getIndexName(timestamp time.Time) string {
	return fmt.Sprintf("%s-%s", es.config.IndexPrefix, timestamp.Format("2006.01.02"))
}

func (es *ElasticsearchStorage) ensureIndexTemplate() error {
	templateName := es.config.IndexPrefix + "-template"

	template := map[string]interface{}{
		"index_patterns": []string{es.config.IndexPrefix + "-*"},
		"template": map[string]interface{}{
			"settings": map[string]interface{}{
				"number_of_shards":   1,
				"number_of_replicas": 0,
				"refresh_interval":   "30s",
			},
			"mappings": map[string]interface{}{
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type": "keyword",
					},
					"timestamp": map[string]interface{}{
						"type": "date",
					},
					"user_agent": map[string]interface{}{
						"type": "text",
						"fields": map[string]interface{}{
							"keyword": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
					"remote_addr": map[string]interface{}{
						"type": "ip",
					},
					"browser_type": map[string]interface{}{
						"type": "keyword",
					},
					"parsed_report": map[string]interface{}{
						"properties": map[string]interface{}{
							"document_uri": map[string]interface{}{
								"type": "keyword",
							},
							"referrer": map[string]interface{}{
								"type": "keyword",
							},
							"violated_directive": map[string]interface{}{
								"type": "keyword",
							},
							"original_policy": map[string]interface{}{
								"type": "text",
							},
							"blocked_uri": map[string]interface{}{
								"type": "keyword",
							},
							"status_code": map[string]interface{}{
								"type": "integer",
							},
							"script_sample": map[string]interface{}{
								"type": "text",
							},
							"line_number": map[string]interface{}{
								"type": "integer",
							},
							"column_number": map[string]interface{}{
								"type": "integer",
							},
							"source_file": map[string]interface{}{
								"type": "keyword",
							},
							"disposition": map[string]interface{}{
								"type": "keyword",
							},
							"effective_directive": map[string]interface{}{
								"type": "keyword",
							},
						},
					},
					"human_readable": map[string]interface{}{
						"type": "text",
					},
					"processing_errors": map[string]interface{}{
						"type": "keyword",
					},
				},
			},
		},
	}

	templateBytes, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), esConnectionTimeout)
	defer cancel()

	req := esapi.IndicesPutIndexTemplateRequest{
		Name: templateName,
		Body: bytes.NewReader(templateBytes),
	}

	res, err := req.Do(ctx, es.client)
	if err != nil {
		return fmt.Errorf("failed to create index template: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("index template creation error: %s", res.Status())
	}

	return nil
}
