package storage

import "universal-csp-report/internal/models"

type Storage interface {
	StoreBatch(reports []*models.CSPReport) error
	Close() error
}
