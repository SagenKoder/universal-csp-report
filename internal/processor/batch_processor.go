package processor

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"universal-csp-report/internal/config"
	"universal-csp-report/internal/models"
	"universal-csp-report/internal/storage"

	"github.com/sirupsen/logrus"
)

type BatchProcessor struct {
	config  config.BatchProcessorConfig
	storage storage.Storage
	logger  *logrus.Logger

	reportChan chan *models.CSPReport
	batchChan  chan []*models.CSPReport

	workers []Worker
	batcher *Batcher

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stats Stats
}

type Stats struct {
	QueueSize      int64 `json:"queue_size"`
	ProcessedTotal int64 `json:"processed_total"`
	ErrorsTotal    int64 `json:"errors_total"`
	BatchesTotal   int64 `json:"batches_total"`
}

type Worker struct {
	id      int
	storage storage.Storage
	logger  *logrus.Logger
}

type Batcher struct {
	batchSize    int
	flushTimeout time.Duration
	inputChan    chan *models.CSPReport
	outputChan   chan []*models.CSPReport
	logger       *logrus.Logger
}

func New(cfg config.BatchProcessorConfig, store storage.Storage, logger *logrus.Logger) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())

	reportChan := make(chan *models.CSPReport, cfg.QueueSize)
	batchChan := make(chan []*models.CSPReport, cfg.WorkerCount*config.BatchChannelMultiplier)

	return &BatchProcessor{
		config:     cfg,
		storage:    store,
		logger:     logger,
		reportChan: reportChan,
		batchChan:  batchChan,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (bp *BatchProcessor) Start() {
	bp.logger.Info("Starting batch processor")

	bp.batcher = &Batcher{
		batchSize:    bp.config.BatchSize,
		flushTimeout: time.Duration(bp.config.FlushInterval) * time.Second,
		inputChan:    bp.reportChan,
		outputChan:   bp.batchChan,
		logger:       bp.logger,
	}

	bp.wg.Add(1)
	go bp.batcher.start(bp.ctx, &bp.wg)

	bp.workers = make([]Worker, bp.config.WorkerCount)
	for i := 0; i < bp.config.WorkerCount; i++ {
		bp.workers[i] = Worker{
			id:      i,
			storage: bp.storage,
			logger:  bp.logger,
		}

		bp.wg.Add(1)
		go bp.workers[i].start(bp.ctx, bp.batchChan, &bp.wg, &bp.stats)
	}

	bp.logger.WithFields(logrus.Fields{
		"workers":    bp.config.WorkerCount,
		"batch_size": bp.config.BatchSize,
		"queue_size": bp.config.QueueSize,
	}).Info("Batch processor started")
}

func (bp *BatchProcessor) Stop() {
	bp.logger.Info("Stopping batch processor")
	bp.cancel()
	bp.wg.Wait()
	bp.logger.Info("Batch processor stopped")
}

func (bp *BatchProcessor) Submit(report *models.CSPReport) error {
	select {
	case bp.reportChan <- report:
		atomic.AddInt64(&bp.stats.QueueSize, 1)
		return nil
	default:
		atomic.AddInt64(&bp.stats.ErrorsTotal, 1)
		bp.logger.Warn("Report queue is full, dropping report")
		return nil
	}
}

func (bp *BatchProcessor) GetStatus() Stats {
	return Stats{
		QueueSize:      atomic.LoadInt64(&bp.stats.QueueSize),
		ProcessedTotal: atomic.LoadInt64(&bp.stats.ProcessedTotal),
		ErrorsTotal:    atomic.LoadInt64(&bp.stats.ErrorsTotal),
		BatchesTotal:   atomic.LoadInt64(&bp.stats.BatchesTotal),
	}
}

func (b *Batcher) start(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	batch := make([]*models.CSPReport, 0, b.batchSize)
	ticker := time.NewTicker(b.flushTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				b.flushBatch(batch)
			}
			return

		case report := <-b.inputChan:
			batch = append(batch, report)
			if len(batch) >= b.batchSize {
				b.flushBatch(batch)
				batch = make([]*models.CSPReport, 0, b.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				b.flushBatch(batch)
				batch = make([]*models.CSPReport, 0, b.batchSize)
			}
		}
	}
}

func (b *Batcher) flushBatch(batch []*models.CSPReport) {
	if len(batch) == 0 {
		return
	}

	batchCopy := make([]*models.CSPReport, len(batch))
	copy(batchCopy, batch)

	select {
	case b.outputChan <- batchCopy:
	default:
		b.logger.Warn("Batch channel is full, dropping batch")
	}
}

func (w *Worker) start(ctx context.Context, batchChan chan []*models.CSPReport, wg *sync.WaitGroup, stats *Stats) {
	defer wg.Done()

	logger := w.logger.WithField("worker_id", w.id)
	logger.Info("Worker started")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Worker stopping")
			return

		case batch := <-batchChan:
			w.processBatch(batch, stats, logger)
		}
	}
}

func (w *Worker) processBatch(batch []*models.CSPReport, stats *Stats, logger *logrus.Entry) {
	if len(batch) == 0 {
		return
	}

	start := time.Now()
	err := w.storage.StoreBatch(batch)
	duration := time.Since(start)

	atomic.AddInt64(&stats.QueueSize, -int64(len(batch)))
	atomic.AddInt64(&stats.BatchesTotal, 1)

	if err != nil {
		atomic.AddInt64(&stats.ErrorsTotal, int64(len(batch)))
		logger.WithError(err).WithFields(logrus.Fields{
			"batch_size": len(batch),
			"duration":   duration,
		}).Error("Failed to store batch")
		return
	}

	atomic.AddInt64(&stats.ProcessedTotal, int64(len(batch)))
	logger.WithFields(logrus.Fields{
		"batch_size": len(batch),
		"duration":   duration,
	}).Debug("Batch processed successfully")
}
