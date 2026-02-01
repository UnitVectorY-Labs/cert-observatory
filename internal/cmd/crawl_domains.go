package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/crawler"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
)

// CrawlDomainsConfig contains configuration for the crawl-domains command.
type CrawlDomainsConfig struct {
	// AgeDays is the number of days since last successful crawl
	AgeDays int
	// Parallel is the number of concurrent crawlers
	Parallel int
	// Timeout for each crawl operation
	Timeout time.Duration
	// Verbose enables debug logging
	Verbose bool
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stderr is the writer for logging
	Stderr io.Writer
}

// DefaultCrawlDomainsConfig returns default configuration.
func DefaultCrawlDomainsConfig() *CrawlDomainsConfig {
	return &CrawlDomainsConfig{
		AgeDays:  1,
		Parallel: 4,
		Timeout:  10 * time.Second,
		Stderr:   os.Stderr,
	}
}

// CrawlDomainsStats contains statistics from the crawl-domains command.
type CrawlDomainsStats struct {
	Eligible  int
	Succeeded int
	Failed    int
	Duration  time.Duration
}

// CrawlDomains executes the crawl-domains command.
func CrawlDomains(ctx context.Context, cfg *CrawlDomainsConfig) error {
	startTime := time.Now()

	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	logger.Info("starting crawl-domains job",
		"age_days", cfg.AgeDays,
		"parallel", cfg.Parallel,
	)

	// Connect to database
	database, err := db.Open(cfg.DBConfig)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return fmt.Errorf("database connection: %w", err)
	}
	defer database.Close()

	// Check migration version
	if err := db.CheckMigrationVersion(database.DB); err != nil {
		logger.Error("database migration check failed", "error", err)
		return fmt.Errorf("migration check: %w", err)
	}

	repo := db.NewRepository(database)

	// Calculate effective age: (age_days * 24h) - 1h
	effectiveAge := time.Duration(cfg.AgeDays*24)*time.Hour - 1*time.Hour
	if effectiveAge < 0 {
		effectiveAge = 0
	}

	logger.Debug("effective age threshold", "effective_age", effectiveAge.String())

	// Get count of eligible domains first for logging
	totalEligible, err := repo.CountEligibleDomains(ctx, effectiveAge)
	if err != nil {
		logger.Error("failed to count eligible domains", "error", err)
		return fmt.Errorf("count eligible domains: %w", err)
	}

	if totalEligible == 0 {
		logger.Info("no domains eligible for crawling")
		return nil
	}

	logger.Info("found eligible domains", "count", totalEligible)

	// Fetch eligible domains (fetch in batches but for simplicity, get all at once)
	// In production, you might want to batch this
	const batchLimit = 10000
	domains, err := repo.GetEligibleDomainsForCrawl(ctx, effectiveAge, batchLimit)
	if err != nil {
		logger.Error("failed to get eligible domains", "error", err)
		return fmt.Errorf("get eligible domains: %w", err)
	}

	// Create crawler
	c := crawler.New(cfg.Timeout)
	backoffPolicy := db.DefaultBackoffPolicy()

	// Statistics counters
	var succeeded atomic.Int64
	var failed atomic.Int64

	// Worker pool
	domainChan := make(chan *db.EligibleDomain)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.Parallel; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for domain := range domainChan {
				crawlOneDomain(ctx, domain, c, repo, backoffPolicy, logger, cfg.Verbose, &succeeded, &failed)
			}
		}(i)
	}

	// Send domains to workers
	for _, domain := range domains {
		select {
		case <-ctx.Done():
			close(domainChan)
			return ctx.Err()
		case domainChan <- domain:
		}
	}
	close(domainChan)

	// Wait for all workers to complete
	wg.Wait()

	duration := time.Since(startTime)

	// Log final summary
	logger.Info("crawl-domains job completed",
		"eligible", len(domains),
		"succeeded", succeeded.Load(),
		"failed", failed.Load(),
		"duration", duration.String(),
	)

	return nil
}

func crawlOneDomain(
	ctx context.Context,
	domain *db.EligibleDomain,
	c *crawler.Crawler,
	repo *db.Repository,
	policy *db.BackoffPolicy,
	logger *slog.Logger,
	verbose bool,
	succeeded *atomic.Int64,
	failed *atomic.Int64,
) {
	crawlTime := time.Now()

	result, err := c.Crawl(ctx, domain.Domain)
	if err != nil {
		// Record failure with backoff
		noRetryBefore, consecutiveFailures, dbErr := repo.RecordAutoCrawlFailure(ctx, domain.Domain, crawlTime, policy)
		if dbErr != nil {
			logger.Error("failed to record crawl failure",
				"domain", domain.Domain,
				"crawl_error", err.Error(),
				"db_error", dbErr.Error(),
			)
		} else {
			// Always log failures (even without verbose)
			logger.Warn("crawl failed",
				"domain", domain.Domain,
				"reason", categorizeError(err),
				"consecutive_failures", consecutiveFailures,
				"no_retry_before", noRetryBefore.Format(time.RFC3339),
			)
		}
		failed.Add(1)
		return
	}

	// Record success
	_, err = repo.RecordAutoCrawlSuccess(ctx, domain.Domain, result.ChainInfo, crawlTime)
	if err != nil {
		logger.Error("failed to record crawl success",
			"domain", domain.Domain,
			"error", err.Error(),
		)
		failed.Add(1)
		return
	}

	succeeded.Add(1)

	// Only log individual successes in verbose mode
	if verbose {
		logger.Debug("crawl succeeded",
			"domain", domain.Domain,
			"chain_depth", result.ChainInfo.Depth,
		)
	}
}

// categorizeError returns a brief category for the error.
func categorizeError(err error) string {
	errStr := err.Error()

	// Check for common error patterns
	switch {
	case contains(errStr, "timeout"):
		return "timeout"
	case contains(errStr, "connection refused"):
		return "connection_refused"
	case contains(errStr, "no such host"):
		return "dns_error"
	case contains(errStr, "handshake"):
		return "handshake_failure"
	case contains(errStr, "certificate"):
		return "certificate_error"
	case contains(errStr, "network"):
		return "network_error"
	default:
		return "unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
