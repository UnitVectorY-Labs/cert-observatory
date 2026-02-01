// Package cmd provides command-line interface implementations.
package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/crawler"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/domain"
)

// CrawlDomainConfig contains configuration for the crawl-domain command.
type CrawlDomainConfig struct {
	// URL is the domain to crawl (despite the name, not a full URL)
	URL string
	// Timeout for the crawl operation
	Timeout time.Duration
	// Verbose enables debug logging
	Verbose bool
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stdout is the writer for certificate output
	Stdout io.Writer
	// Stderr is the writer for logging
	Stderr io.Writer
}

// CrawlDomain executes the crawl-domain command.
func CrawlDomain(ctx context.Context, cfg *CrawlDomainConfig) error {
	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	// Validate and normalize domain
	normalizedDomain, err := domain.NormalizeAndValidate(cfg.URL)
	if err != nil {
		logger.Error("invalid domain", "input", cfg.URL, "error", err)
		return fmt.Errorf("invalid domain: %w", err)
	}

	logger.Info("starting crawl", "domain", normalizedDomain)

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

	// Perform crawl
	c := crawler.New(cfg.Timeout)
	result, err := c.Crawl(ctx, normalizedDomain)
	if err != nil {
		// Record failed crawl
		logger.Error("crawl failed", "domain", normalizedDomain, "error", err)

		if dbErr := repo.RecordFailedCrawl(ctx, normalizedDomain, time.Now(), db.CrawlModeStandard); dbErr != nil {
			logger.Error("failed to record failed crawl", "error", dbErr)
		}

		return fmt.Errorf("crawl failed: %w", err)
	}

	// Log chain info
	logger.Info("crawl successful",
		"domain", normalizedDomain,
		"certs_in_chain", result.ChainInfo.Depth,
	)

	if cfg.Verbose {
		logger.Debug("chain details",
			"chain_hash", hex.EncodeToString(result.ChainInfo.ChainHash),
			"leaf_cert_hash", hex.EncodeToString(result.ChainInfo.LeafCertHash),
		)

		for i, cert := range result.ChainInfo.Certs {
			logAttrs := []any{
				"position", i + 1,
				"cert_hash", hex.EncodeToString(cert.CertHash),
				"not_before", cert.NotBefore.Format(time.RFC3339),
				"not_after", cert.NotAfter.Format(time.RFC3339),
			}
			if cert.SKI != nil {
				logAttrs = append(logAttrs, "ski_present", true)
			}
			if cert.AKI != nil {
				logAttrs = append(logAttrs, "aki_present", true)
			}
			logger.Debug("certificate", logAttrs...)
		}
	}

	// Record successful crawl
	dbResult := &db.CrawlResult{
		Domain:    normalizedDomain,
		ChainInfo: result.ChainInfo,
		CrawlTime: result.CrawlTime,
		Mode:      db.CrawlModeStandard,
	}

	stats, err := repo.RecordSuccessfulCrawl(ctx, dbResult)
	if err != nil {
		logger.Error("failed to record crawl result", "error", err)
		return fmt.Errorf("record crawl: %w", err)
	}

	// Log database update summary
	if stats.DomainInserted {
		logger.Info("domain inserted", "domain", normalizedDomain)
	} else {
		logger.Info("domain already existed", "domain", normalizedDomain)
	}

	if stats.CertsInserted > 0 {
		logger.Info("certificates inserted", "count", stats.CertsInserted)
	}

	if stats.ChainInserted {
		logger.Info("chain inserted (new)")
	} else {
		logger.Info("chain already existed")
	}

	if stats.CurrentChainChanged {
		logger.Info("current chain changed for domain",
			"previous_chain_hash", hex.EncodeToString(stats.PreviousChainHash),
			"new_chain_hash", hex.EncodeToString(result.ChainInfo.ChainHash),
		)
	} else {
		logger.Info("current chain unchanged for domain")
	}

	if stats.ChainStateNewInterval {
		logger.Info("new chain state interval created")
	} else {
		logger.Info("existing chain state interval updated")
	}

	// Output PEM to stdout
	pemOutput := certutil.ChainToPEM(result.ChainInfo.Certs)
	if _, err := fmt.Fprint(cfg.Stdout, pemOutput); err != nil {
		return fmt.Errorf("write PEM output: %w", err)
	}

	return nil
}

// DefaultCrawlDomainConfig returns default values for optional config fields.
func DefaultCrawlDomainConfig() *CrawlDomainConfig {
	return &CrawlDomainConfig{
		Timeout: 10 * time.Second,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
}
