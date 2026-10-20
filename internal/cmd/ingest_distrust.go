package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

type DistrustStore interface {
	RefreshDistrust(context.Context, string, func() ([]distrust.Rule, error)) error
}

type IngestDistrustConfig struct {
	DBConfig   *db.Config
	Source     string
	Timeout    time.Duration
	Verbose    bool
	Stderr     io.Writer
	HTTPClient distrust.HTTPClient
	Store      DistrustStore // Optional injection for tests.
}

func DefaultIngestDistrustConfig() *IngestDistrustConfig {
	return &IngestDistrustConfig{Source: "all", Timeout: 120 * time.Second, Stderr: os.Stderr}
}

func IngestDistrust(ctx context.Context, cfg *IngestDistrustConfig) error {
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	sources := []string{distrust.OneCRL, distrust.CCADB}
	if cfg.Source != "all" {
		if cfg.Source != distrust.OneCRL && cfg.Source != distrust.CCADB {
			return fmt.Errorf("source must be all, mozilla_onecrl, or ccadb")
		}
		sources = []string{cfg.Source}
	}
	store := cfg.Store
	if store == nil {
		database, err := db.Open(cfg.DBConfig)
		if err != nil {
			return err
		}
		defer database.Close()
		if err = db.CheckMigrationVersion(database.DB); err != nil {
			return err
		}
		store = db.NewRepository(database)
	}
	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, &slog.HandlerOptions{Level: level}))
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	var failures []error
	for _, source := range sources {
		count := 0
		err := store.RefreshDistrust(ctx, source, func() ([]distrust.Rule, error) {
			fetchCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
			defer cancel()
			rules, err := distrust.Fetch(fetchCtx, client, source)
			count = len(rules)
			return rules, err
		})
		if err != nil {
			logger.Error("distrust refresh failed; existing rules retained", "source", source, "error", err)
			failures = append(failures, fmt.Errorf("%s: %w", source, err))
			continue
		}
		logger.Info("distrust source refreshed", "source", source, "active_rules", count)
	}
	return errors.Join(failures...)
}
