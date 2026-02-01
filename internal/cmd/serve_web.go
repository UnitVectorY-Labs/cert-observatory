package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/web"
)

// ServeWebConfig contains configuration for the serve-web command.
type ServeWebConfig struct {
	// ListenAddr is the address to listen on
	ListenAddr string
	// CrawlTimeout is the timeout for outbound crawl operations
	CrawlTimeout time.Duration
	// ReadTimeout is the HTTP server read timeout
	ReadTimeout time.Duration
	// WriteTimeout is the HTTP server write timeout
	WriteTimeout time.Duration
	// IdleTimeout is the HTTP server idle timeout
	IdleTimeout time.Duration
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Verbose enables debug logging
	Verbose bool
	// Stderr is the writer for logging
	Stderr io.Writer
}

// DefaultServeWebConfig returns default values for optional config fields.
func DefaultServeWebConfig() *ServeWebConfig {
	return &ServeWebConfig{
		ListenAddr:   ":8080",
		CrawlTimeout: 30 * time.Second,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		Stderr:       os.Stderr,
	}
}

// ServeWeb starts the web server.
func ServeWeb(ctx context.Context, cfg *ServeWebConfig) error {
	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	logger.Info("starting serve-web", "listen", cfg.ListenAddr)

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

	// Create repository and crawler
	repo := db.NewWebRepository(database)
	crawler := NewWebCrawler(cfg.CrawlTimeout)

	// Create web server
	webCfg := &web.Config{
		ListenAddr:            cfg.ListenAddr,
		CrawlTimeout:          cfg.CrawlTimeout,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		IdleTimeout:           cfg.IdleTimeout,
		StandardRefreshWindow: 23 * time.Hour,
		ForcedRefreshWindow:   1 * time.Hour,
		Logger:                logger,
	}

	server, err := web.New(webCfg, repo, crawler)
	if err != nil {
		logger.Error("failed to create web server", "error", err)
		return fmt.Errorf("create server: %w", err)
	}

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start()
	}()

	select {
	case err := <-errChan:
		if err != nil {
			logger.Error("server error", "error", err)
			return err
		}
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
			return err
		}
	}

	logger.Info("server stopped")
	return nil
}
