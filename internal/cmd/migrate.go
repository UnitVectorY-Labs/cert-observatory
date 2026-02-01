package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
)

// MigrateConfig contains configuration for the migrate command.
type MigrateConfig struct {
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stderr is the writer for logging
	Stderr io.Writer
}

// MigrateUp runs all pending migrations.
func MigrateUp(ctx context.Context, cfg *MigrateConfig) error {
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, nil))

	// Connect to database
	database, err := db.Open(cfg.DBConfig)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return fmt.Errorf("database connection: %w", err)
	}
	defer database.Close()

	// Get current version
	version, dirty, err := db.GetMigrationVersion(database.DB)
	if err != nil {
		logger.Error("failed to get migration version", "error", err)
		return fmt.Errorf("get migration version: %w", err)
	}

	if dirty {
		logger.Error("database is in dirty state", "version", version)
		return fmt.Errorf("database is in dirty state at version %d", version)
	}

	logger.Info("current migration version", "version", version, "expected", db.ExpectedVersion)

	if version >= uint(db.ExpectedVersion) {
		logger.Info("no migrations to run")
		return nil
	}

	// Run migrations
	logger.Info("running migrations")
	if err := db.RunMigrations(database.DB); err != nil {
		logger.Error("failed to run migrations", "error", err)
		return fmt.Errorf("run migrations: %w", err)
	}

	// Get new version
	newVersion, _, err := db.GetMigrationVersion(database.DB)
	if err != nil {
		logger.Error("failed to get new migration version", "error", err)
		return fmt.Errorf("get new migration version: %w", err)
	}

	logger.Info("migrations complete", "version", newVersion)

	return nil
}

// DefaultMigrateConfig returns default values for optional config fields.
func DefaultMigrateConfig() *MigrateConfig {
	return &MigrateConfig{
		Stderr: os.Stderr,
	}
}

// MigrateStatus shows the current migration status.
func MigrateStatus(ctx context.Context, cfg *MigrateConfig) error {
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, nil))

	database, err := db.Open(cfg.DBConfig)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		return fmt.Errorf("database connection: %w", err)
	}
	defer database.Close()

	version, dirty, err := db.GetMigrationVersion(database.DB)
	if err != nil {
		logger.Error("failed to get migration version", "error", err)
		return fmt.Errorf("get migration version: %w", err)
	}

	status := "clean"
	if dirty {
		status = "dirty"
	}

	logger.Info("migration status",
		"current_version", version,
		"expected_version", db.ExpectedVersion,
		"status", status,
	)

	if version != uint(db.ExpectedVersion) {
		logger.Info("migrations are pending")
	} else {
		logger.Info("database is up to date")
	}

	return nil
}
