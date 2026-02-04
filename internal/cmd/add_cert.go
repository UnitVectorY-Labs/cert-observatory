package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
)

// AddCertConfig contains configuration for the add-cert command.
type AddCertConfig struct {
	// PEMFile is the path to the PEM file to ingest
	PEMFile string
	// Verbose enables debug logging
	Verbose bool
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stderr is the writer for logging
	Stderr io.Writer
}

// AddCertStats contains statistics from the add-cert command.
type AddCertStats struct {
	Parsed        int
	Inserted      int
	AlreadyExists int
	ParseFailures int
}

// DefaultAddCertConfig returns default configuration.
func DefaultAddCertConfig() *AddCertConfig {
	return &AddCertConfig{
		Stderr: os.Stderr,
	}
}

// AddCert executes the add-cert command.
func AddCert(ctx context.Context, cfg *AddCertConfig) error {
	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	logger.Info("starting add-cert", "pem_file", cfg.PEMFile)

	// Read PEM file
	pemData, err := os.ReadFile(cfg.PEMFile)
	if err != nil {
		logger.Error("failed to read PEM file", "error", err)
		return fmt.Errorf("read PEM file: %w", err)
	}

	// Parse PEM bundle
	certs, parseFailures := ParsePEMBundle(pemData)

	logger.Info("parsed certificates",
		"count", len(certs),
		"parse_failures", parseFailures,
	)

	if len(certs) == 0 {
		if parseFailures > 0 {
			return fmt.Errorf("no valid certificates found in PEM file (%d parse failures)", parseFailures)
		}
		return fmt.Errorf("no certificates found in PEM file")
	}

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

	// Check which certs already exist
	hashes := make([][]byte, len(certs))
	for i, cert := range certs {
		hashes[i] = cert.CertHash
	}

	existing, err := repo.CheckCertificatesExist(ctx, hashes)
	if err != nil {
		return fmt.Errorf("check existing certificates: %w", err)
	}

	stats := &AddCertStats{
		Parsed:        len(certs),
		ParseFailures: parseFailures,
	}

	// Insert certificates
	for _, cert := range certs {
		hashKey := string(cert.CertHash)
		if existing[hashKey] {
			stats.AlreadyExists++
			if cfg.Verbose {
				logger.Debug("certificate already exists",
					"subject", cert.Parsed.Subject.CommonName,
					"cert_hash", hex.EncodeToString(cert.CertHash),
				)
			}
		} else {
			inserted, err := repo.InsertRootCertificate(ctx, cert)
			if err != nil {
				return fmt.Errorf("insert certificate: %w", err)
			}
			if inserted {
				stats.Inserted++
				if cfg.Verbose {
					logger.Debug("certificate inserted",
						"subject", cert.Parsed.Subject.CommonName,
						"cert_hash", hex.EncodeToString(cert.CertHash),
					)
				}
			} else {
				// Race condition - another process inserted it
				stats.AlreadyExists++
			}
		}
	}

	logger.Info("add-cert completed",
		"parsed", stats.Parsed,
		"inserted", stats.Inserted,
		"already_exists", stats.AlreadyExists,
		"parse_failures", stats.ParseFailures,
	)

	return nil
}
