package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/roots"
)

// RootSource represents a source for root certificates.
type RootSource struct {
	Name string
	URL  string
}

// IngestRootsConfig contains configuration for the ingest-roots command.
type IngestRootsConfig struct {
	// Verbose enables debug logging
	Verbose bool
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stderr is the writer for logging
	Stderr io.Writer
	// HTTPClient is the HTTP client to use (for testing)
	HTTPClient HTTPClient
	// Sources is the list of root sources to ingest (nil = default sources)
	Sources []RootSource
}

// DefaultIngestRootsConfig returns default configuration.
func DefaultIngestRootsConfig() *IngestRootsConfig {
	return &IngestRootsConfig{
		Stderr: os.Stderr,
		// Sources will be loaded from embedded configuration in IngestRoots
	}
}

// IngestRootsStats contains statistics from a single source ingest.
type IngestRootsStats struct {
	SourceName    string
	Parsed        int
	Inserted      int
	AlreadyExists int
	ParseFailures int
}

// IngestRoots executes the ingest-roots command.
func IngestRoots(ctx context.Context, cfg *IngestRootsConfig) error {
	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	logger.Info("starting ingest-roots job")

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

	sources := cfg.Sources
	if len(sources) == 0 {
		// Load sources from embedded configuration
		embeddedSources, err := roots.GetSources()
		if err != nil {
			logger.Error("failed to load root sources", "error", err)
			return fmt.Errorf("load root sources: %w", err)
		}
		for _, s := range embeddedSources {
			sources = append(sources, RootSource{Name: s.Name, URL: s.URL})
		}
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}

	for _, source := range sources {
		stats, err := ingestRootSource(ctx, source, client, repo, logger, cfg.Verbose)
		if err != nil {
			logger.Error("failed to ingest root source",
				"source", source.Name,
				"error", err,
			)
			return fmt.Errorf("ingest source %s: %w", source.Name, err)
		}

		logger.Info("root source ingested",
			"source", stats.SourceName,
			"parsed", stats.Parsed,
			"inserted", stats.Inserted,
			"already_exists", stats.AlreadyExists,
			"parse_failures", stats.ParseFailures,
		)
	}

	return nil
}

func ingestRootSource(
	ctx context.Context,
	source RootSource,
	client HTTPClient,
	repo *db.Repository,
	logger *slog.Logger,
	verbose bool,
) (*IngestRootsStats, error) {
	stats := &IngestRootsStats{SourceName: source.Name}

	logger.Info("fetching root certificates", "source", source.Name, "url", source.URL)

	// Fetch PEM bundle
	pemBundle, err := fetchPEMBundle(ctx, client, source.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch PEM bundle: %w", err)
	}

	// Parse PEM bundle
	certs, parseFailures := ParsePEMBundle(pemBundle)
	stats.Parsed = len(certs)
	stats.ParseFailures = parseFailures

	logger.Info("parsed certificates",
		"source", source.Name,
		"count", len(certs),
		"parse_failures", parseFailures,
	)

	if len(certs) == 0 {
		return stats, nil
	}

	// First, check which certs already exist to minimize DB operations
	hashes := make([][]byte, len(certs))
	for i, cert := range certs {
		hashes[i] = cert.CertHash
	}

	existing, err := repo.CheckCertificatesExist(ctx, hashes)
	if err != nil {
		return nil, fmt.Errorf("check existing certificates: %w", err)
	}

	// Insert new certificates (no source association needed with simplified schema)
	for _, cert := range certs {
		hashKey := string(cert.CertHash)
		if existing[hashKey] {
			stats.AlreadyExists++
			if verbose {
				logger.Debug("certificate already exists",
					"source", source.Name,
					"subject", cert.Parsed.Subject.CommonName,
				)
			}
		} else {
			inserted, err := repo.InsertRootCertificate(ctx, cert)
			if err != nil {
				return nil, fmt.Errorf("insert certificate: %w", err)
			}
			if inserted {
				stats.Inserted++
				if verbose {
					logger.Debug("certificate inserted",
						"source", source.Name,
						"subject", cert.Parsed.Subject.CommonName,
					)
				}
			} else {
				// Race condition - another process inserted it
				stats.AlreadyExists++
			}
		}
	}

	return stats, nil
}

// fetchPEMBundle fetches a PEM bundle from a URL.
func fetchPEMBundle(ctx context.Context, client HTTPClient, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ParsePEMBundle parses a concatenated PEM bundle and returns certificate infos.
// Returns the parsed certificates and the count of parse failures.
func ParsePEMBundle(pemBundle []byte) ([]*certutil.CertInfo, int) {
	var certs []*certutil.CertInfo
	parseFailures := 0

	data := pemBundle
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			parseFailures++
			continue
		}

		certInfo := certutil.ParseX509Certificate(x509Cert)
		certs = append(certs, certInfo)
	}

	return certs, parseFailures
}
