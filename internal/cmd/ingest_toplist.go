package cmd

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/domain"
)

const (
	// CloudflareRadarToplistURL is the URL for Cloudflare Radar Top 10k domains.
	CloudflareRadarToplistURL = "https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_10000"
)

// IngestToplistConfig contains configuration for the ingest-toplist command.
type IngestToplistConfig struct {
	// CloudflareToken is the API token for Cloudflare Radar
	CloudflareToken string
	// Verbose enables debug logging
	Verbose bool
	// DBConfig is the database configuration
	DBConfig *db.Config
	// Stderr is the writer for logging
	Stderr io.Writer
	// HTTPClient is the HTTP client to use (for testing)
	HTTPClient HTTPClient
	// ToplistURL is the URL to fetch (for testing)
	ToplistURL string
}

// HTTPClient interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// DefaultIngestToplistConfig returns default configuration.
func DefaultIngestToplistConfig() *IngestToplistConfig {
	return &IngestToplistConfig{
		Stderr:     os.Stderr,
		ToplistURL: CloudflareRadarToplistURL,
	}
}

// IngestToplistStats contains statistics from the ingest-toplist command.
type IngestToplistStats struct {
	Fetched  int
	Accepted int
	Inserted int
	Updated  int
	Rejected int
}

// IngestToplist executes the ingest-toplist command.
func IngestToplist(ctx context.Context, cfg *IngestToplistConfig) error {
	// Set up logging
	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}

	logOpts := &slog.HandlerOptions{Level: logLevel}
	logger := slog.New(slog.NewTextHandler(cfg.Stderr, logOpts))

	logger.Info("starting ingest-toplist job")

	if cfg.CloudflareToken == "" {
		return fmt.Errorf("cloudflare API token is required")
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

	// Fetch domains from Cloudflare Radar
	logger.Info("fetching domains from Cloudflare Radar")

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}

	url := cfg.ToplistURL
	if url == "" {
		url = CloudflareRadarToplistURL
	}

	rawDomains, err := fetchCloudflareToplist(ctx, client, url, cfg.CloudflareToken)
	if err != nil {
		logger.Error("failed to fetch toplist", "error", err)
		return fmt.Errorf("fetch toplist: %w", err)
	}

	logger.Info("fetched domains", "count", len(rawDomains))

	// Normalize and validate domains
	var validDomains []string
	rejected := 0

	for _, raw := range rawDomains {
		normalized, err := domain.NormalizeAndValidate(raw)
		if err != nil {
			logger.Debug("rejected domain", "domain", raw, "reason", err.Error())
			rejected++
			continue
		}
		validDomains = append(validDomains, normalized)
	}

	logger.Info("domain validation complete",
		"accepted", len(validDomains),
		"rejected", rejected,
	)

	if len(validDomains) == 0 {
		logger.Warn("no valid domains to ingest")
		return nil
	}

	// Bulk upsert domains in sequential batches to avoid huge single transactions.
	batchSize := 100
	totalInserted := 0
	totalUpdated := 0

	for i := 0; i < len(validDomains); i += batchSize {
		end := min(i+batchSize, len(validDomains))
		batch := validDomains[i:end]
		batchNum := i/batchSize + 1

		logger.Info("upserting domain batch", "batch", batchNum, "size", len(batch))

		inserted, updated, err := repo.BulkUpsertDomainsFromToplist(ctx, batch)
		if err != nil {
			logger.Error("failed to upsert domains batch", "batch", batchNum, "error", err)
			return fmt.Errorf("upsert domains batch %d: %w", batchNum, err)
		}

		totalInserted += inserted
		totalUpdated += updated

		logger.Info("completed batch upsert", "batch", batchNum, "inserted", inserted, "updated", updated)
	}

	logger.Info("ingest-toplist completed",
		"fetched", len(rawDomains),
		"accepted", len(validDomains),
		"inserted", totalInserted,
		"updated", totalUpdated,
		"rejected", rejected,
	)

	return nil
}

// fetchCloudflareToplist fetches the domain list from Cloudflare Radar API.
func fetchCloudflareToplist(ctx context.Context, client HTTPClient, url, token string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return parseToplistResponse(body)
}

// parseToplistResponse parses the CSV-like response from Cloudflare Radar.
func parseToplistResponse(data []byte) ([]string, error) {
	var domains []string
	scanner := bufio.NewScanner(bytes.NewReader(data))

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip the header line "domain"
		if lineNum == 1 && line == "domain" {
			continue
		}

		// Skip empty lines
		if line == "" {
			continue
		}

		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan response: %w", err)
	}

	return domains, nil
}
