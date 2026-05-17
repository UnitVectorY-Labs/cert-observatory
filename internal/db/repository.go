package db

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/lib/pq"
)

// CrawlMode represents how a crawl was triggered.
type CrawlMode string

const (
	CrawlModeStandard CrawlMode = "standard"
	CrawlModeForced   CrawlMode = "forced"
	CrawlModeAuto     CrawlMode = "auto"
)

// CrawlResult represents the result to be stored from a crawl operation.
type CrawlResult struct {
	Domain    string
	Port      int
	ChainInfo *certutil.ChainInfo
	CrawlTime time.Time
	Mode      CrawlMode
}

// CrawlStats contains information about what was created/updated during a crawl.
type CrawlStats struct {
	DomainInserted      bool
	CertsInserted       int
	ChainInserted       bool
	DomainChainUpdated  bool
	DomainChainInserted bool
	CurrentChainChanged bool
	PreviousChainHash   []byte
}

// Repository provides database operations for certificate crawling.
type Repository struct {
	db *DB
}

// NewRepository creates a new Repository.
func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// RecordSuccessfulCrawl records a successful crawl result in a single transaction.
func (r *Repository) RecordSuccessfulCrawl(ctx context.Context, result *CrawlResult) (*CrawlStats, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stats := &CrawlStats{}

	// Step 1: Upsert domain
	port := normalizePort(result.Port)

	inserted, previousChainHash, err := r.upsertDomain(ctx, tx, result.Domain, port)
	if err != nil {
		return nil, fmt.Errorf("upsert domain: %w", err)
	}
	stats.DomainInserted = inserted
	stats.PreviousChainHash = previousChainHash

	// Step 2: Insert certificates
	certsInserted, err := r.insertCertificates(ctx, tx, result.ChainInfo.Certs)
	if err != nil {
		return nil, fmt.Errorf("insert certificates: %w", err)
	}
	stats.CertsInserted = certsInserted

	// Step 3: Insert chain
	chainInserted, err := r.insertChain(ctx, tx, result.ChainInfo)
	if err != nil {
		return nil, fmt.Errorf("insert chain: %w", err)
	}
	stats.ChainInserted = chainInserted

	// Step 4: Update domain current chain and timestamps
	chainChanged, err := r.updateDomainSuccess(ctx, tx, result.Domain, port, result.ChainInfo.ChainHash, result.CrawlTime, result.Mode)
	if err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	stats.CurrentChainChanged = chainChanged

	// Step 5: Upsert domain_chains association
	dcInserted, err := r.upsertDomainChain(ctx, tx, result.Domain, port, result.ChainInfo.ChainHash, result.CrawlTime, result.Mode)
	if err != nil {
		return nil, fmt.Errorf("upsert domain chain: %w", err)
	}
	stats.DomainChainInserted = dcInserted
	stats.DomainChainUpdated = !dcInserted

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return stats, nil
}

// upsertDomain ensures a domain row exists and returns whether it was inserted and its previous chain hash.
func (r *Repository) upsertDomain(ctx context.Context, tx *sql.Tx, domain string, port int) (bool, []byte, error) {
	// First, try to get existing domain
	var previousChainHash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT current_chain_hash
		FROM domains
		WHERE domain = $1 AND port = $2
	`, domain, port).Scan(&previousChainHash)

	if err == nil {
		// Domain exists
		return false, previousChainHash, nil
	}

	if err != sql.ErrNoRows {
		return false, nil, fmt.Errorf("query domain: %w", err)
	}

	// Insert new domain
	_, err = tx.ExecContext(ctx, `
		INSERT INTO domains (domain, port, first_seen_at)
		VALUES ($1, $2, now())
	`, domain, port)

	if err != nil {
		return false, nil, fmt.Errorf("insert domain: %w", err)
	}

	return true, nil, nil
}

// insertCertificates inserts certificates that don't already exist.
func (r *Repository) insertCertificates(ctx context.Context, tx *sql.Tx, certs []*certutil.CertInfo) (int, error) {
	inserted := 0

	for _, cert := range certs {
		// Try to insert, do nothing on conflict (upsert by hash)
		result, err := tx.ExecContext(ctx, `
			INSERT INTO certificates (cert_hash, der, subject, issuer, not_before, not_after, ski, aki)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (cert_hash) DO NOTHING
		`, cert.CertHash, cert.DER, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter, nullableBytes(cert.SKI), nullableBytes(cert.AKI))
		if err != nil {
			return inserted, fmt.Errorf("insert certificate: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return inserted, fmt.Errorf("get rows affected: %w", err)
		}
		if rowsAffected > 0 {
			inserted++
		}
	}

	return inserted, nil
}

// insertChain inserts a chain if it doesn't already exist.
func (r *Repository) insertChain(ctx context.Context, tx *sql.Tx, chainInfo *certutil.ChainInfo) (bool, error) {
	// Try to insert, do nothing on conflict (upsert by hash)
	result, err := tx.ExecContext(ctx, `
		INSERT INTO chains (chain_hash, cert_hashes)
		VALUES ($1, $2)
		ON CONFLICT (chain_hash) DO NOTHING
	`, chainInfo.ChainHash, pq.Array(chainInfo.CertHashes))
	if err != nil {
		return false, fmt.Errorf("insert chain: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// updateDomainSuccess updates domain timestamps for a successful crawl.
func (r *Repository) updateDomainSuccess(ctx context.Context, tx *sql.Tx, domain string, port int, chainHash []byte, crawlTime time.Time, mode CrawlMode) (bool, error) {
	var currentChainHash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT current_chain_hash FROM domains WHERE domain = $1 AND port = $2
	`, domain, port).Scan(&currentChainHash)
	if err != nil && err != sql.ErrNoRows {
		return false, fmt.Errorf("get current chain: %w", err)
	}

	chainChanged := !bytes.Equal(currentChainHash, chainHash)

	// Build update based on mode
	var query string
	switch mode {
	case CrawlModeStandard:
		query = `
			UPDATE domains SET
				current_chain_hash = $2,
				current_chain_updated_at = $3,
				last_success_at = $3,
				last_standard_attempt_at = $3,
				last_standard_success_at = $3,
				consecutive_failures = 0
			WHERE domain = $1 AND port = $4
		`
	case CrawlModeForced:
		query = `
			UPDATE domains SET
				current_chain_hash = $2,
				current_chain_updated_at = $3,
				last_success_at = $3,
				last_forced_attempt_at = $3,
				last_forced_success_at = $3,
				consecutive_failures = 0
			WHERE domain = $1 AND port = $4
		`
	case CrawlModeAuto:
		// Auto mode also updates standard timestamps so web interface
		// recognizes recently crawled domains and doesn't force re-crawl
		query = `
			UPDATE domains SET
				current_chain_hash = $2,
				current_chain_updated_at = $3,
				last_success_at = $3,
				last_standard_attempt_at = $3,
				last_standard_success_at = $3,
				consecutive_failures = 0,
				no_retry_before = NULL
			WHERE domain = $1 AND port = $4
		`
	default:
		query = `
			UPDATE domains SET
				current_chain_hash = $2,
				current_chain_updated_at = $3,
				last_success_at = $3,
				consecutive_failures = 0
			WHERE domain = $1 AND port = $4
		`
	}

	_, err = tx.ExecContext(ctx, query, domain, chainHash, crawlTime, port)
	if err != nil {
		return false, fmt.Errorf("update domain: %w", err)
	}

	return chainChanged, nil
}

// upsertDomainChain upserts the domain_chains association.
// Returns true if a new row was inserted, false if an existing row was updated.
func (r *Repository) upsertDomainChain(ctx context.Context, tx *sql.Tx, domain string, port int, chainHash []byte, crawlTime time.Time, mode CrawlMode) (bool, error) {
	// Try to update existing row first
	result, err := tx.ExecContext(ctx, `
		UPDATE domain_chains SET
			last_seen_at = $3,
			seen_count = seen_count + 1,
			last_mode = $4
		WHERE domain = $1 AND chain_hash = $2
			AND port = $5
	`, domain, chainHash, crawlTime, mode, port)
	if err != nil {
		return false, fmt.Errorf("update domain_chain: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		// Existing row was updated
		return false, nil
	}

	// Insert new row
	_, err = tx.ExecContext(ctx, `
		INSERT INTO domain_chains (domain, port, chain_hash, first_seen_at, last_seen_at, seen_count, last_mode)
		VALUES ($1, $2, $3, $4, $4, 1, $5)
	`, domain, port, chainHash, crawlTime, mode)
	if err != nil {
		return true, fmt.Errorf("insert domain_chain: %w", err)
	}

	return true, nil
}

// RecordFailedCrawl records a failed crawl attempt.
func (r *Repository) RecordFailedCrawl(ctx context.Context, domain string, crawlTime time.Time, mode CrawlMode) error {
	return r.RecordFailedCrawlForPort(ctx, domain, 443, crawlTime, mode)
}

// RecordFailedCrawlForPort records a failed crawl attempt for a domain and port.
func (r *Repository) RecordFailedCrawlForPort(ctx context.Context, domain string, port int, crawlTime time.Time, mode CrawlMode) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Upsert domain
	_, _, err = r.upsertDomain(ctx, tx, domain, normalizePort(port))
	if err != nil {
		return fmt.Errorf("upsert domain: %w", err)
	}

	// Update failure fields
	var query string
	switch mode {
	case CrawlModeStandard:
		query = `
			UPDATE domains SET
				last_failure_at = $2,
				consecutive_failures = consecutive_failures + 1,
				last_standard_attempt_at = $2
			WHERE domain = $1 AND port = $3
		`
	case CrawlModeForced:
		query = `
			UPDATE domains SET
				last_failure_at = $2,
				consecutive_failures = consecutive_failures + 1,
				last_forced_attempt_at = $2
			WHERE domain = $1 AND port = $3
		`
	default:
		query = `
			UPDATE domains SET
				last_failure_at = $2,
				consecutive_failures = consecutive_failures + 1
			WHERE domain = $1 AND port = $3
		`
	}

	_, err = tx.ExecContext(ctx, query, domain, crawlTime, normalizePort(port))
	if err != nil {
		return fmt.Errorf("update domain failure: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func normalizePort(port int) int {
	if port == 0 {
		return 443
	}
	return port
}

// nullableBytes returns nil if the slice is empty, otherwise returns the slice.
func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
