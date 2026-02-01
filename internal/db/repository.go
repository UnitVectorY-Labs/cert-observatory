package db

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
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
	ChainInfo *certutil.ChainInfo
	CrawlTime time.Time
	Mode      CrawlMode
}

// CrawlStats contains information about what was created/updated during a crawl.
type CrawlStats struct {
	DomainInserted       bool
	DomainID             int64
	CertsInserted        int
	ChainInserted        bool
	ChainStateUpdated    bool
	ChainStateNewInterval bool
	CurrentChainChanged  bool
	PreviousChainHash    []byte
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
	domainID, inserted, previousChainHash, err := r.upsertDomain(ctx, tx, result.Domain)
	if err != nil {
		return nil, fmt.Errorf("upsert domain: %w", err)
	}
	stats.DomainInserted = inserted
	stats.DomainID = domainID
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
	chainChanged, err := r.updateDomainSuccess(ctx, tx, domainID, result.ChainInfo.ChainHash, result.CrawlTime, result.Mode)
	if err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	stats.CurrentChainChanged = chainChanged

	// Step 5: Update domain chain state intervals
	newInterval, err := r.updateDomainChainState(ctx, tx, domainID, result.ChainInfo.ChainHash, result.CrawlTime, result.Mode)
	if err != nil {
		return nil, fmt.Errorf("update domain chain state: %w", err)
	}
	stats.ChainStateUpdated = true
	stats.ChainStateNewInterval = newInterval

	// Step 6: Populate cert_signers relationships
	if err := r.populateCertSigners(ctx, tx, result.ChainInfo.Certs); err != nil {
		return nil, fmt.Errorf("populate cert signers: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}

	return stats, nil
}

// upsertDomain ensures a domain row exists and returns its ID, whether it was inserted, and its previous chain hash.
func (r *Repository) upsertDomain(ctx context.Context, tx *sql.Tx, domain string) (int64, bool, []byte, error) {
	// First, try to get existing domain
	var domainID int64
	var previousChainHash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT domain_id, current_chain_hash
		FROM domains
		WHERE domain = $1
	`, domain).Scan(&domainID, &previousChainHash)

	if err == nil {
		// Domain exists
		return domainID, false, previousChainHash, nil
	}

	if err != sql.ErrNoRows {
		return 0, false, nil, fmt.Errorf("query domain: %w", err)
	}

	// Insert new domain
	err = tx.QueryRowContext(ctx, `
		INSERT INTO domains (domain, first_seen_at)
		VALUES ($1, now())
		RETURNING domain_id
	`, domain).Scan(&domainID)

	if err != nil {
		return 0, false, nil, fmt.Errorf("insert domain: %w", err)
	}

	return domainID, true, nil, nil
}

// insertCertificates inserts certificates that don't already exist.
func (r *Repository) insertCertificates(ctx context.Context, tx *sql.Tx, certs []*certutil.CertInfo) (int, error) {
	inserted := 0

	for _, cert := range certs {
		// Check if certificate already exists
		var exists bool
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(SELECT 1 FROM certificates WHERE cert_hash = $1)
		`, cert.CertHash).Scan(&exists)
		if err != nil {
			return inserted, fmt.Errorf("check certificate exists: %w", err)
		}

		if exists {
			continue
		}

		// Insert certificate
		_, err = tx.ExecContext(ctx, `
			INSERT INTO certificates (cert_hash, pem, not_before, not_after, ski, aki)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, cert.CertHash, cert.PEM, cert.NotBefore, cert.NotAfter, nullableBytes(cert.SKI), nullableBytes(cert.AKI))
		if err != nil {
			return inserted, fmt.Errorf("insert certificate: %w", err)
		}
		inserted++
	}

	return inserted, nil
}

// insertChain inserts a chain if it doesn't already exist.
func (r *Repository) insertChain(ctx context.Context, tx *sql.Tx, chainInfo *certutil.ChainInfo) (bool, error) {
	// Check if chain already exists
	var exists bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM chains WHERE chain_hash = $1)
	`, chainInfo.ChainHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check chain exists: %w", err)
	}

	if exists {
		return false, nil
	}

	// Insert chain
	_, err = tx.ExecContext(ctx, `
		INSERT INTO chains (chain_hash, leaf_cert_hash, depth)
		VALUES ($1, $2, $3)
	`, chainInfo.ChainHash, chainInfo.LeafCertHash, chainInfo.Depth)
	if err != nil {
		return false, fmt.Errorf("insert chain: %w", err)
	}

	// Insert chain_certs
	for i, cert := range chainInfo.Certs {
		position := i + 1 // 1-based position
		_, err = tx.ExecContext(ctx, `
			INSERT INTO chain_certs (chain_hash, position, cert_hash)
			VALUES ($1, $2, $3)
		`, chainInfo.ChainHash, position, cert.CertHash)
		if err != nil {
			return false, fmt.Errorf("insert chain_cert at position %d: %w", position, err)
		}
	}

	return true, nil
}

// updateDomainSuccess updates domain timestamps for a successful crawl.
func (r *Repository) updateDomainSuccess(ctx context.Context, tx *sql.Tx, domainID int64, chainHash []byte, crawlTime time.Time, mode CrawlMode) (bool, error) {
	var currentChainHash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT current_chain_hash FROM domains WHERE domain_id = $1
	`, domainID).Scan(&currentChainHash)
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
			WHERE domain_id = $1
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
			WHERE domain_id = $1
		`
	default:
		query = `
			UPDATE domains SET
				current_chain_hash = $2,
				current_chain_updated_at = $3,
				last_success_at = $3,
				consecutive_failures = 0
			WHERE domain_id = $1
		`
	}

	_, err = tx.ExecContext(ctx, query, domainID, chainHash, crawlTime)
	if err != nil {
		return false, fmt.Errorf("update domain: %w", err)
	}

	return chainChanged, nil
}

// updateDomainChainState updates or creates domain_chain_states intervals.
func (r *Repository) updateDomainChainState(ctx context.Context, tx *sql.Tx, domainID int64, chainHash []byte, crawlTime time.Time, mode CrawlMode) (bool, error) {
	// Find current interval (ended_at IS NULL)
	var stateID int64
	var currentChainHash []byte
	err := tx.QueryRowContext(ctx, `
		SELECT state_id, chain_hash
		FROM domain_chain_states
		WHERE domain_id = $1 AND ended_at IS NULL
	`, domainID).Scan(&stateID, &currentChainHash)

	if err == sql.ErrNoRows {
		// No current interval, insert new one
		_, err = tx.ExecContext(ctx, `
			INSERT INTO domain_chain_states (domain_id, chain_hash, first_seen_at, last_seen_at, seen_count, last_mode)
			VALUES ($1, $2, $3, $3, 1, $4)
		`, domainID, chainHash, crawlTime, mode)
		if err != nil {
			return true, fmt.Errorf("insert chain state: %w", err)
		}
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("query current chain state: %w", err)
	}

	// Current interval exists
	if bytes.Equal(currentChainHash, chainHash) {
		// Same chain, update interval
		_, err = tx.ExecContext(ctx, `
			UPDATE domain_chain_states SET
				last_seen_at = $2,
				seen_count = seen_count + 1,
				last_mode = $3
			WHERE state_id = $1
		`, stateID, crawlTime, mode)
		if err != nil {
			return false, fmt.Errorf("update chain state: %w", err)
		}
		return false, nil
	}

	// Different chain, close old interval and open new one
	_, err = tx.ExecContext(ctx, `
		UPDATE domain_chain_states SET ended_at = $2 WHERE state_id = $1
	`, stateID, crawlTime)
	if err != nil {
		return true, fmt.Errorf("close previous chain state: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO domain_chain_states (domain_id, chain_hash, first_seen_at, last_seen_at, seen_count, last_mode)
		VALUES ($1, $2, $3, $3, 1, $4)
	`, domainID, chainHash, crawlTime, mode)
	if err != nil {
		return true, fmt.Errorf("insert new chain state: %w", err)
	}

	return true, nil
}

// populateCertSigners populates cert_signers relationships for newly inserted certificates.
func (r *Repository) populateCertSigners(ctx context.Context, tx *sql.Tx, certs []*certutil.CertInfo) error {
	for _, cert := range certs {
		if cert.AKI == nil {
			continue
		}

		// Find potential issuers where issuer.ski = subject.aki
		rows, err := tx.QueryContext(ctx, `
			SELECT cert_hash FROM certificates WHERE ski = $1
		`, cert.AKI)
		if err != nil {
			return fmt.Errorf("query potential issuers: %w", err)
		}

		var issuerHashes [][]byte
		for rows.Next() {
			var issuerHash []byte
			if err := rows.Scan(&issuerHash); err != nil {
				rows.Close()
				return fmt.Errorf("scan issuer hash: %w", err)
			}
			issuerHashes = append(issuerHashes, issuerHash)
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate issuers: %w", err)
		}

		// Insert cert_signers relationships
		for _, issuerHash := range issuerHashes {
			// Skip self-referential entries
			if bytes.Equal(cert.CertHash, issuerHash) {
				continue
			}

			_, err = tx.ExecContext(ctx, `
				INSERT INTO cert_signers (subject_cert_hash, issuer_cert_hash, is_verified)
				VALUES ($1, $2, false)
				ON CONFLICT (subject_cert_hash, issuer_cert_hash) DO NOTHING
			`, cert.CertHash, issuerHash)
			if err != nil {
				return fmt.Errorf("insert cert_signer: %w", err)
			}
		}
	}

	return nil
}

// RecordFailedCrawl records a failed crawl attempt.
func (r *Repository) RecordFailedCrawl(ctx context.Context, domain string, crawlTime time.Time, mode CrawlMode) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Upsert domain
	domainID, _, _, err := r.upsertDomain(ctx, tx, domain)
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
			WHERE domain_id = $1
		`
	case CrawlModeForced:
		query = `
			UPDATE domains SET
				last_failure_at = $2,
				consecutive_failures = consecutive_failures + 1,
				last_forced_attempt_at = $2
			WHERE domain_id = $1
		`
	default:
		query = `
			UPDATE domains SET
				last_failure_at = $2,
				consecutive_failures = consecutive_failures + 1
			WHERE domain_id = $1
		`
	}

	_, err = tx.ExecContext(ctx, query, domainID, crawlTime)
	if err != nil {
		return fmt.Errorf("update domain failure: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// nullableBytes returns nil if the slice is empty, otherwise returns the slice.
func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
