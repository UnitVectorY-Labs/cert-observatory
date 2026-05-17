package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
)

// EligibleDomain represents a domain eligible for automated crawling.
type EligibleDomain struct {
	Domain string
}

// CrawlDomainsOptions contains options for querying eligible domains.
type CrawlDomainsOptions struct {
	// IgnoreErrors ignores backoff errors (no_retry_before)
	IgnoreErrors bool
	// IncludeNonPublic includes domains where popular_domain = false
	IncludeNonPublic bool
}

// BackoffPolicy defines the exponential backoff parameters.
type BackoffPolicy struct {
	BaseDelay  time.Duration
	Multiplier float64
	MaxDelay   time.Duration
	MaxBackoff time.Duration // Maximum total backoff (e.g., 1 month)
}

// DefaultBackoffPolicy returns the default backoff policy.
func DefaultBackoffPolicy() *BackoffPolicy {
	return &BackoffPolicy{
		BaseDelay:  1 * time.Hour,
		Multiplier: 2.0,
		MaxDelay:   7 * 24 * time.Hour,  // 7 days cap per retry
		MaxBackoff: 30 * 24 * time.Hour, // 1 month maximum
	}
}

// ComputeBackoff calculates the next retry time based on consecutive failures.
func (p *BackoffPolicy) ComputeBackoff(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return p.BaseDelay
	}

	// Calculate delay: baseDelay * (multiplier ^ (consecutiveFailures - 1))
	delay := p.BaseDelay
	for i := 1; i < consecutiveFailures; i++ {
		delay = time.Duration(float64(delay) * p.Multiplier)
		if delay > p.MaxDelay {
			delay = p.MaxDelay
			break
		}
	}

	// Cap at maximum backoff
	if delay > p.MaxBackoff {
		delay = p.MaxBackoff
	}

	return delay
}

// GetEligibleDomainsForCrawl returns domains that are due for automated re-crawling.
// effectiveAge is the threshold age (e.g., 23 hours for 1-day schedule).
func (r *Repository) GetEligibleDomainsForCrawl(ctx context.Context, effectiveAge time.Duration, limit int) ([]*EligibleDomain, error) {
	threshold := time.Now().Add(-effectiveAge)

	query := `
		SELECT domain
		FROM domains
		WHERE auto_crawl = true
		  AND port = 443
		  AND (no_retry_before IS NULL OR no_retry_before <= now())
		  AND (last_success_at IS NULL OR last_success_at <= $1)
		ORDER BY
			CASE
				WHEN last_success_at IS NULL AND last_failure_at IS NULL THEN 0
				ELSE 1
			END,
			GREATEST(
				COALESCE(last_success_at, '-infinity'::timestamptz),
				COALESCE(last_failure_at, '-infinity'::timestamptz)
			),
			domain
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("query eligible domains: %w", err)
	}
	defer rows.Close()

	var domains []*EligibleDomain
	for rows.Next() {
		d := &EligibleDomain{}
		if err := rows.Scan(&d.Domain); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate domains: %w", err)
	}

	return domains, nil
}

// RecordAutoCrawlSuccess records a successful automated crawl.
func (r *Repository) RecordAutoCrawlSuccess(ctx context.Context, domain string, chainInfo *certutil.ChainInfo, crawlTime time.Time) (*CrawlStats, error) {
	result := &CrawlResult{
		Domain:    domain,
		Port:      443,
		ChainInfo: chainInfo,
		CrawlTime: crawlTime,
		Mode:      CrawlModeAuto,
	}

	stats, err := r.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		return nil, err
	}

	// Also clear no_retry_before explicitly for auto mode
	_, err = r.db.ExecContext(ctx, `
		UPDATE domains SET no_retry_before = NULL WHERE domain = $1 AND port = 443
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("clear no_retry_before: %w", err)
	}

	return stats, nil
}

// RecordAutoCrawlFailure records a failed automated crawl with exponential backoff.
func (r *Repository) RecordAutoCrawlFailure(ctx context.Context, domain string, crawlTime time.Time, policy *BackoffPolicy) (time.Time, int, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Upsert domain
	_, _, err = r.upsertDomain(ctx, tx, domain, 443)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("upsert domain: %w", err)
	}

	// Get current consecutive failures and increment
	var currentFailures int
	err = tx.QueryRowContext(ctx, `
		SELECT consecutive_failures FROM domains WHERE domain = $1 AND port = 443
	`, domain).Scan(&currentFailures)
	if err != nil && err != sql.ErrNoRows {
		return time.Time{}, 0, fmt.Errorf("get consecutive failures: %w", err)
	}

	newFailures := currentFailures + 1
	backoffDuration := policy.ComputeBackoff(newFailures)
	noRetryBefore := crawlTime.Add(backoffDuration)

	// Update domain with failure info and backoff
	_, err = tx.ExecContext(ctx, `
		UPDATE domains SET
			last_failure_at = $2,
			consecutive_failures = $3,
			no_retry_before = $4
		WHERE domain = $1 AND port = 443
	`, domain, crawlTime, newFailures, noRetryBefore)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("update domain failure: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return time.Time{}, 0, fmt.Errorf("commit transaction: %w", err)
	}

	return noRetryBefore, newFailures, nil
}

// CountEligibleDomains returns the count of domains eligible for crawling.
func (r *Repository) CountEligibleDomains(ctx context.Context, effectiveAge time.Duration) (int, error) {
	threshold := time.Now().Add(-effectiveAge)

	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM domains
		WHERE auto_crawl = true
		  AND port = 443
		  AND (no_retry_before IS NULL OR no_retry_before <= now())
		  AND (last_success_at IS NULL OR last_success_at <= $1)
	`, threshold).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count eligible domains: %w", err)
	}

	return count, nil
}

// CountEligibleDomainsWithOptions returns the count of domains eligible for crawling with additional options.
func (r *Repository) CountEligibleDomainsWithOptions(ctx context.Context, effectiveAge time.Duration, opts *CrawlDomainsOptions) (int, error) {
	threshold := time.Now().Add(-effectiveAge)

	// Build the query dynamically based on options
	query := `SELECT COUNT(*) FROM domains WHERE auto_crawl = true AND port = 443`

	// Handle backoff logic
	if !opts.IgnoreErrors {
		query += ` AND (no_retry_before IS NULL OR no_retry_before <= now())`
	}

	// Handle popular_domain filter
	if !opts.IncludeNonPublic {
		query += ` AND popular_domain = true`
	}

	query += ` AND (last_success_at IS NULL OR last_success_at <= $1)`

	var count int
	err := r.db.QueryRowContext(ctx, query, threshold).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count eligible domains: %w", err)
	}

	return count, nil
}

// GetEligibleDomainsForCrawlWithOptions returns domains that are due for automated re-crawling with additional options.
func (r *Repository) GetEligibleDomainsForCrawlWithOptions(ctx context.Context, effectiveAge time.Duration, limit int, opts *CrawlDomainsOptions) ([]*EligibleDomain, error) {
	threshold := time.Now().Add(-effectiveAge)

	// Build the query dynamically based on options
	query := `SELECT domain FROM domains WHERE auto_crawl = true AND port = 443`

	// Handle backoff logic
	if !opts.IgnoreErrors {
		query += ` AND (no_retry_before IS NULL OR no_retry_before <= now())`
	}

	// Handle popular_domain filter
	if !opts.IncludeNonPublic {
		query += ` AND popular_domain = true`
	}

	query += ` AND (last_success_at IS NULL OR last_success_at <= $1)`
	query += ` ORDER BY
		CASE
			WHEN last_success_at IS NULL AND last_failure_at IS NULL THEN 0
			ELSE 1
		END,
		GREATEST(
			COALESCE(last_success_at, '-infinity'::timestamptz),
			COALESCE(last_failure_at, '-infinity'::timestamptz)
		),
		domain
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("query eligible domains: %w", err)
	}
	defer rows.Close()

	var domains []*EligibleDomain
	for rows.Next() {
		d := &EligibleDomain{}
		if err := rows.Scan(&d.Domain); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, d)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate domains: %w", err)
	}

	return domains, nil
}

// UpsertDomainFromToplist inserts or updates a domain from the toplist.
// Sets popular_domain = true and auto_crawl = true.
// Returns (isNew, wasUpdated, error).
func (r *Repository) UpsertDomainFromToplist(ctx context.Context, domain string) (bool, bool, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return false, false, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Check if domain exists
	var popularDomain, autoCrawl bool
	err = tx.QueryRowContext(ctx, `
		SELECT popular_domain, auto_crawl
		FROM domains
		WHERE domain = $1 AND port = 443
	`, domain).Scan(&popularDomain, &autoCrawl)

	if err == sql.ErrNoRows {
		// Insert new domain
		_, err = tx.ExecContext(ctx, `
			INSERT INTO domains (domain, port, first_seen_at, popular_domain, auto_crawl)
			VALUES ($1, 443, now(), true, true)
		`, domain)
		if err != nil {
			return false, false, fmt.Errorf("insert domain: %w", err)
		}

		if err := tx.Commit(); err != nil {
			return false, false, fmt.Errorf("commit: %w", err)
		}
		return true, false, nil
	}

	if err != nil {
		return false, false, fmt.Errorf("query domain: %w", err)
	}

	// Domain exists, check if update needed
	needsUpdate := !popularDomain || !autoCrawl
	if needsUpdate {
		_, err = tx.ExecContext(ctx, `
			UPDATE domains SET popular_domain = true, auto_crawl = true WHERE domain = $1 AND port = 443
		`, domain)
		if err != nil {
			return false, false, fmt.Errorf("update domain: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, false, fmt.Errorf("commit: %w", err)
	}

	return false, needsUpdate, nil
}

// BulkUpsertDomainsFromToplist efficiently upserts multiple domains from the toplist.
// Returns (inserted, updated, error).
func (r *Repository) BulkUpsertDomainsFromToplist(ctx context.Context, domains []string) (int, int, error) {
	if len(domains) == 0 {
		return 0, 0, nil
	}

	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	inserted := 0
	updated := 0

	for _, domain := range domains {
		// Check if exists
		var popularDomain, autoCrawl bool
		err = tx.QueryRowContext(ctx, `
			SELECT popular_domain, auto_crawl
			FROM domains
			WHERE domain = $1 AND port = 443
		`, domain).Scan(&popularDomain, &autoCrawl)

		if err == sql.ErrNoRows {
			// Insert new domain
			_, err = tx.ExecContext(ctx, `
				INSERT INTO domains (domain, port, first_seen_at, popular_domain, auto_crawl)
				VALUES ($1, 443, now(), true, true)
			`, domain)
			if err != nil {
				return inserted, updated, fmt.Errorf("insert domain %s: %w", domain, err)
			}
			inserted++
			continue
		}

		if err != nil {
			return inserted, updated, fmt.Errorf("query domain %s: %w", domain, err)
		}

		// Domain exists, check if update needed
		needsUpdate := !popularDomain || !autoCrawl
		if needsUpdate {
			_, err = tx.ExecContext(ctx, `
				UPDATE domains SET popular_domain = true, auto_crawl = true WHERE domain = $1 AND port = 443
			`, domain)
			if err != nil {
				return inserted, updated, fmt.Errorf("update domain %s: %w", domain, err)
			}
			updated++
		}
	}

	if err := tx.Commit(); err != nil {
		return inserted, updated, fmt.Errorf("commit: %w", err)
	}

	return inserted, updated, nil
}

// InsertCertificate inserts a certificate if it doesn't exist.
// Returns true if inserted, false if already existed.
// This can be used for any certificate type (root, intermediate, or end-entity).
func (r *Repository) InsertCertificate(ctx context.Context, certInfo *certutil.CertInfo) (bool, error) {
	// Try to insert, do nothing on conflict (upsert by hash)
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (cert_hash, der, subject, issuer, not_before, not_after, ski, aki)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (cert_hash) DO NOTHING
	`, certInfo.CertHash, certInfo.DER, certInfo.Subject, certInfo.Issuer, certInfo.NotBefore, certInfo.NotAfter, nullableBytes(certInfo.SKI), nullableBytes(certInfo.AKI))
	if err != nil {
		return false, fmt.Errorf("insert certificate: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("get rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// CheckCertificatesExist checks which certificate hashes already exist.
// Returns a set of hashes that exist.
func (r *Repository) CheckCertificatesExist(ctx context.Context, hashes [][]byte) (map[string]bool, error) {
	existing := make(map[string]bool)

	if len(hashes) == 0 {
		return existing, nil
	}

	// Check in batches of 100 using IN clause
	batchSize := 100
	for i := 0; i < len(hashes); i += batchSize {
		end := i + batchSize
		if end > len(hashes) {
			end = len(hashes)
		}

		batch := hashes[i:end]

		// Build query with placeholders for IN clause
		placeholders := make([]string, len(batch))
		args := make([]interface{}, len(batch))
		for j, hash := range batch {
			placeholders[j] = fmt.Sprintf("$%d", j+1)
			args[j] = hash
		}

		query := `SELECT cert_hash FROM certificates WHERE cert_hash IN (` + joinStrings(placeholders, ",") + `)`

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("check certificates exist: %w", err)
		}

		for rows.Next() {
			var certHash []byte
			if err := rows.Scan(&certHash); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan cert_hash: %w", err)
			}
			existing[string(certHash)] = true
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate certificates: %w", err)
		}
	}

	return existing, nil
}

// joinStrings joins strings with a separator (simple helper to avoid importing strings package).
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
