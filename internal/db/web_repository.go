package db

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/web"
	"github.com/lib/pq"
)

// WebRepository provides database operations for the web interface.
type WebRepository struct {
	db   *DB
	repo *Repository
}

// NewWebRepository creates a new WebRepository.
func NewWebRepository(db *DB) *WebRepository {
	return &WebRepository{
		db:   db,
		repo: NewRepository(db),
	}
}

// GetDomainWithChain retrieves a domain and its current chain with certificates.
func (r *WebRepository) GetDomainWithChain(ctx context.Context, domainName string) (*web.DomainResult, error) {
	return r.GetDomainWithChainForPort(ctx, domainName, 443)
}

// GetDomainWithChainForPort retrieves a domain target and its current chain with certificates.
func (r *WebRepository) GetDomainWithChainForPort(ctx context.Context, domainName string, port int) (*web.DomainResult, error) {
	result := &web.DomainResult{
		Domain: domainName,
		Port:   port,
	}

	// Get domain info
	var chainHash []byte
	var updatedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT current_chain_hash, current_chain_updated_at
		FROM domains
		WHERE domain = $1 AND port = $2
	`, domainName, port).Scan(&chainHash, &updatedAt)

	if err == sql.ErrNoRows {
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query domain: %w", err)
	}

	if chainHash == nil {
		return result, nil
	}

	if updatedAt.Valid {
		result.UpdatedAt = updatedAt.Time
	}

	// Get chain cert_hashes array
	var certHashes [][]byte
	err = r.db.QueryRowContext(ctx, `
		SELECT cert_hashes
		FROM chains
		WHERE chain_hash = $1
	`, chainHash).Scan(pq.Array(&certHashes))
	if err != nil {
		return nil, fmt.Errorf("query chain: %w", err)
	}

	// Get certificates in the chain order
	for i, certHash := range certHashes {
		cert := &web.CertificateResult{
			CertHash: certHash,
			Position: i + 1, // 1-based position
		}

		var der []byte
		var ski, aki []byte
		var notBefore, notAfter sql.NullTime

		err := r.db.QueryRowContext(ctx, `
			SELECT der, not_before, not_after, ski, aki
			FROM certificates
			WHERE cert_hash = $1
		`, certHash).Scan(&der, &notBefore, &notAfter, &ski, &aki)
		if err != nil {
			return nil, fmt.Errorf("query cert %d: %w", i, err)
		}

		// Convert DER to PEM on demand
		cert.PEM = certutil.DERToPEM(der)

		if notBefore.Valid {
			cert.NotBefore = notBefore.Time
		}
		if notAfter.Valid {
			cert.NotAfter = notAfter.Time
		}
		cert.SKI = ski
		cert.AKI = aki

		// Parse the certificate from DER
		cert.Parsed = parseCertificateDER(der)

		result.Chain = append(result.Chain, cert)
	}

	result.HasChain = len(result.Chain) > 0
	return result, nil
}

// GetCertificateByHash retrieves a certificate by its hash.
func (r *WebRepository) GetCertificateByHash(ctx context.Context, hash []byte) (*web.CertificateResult, error) {
	cert := &web.CertificateResult{
		CertHash: hash,
	}

	var der []byte
	var ski, aki []byte
	var notBefore, notAfter sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT der, not_before, not_after, ski, aki
		FROM certificates
		WHERE cert_hash = $1
	`, hash).Scan(&der, &notBefore, &notAfter, &ski, &aki)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query certificate: %w", err)
	}

	// Convert DER to PEM on demand
	cert.PEM = certutil.DERToPEM(der)

	if notBefore.Valid {
		cert.NotBefore = notBefore.Time
	}
	if notAfter.Valid {
		cert.NotAfter = notAfter.Time
	}
	cert.SKI = ski
	cert.AKI = aki

	// Parse the certificate from DER
	cert.Parsed = parseCertificateDER(der)

	return cert, nil
}

// CanStandardRefresh checks if a standard refresh is allowed for the domain.
func (r *WebRepository) CanStandardRefresh(ctx context.Context, domainName string, window time.Duration) (bool, time.Duration, error) {
	return r.CanStandardRefreshForPort(ctx, domainName, 443, window)
}

// CanStandardRefreshForPort checks if a standard refresh is allowed for the domain target.
func (r *WebRepository) CanStandardRefreshForPort(ctx context.Context, domainName string, port int, window time.Duration) (bool, time.Duration, error) {
	var lastAttempt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT last_standard_attempt_at
		FROM domains
		WHERE domain = $1 AND port = $2
	`, domainName, port).Scan(&lastAttempt)

	if err == sql.ErrNoRows {
		// Domain doesn't exist, allow refresh
		return true, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("query domain: %w", err)
	}

	if !lastAttempt.Valid {
		// No previous attempt, allow refresh
		return true, 0, nil
	}

	elapsed := time.Since(lastAttempt.Time)
	if elapsed >= window {
		return true, 0, nil
	}

	return false, window - elapsed, nil
}

// CanForcedRefresh checks if a forced refresh is allowed for the domain.
func (r *WebRepository) CanForcedRefresh(ctx context.Context, domainName string, window time.Duration) (bool, time.Duration, error) {
	return r.CanForcedRefreshForPort(ctx, domainName, 443, window)
}

// CanForcedRefreshForPort checks if a forced refresh is allowed for the domain target.
func (r *WebRepository) CanForcedRefreshForPort(ctx context.Context, domainName string, port int, window time.Duration) (bool, time.Duration, error) {
	var lastAttempt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT last_forced_attempt_at
		FROM domains
		WHERE domain = $1 AND port = $2
	`, domainName, port).Scan(&lastAttempt)

	if err == sql.ErrNoRows {
		// Domain doesn't exist, allow refresh
		return true, 0, nil
	}
	if err != nil {
		return false, 0, fmt.Errorf("query domain: %w", err)
	}

	if !lastAttempt.Valid {
		// No previous forced attempt, allow refresh
		return true, 0, nil
	}

	elapsed := time.Since(lastAttempt.Time)
	if elapsed >= window {
		return true, 0, nil
	}

	return false, window - elapsed, nil
}

// AcquireLock tries to acquire a crawl lock for the domain using PostgreSQL advisory locks.
// This is a no-op since we've removed the domain_locks table and rely on idempotent upserts.
func (r *WebRepository) AcquireLock(ctx context.Context, domainName string, lockID string, ttl time.Duration) (bool, error) {
	return r.AcquireLockForPort(ctx, domainName, 443, lockID, ttl)
}

// AcquireLockForPort tries to acquire a crawl lock for the domain target.
func (r *WebRepository) AcquireLockForPort(ctx context.Context, domainName string, port int, lockID string, ttl time.Duration) (bool, error) {
	// With the simplified schema, we rely on idempotent upserts instead of explicit locks.
	// All database writes (certificate inserts, chain inserts, domain updates, domain_chains upserts)
	// are idempotent and use ON CONFLICT clauses, so concurrent crawls are safe.
	// Return true to indicate the "lock" is always acquired.
	return true, nil
}

// ReleaseLock releases a crawl lock for the domain.
// This is a no-op since we've removed the domain_locks table.
func (r *WebRepository) ReleaseLock(ctx context.Context, domainName string, lockID string) error {
	return r.ReleaseLockForPort(ctx, domainName, 443, lockID)
}

// ReleaseLockForPort releases a crawl lock for the domain target.
func (r *WebRepository) ReleaseLockForPort(ctx context.Context, domainName string, port int, lockID string) error {
	// No-op: locks are no longer used
	return nil
}

// RecordCrawlResult records the result of a crawl operation.
func (r *WebRepository) RecordCrawlResult(ctx context.Context, input *web.CrawlResultInput) error {
	if !input.Success {
		// Record failed crawl
		mode := CrawlModeStandard
		if input.Forced {
			mode = CrawlModeForced
		}
		return r.repo.RecordFailedCrawlForPort(ctx, input.Domain, input.Port, time.Now(), mode)
	}

	// Convert web types to internal types
	certs := make([]*certutil.CertInfo, len(input.Chain))
	certHashes := make([][]byte, len(input.Chain))
	for i, cert := range input.Chain {
		certs[i] = &certutil.CertInfo{
			CertHash:  cert.CertHash,
			DER:       cert.DER,
			Subject:   cert.Subject,
			Issuer:    cert.Issuer,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			SKI:       cert.SKI,
			AKI:       cert.AKI,
			Parsed:    cert.Parsed,
		}
		certHashes[i] = cert.CertHash
	}

	chainInfo := &certutil.ChainInfo{
		ChainHash:    certutil.ComputeChainHash(certHashes),
		LeafCertHash: certHashes[0],
		Depth:        len(certs),
		Certs:        certs,
		CertHashes:   certHashes,
	}

	mode := CrawlModeStandard
	if input.Forced {
		mode = CrawlModeForced
	}

	result := &CrawlResult{
		Domain:    input.Domain,
		Port:      input.Port,
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      mode,
	}

	_, err := r.repo.RecordSuccessfulCrawl(ctx, result)
	return err
}

// StoreCertificate stores a single certificate in the database (upsert by hash).
func (r *WebRepository) StoreCertificate(ctx context.Context, cert *web.CertificateResult) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO certificates (cert_hash, der, subject, issuer, not_before, not_after, ski, aki)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (cert_hash) DO NOTHING
	`, cert.CertHash, cert.DER,
		cert.Subject, cert.Issuer,
		cert.NotBefore, cert.NotAfter,
		nullableBytes(cert.SKI), nullableBytes(cert.AKI))
	if err != nil {
		return fmt.Errorf("store certificate: %w", err)
	}
	return nil
}

func parseCertificateDER(der []byte) *x509.Certificate {
	info, err := certutil.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return info.Parsed
}

// FindCertificatesBySKI finds certificates whose SKI matches the given value.
func (r *WebRepository) FindCertificatesBySKI(ctx context.Context, ski []byte) ([]*web.CertificateResult, error) {
	if len(ski) == 0 {
		return nil, nil
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT cert_hash, der, not_before, not_after, ski, aki
		FROM certificates
		WHERE ski = $1
	`, ski)
	if err != nil {
		return nil, fmt.Errorf("query certificates by ski: %w", err)
	}
	defer rows.Close()

	var results []*web.CertificateResult
	for rows.Next() {
		cert := &web.CertificateResult{}
		var der []byte
		var certSKI, certAKI []byte
		var notBefore, notAfter sql.NullTime

		if err := rows.Scan(&cert.CertHash, &der, &notBefore, &notAfter, &certSKI, &certAKI); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}

		cert.PEM = certutil.DERToPEM(der)
		cert.DER = der
		if notBefore.Valid {
			cert.NotBefore = notBefore.Time
		}
		if notAfter.Valid {
			cert.NotAfter = notAfter.Time
		}
		cert.SKI = certSKI
		cert.AKI = certAKI
		cert.Parsed = parseCertificateDER(der)

		results = append(results, cert)
	}

	return results, rows.Err()
}
