package db

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/web"
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
	result := &web.DomainResult{
		Domain: domainName,
	}

	// Get domain info
	var domainID int64
	var chainHash []byte
	var updatedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT domain_id, current_chain_hash, current_chain_updated_at
		FROM domains
		WHERE domain = $1
	`, domainName).Scan(&domainID, &chainHash, &updatedAt)

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

	// Get chain certificates in order
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.cert_hash, c.pem, c.not_before, c.not_after, c.ski, c.aki, cc.position
		FROM chain_certs cc
		JOIN certificates c ON c.cert_hash = cc.cert_hash
		WHERE cc.chain_hash = $1
		ORDER BY cc.position
	`, chainHash)
	if err != nil {
		return nil, fmt.Errorf("query chain certs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		cert := &web.CertificateResult{}
		var ski, aki []byte
		var notBefore, notAfter sql.NullTime

		err := rows.Scan(&cert.CertHash, &cert.PEM, &notBefore, &notAfter, &ski, &aki, &cert.Position)
		if err != nil {
			return nil, fmt.Errorf("scan cert: %w", err)
		}

		if notBefore.Valid {
			cert.NotBefore = notBefore.Time
		}
		if notAfter.Valid {
			cert.NotAfter = notAfter.Time
		}
		cert.SKI = ski
		cert.AKI = aki

		// Parse the certificate
		cert.Parsed = parseCertificatePEM(cert.PEM)

		result.Chain = append(result.Chain, cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certs: %w", err)
	}

	result.HasChain = len(result.Chain) > 0
	return result, nil
}

// GetCertificateByHash retrieves a certificate by its hash.
func (r *WebRepository) GetCertificateByHash(ctx context.Context, hash []byte) (*web.CertificateResult, error) {
	cert := &web.CertificateResult{
		CertHash: hash,
	}

	var ski, aki []byte
	var notBefore, notAfter sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT pem, not_before, not_after, ski, aki
		FROM certificates
		WHERE cert_hash = $1
	`, hash).Scan(&cert.PEM, &notBefore, &notAfter, &ski, &aki)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("certificate not found")
	}
	if err != nil {
		return nil, fmt.Errorf("query certificate: %w", err)
	}

	if notBefore.Valid {
		cert.NotBefore = notBefore.Time
	}
	if notAfter.Valid {
		cert.NotAfter = notAfter.Time
	}
	cert.SKI = ski
	cert.AKI = aki

	// Parse the certificate
	cert.Parsed = parseCertificatePEM(cert.PEM)

	return cert, nil
}

// CanStandardRefresh checks if a standard refresh is allowed for the domain.
func (r *WebRepository) CanStandardRefresh(ctx context.Context, domainName string, window time.Duration) (bool, time.Duration, error) {
	var lastAttempt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT last_standard_attempt_at
		FROM domains
		WHERE domain = $1
	`, domainName).Scan(&lastAttempt)

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
	var lastAttempt sql.NullTime

	err := r.db.QueryRowContext(ctx, `
		SELECT last_forced_attempt_at
		FROM domains
		WHERE domain = $1
	`, domainName).Scan(&lastAttempt)

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

// AcquireLock tries to acquire a crawl lock for the domain.
func (r *WebRepository) AcquireLock(ctx context.Context, domainName string, lockID string, ttl time.Duration) (bool, error) {
	expiresAt := time.Now().Add(ttl)

	// First, clean up expired locks
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM domain_locks WHERE expires_at < now()
	`)
	if err != nil {
		return false, fmt.Errorf("cleanup expired locks: %w", err)
	}

	// Try to insert lock
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO domain_locks (domain, locked_by, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (domain) DO NOTHING
	`, domainName, lockID, expiresAt)
	if err != nil {
		return false, fmt.Errorf("insert lock: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check rows affected: %w", err)
	}

	return rowsAffected > 0, nil
}

// ReleaseLock releases a crawl lock for the domain.
func (r *WebRepository) ReleaseLock(ctx context.Context, domainName string, lockID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM domain_locks WHERE domain = $1 AND locked_by = $2
	`, domainName, lockID)
	if err != nil {
		return fmt.Errorf("delete lock: %w", err)
	}
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
		return r.repo.RecordFailedCrawl(ctx, input.Domain, time.Now(), mode)
	}

	// Convert web types to internal types
	certs := make([]*certutil.CertInfo, len(input.Chain))
	for i, cert := range input.Chain {
		certs[i] = &certutil.CertInfo{
			CertHash:  cert.CertHash,
			PEM:       cert.PEM,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			SKI:       cert.SKI,
			AKI:       cert.AKI,
			Parsed:    cert.Parsed,
		}
	}

	// Compute chain hash
	certHashes := make([][]byte, len(certs))
	for i, cert := range certs {
		certHashes[i] = cert.CertHash
	}

	chainInfo := &certutil.ChainInfo{
		ChainHash:    certutil.ComputeChainHash(certHashes),
		LeafCertHash: certHashes[0],
		Depth:        len(certs),
		Certs:        certs,
	}

	mode := CrawlModeStandard
	if input.Forced {
		mode = CrawlModeForced
	}

	result := &CrawlResult{
		Domain:    input.Domain,
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      mode,
	}

	_, err := r.repo.RecordSuccessfulCrawl(ctx, result)
	return err
}

// parseCertificatePEM parses a PEM-encoded certificate.
func parseCertificatePEM(pemStr string) *x509.Certificate {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	return cert
}
