// Package crawler provides TLS certificate chain crawling functionality.
package crawler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
)

var (
	// ErrNoCertificates indicates no certificates were returned during TLS handshake
	ErrNoCertificates = errors.New("no certificates returned by server")
)

// CrawlResult contains the result of a TLS certificate crawl.
type CrawlResult struct {
	// Domain is the normalized domain that was crawled
	Domain string
	// ChainInfo contains the parsed certificate chain information
	ChainInfo *certutil.ChainInfo
	// RawCerts contains the raw x509.Certificate objects
	RawCerts []*x509.Certificate
	// CrawlTime is when the crawl was performed
	CrawlTime time.Time
}

// CrawlError represents an error that occurred during crawling.
type CrawlError struct {
	Domain string
	Err    error
}

func (e *CrawlError) Error() string {
	return fmt.Sprintf("crawl failed for %s: %v", e.Domain, e.Err)
}

func (e *CrawlError) Unwrap() error {
	return e.Err
}

// Crawler performs TLS certificate chain crawling.
type Crawler struct {
	// Timeout is the deadline for the entire crawl operation (connection + handshake)
	Timeout time.Duration
}

// New creates a new Crawler with the specified timeout.
func New(timeout time.Duration) *Crawler {
	return &Crawler{
		Timeout: timeout,
	}
}

// Crawl performs a TLS handshake to the specified domain on port 443 and
// returns the certificate chain presented by the server.
//
// The crawl:
//   - Opens a TCP connection to domain:443
//   - Performs a TLS handshake with SNI enabled
//   - Does not require chain validation to succeed
//   - Captures the peer-provided certificate chain in exact order
//   - Does not send HTTP requests or follow redirects
//   - Does not fetch OCSP/CRL or perform AIA fetching
func (c *Crawler) Crawl(ctx context.Context, domain string) (*CrawlResult, error) {
	crawlTime := time.Now()

	// Create context with timeout if not already set
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	// Create dialer with context
	dialer := &net.Dialer{}

	// Dial TCP connection
	addr := net.JoinHostPort(domain, "443")
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &CrawlError{Domain: domain, Err: fmt.Errorf("tcp connect: %w", err)}
	}
	defer conn.Close()

	// Set deadline on the connection
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, &CrawlError{Domain: domain, Err: fmt.Errorf("set deadline: %w", err)}
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		ServerName: domain, // SNI
		// Do not require chain validation to succeed
		InsecureSkipVerify: true,
		// Minimum TLS version for security
		MinVersion: tls.VersionTLS10,
	}

	// Perform TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, &CrawlError{Domain: domain, Err: fmt.Errorf("tls handshake: %w", err)}
	}
	defer tlsConn.Close()

	// Get peer certificates
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, &CrawlError{Domain: domain, Err: ErrNoCertificates}
	}

	// Parse the chain
	chainInfo := certutil.ParseChain(state.PeerCertificates)

	return &CrawlResult{
		Domain:    domain,
		ChainInfo: chainInfo,
		RawCerts:  state.PeerCertificates,
		CrawlTime: crawlTime,
	}, nil
}
