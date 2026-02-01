package cmd

import (
	"context"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/crawler"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/web"
)

// WebCrawler adapts the crawler package for the web interface.
type WebCrawler struct {
	crawler *crawler.Crawler
}

// NewWebCrawler creates a new web crawler adapter.
func NewWebCrawler(timeout time.Duration) *WebCrawler {
	return &WebCrawler{
		crawler: crawler.New(timeout),
	}
}

// Crawl performs a TLS handshake and returns the certificate chain.
func (wc *WebCrawler) Crawl(ctx context.Context, domain string) (*web.CrawlOutput, error) {
	result, err := wc.crawler.Crawl(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Convert to web types
	chain := make([]*web.CertificateResult, len(result.ChainInfo.Certs))
	for i, cert := range result.ChainInfo.Certs {
		chain[i] = &web.CertificateResult{
			CertHash:  cert.CertHash,
			PEM:       cert.PEM,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			SKI:       cert.SKI,
			AKI:       cert.AKI,
			Position:  i + 1,
			Parsed:    cert.Parsed,
		}
	}

	return &web.CrawlOutput{
		Domain: domain,
		Chain:  chain,
	}, nil
}
