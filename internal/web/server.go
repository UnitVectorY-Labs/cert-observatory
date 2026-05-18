// Package web provides the HTTP server and handlers for the cert-observatory web interface.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

//go:embed static/*
var staticFS embed.FS

//go:embed templates/*
var templateFS embed.FS

// Config contains configuration for the web server.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":8080")
	ListenAddr string
	// CrawlTimeout is the timeout for outbound crawl operations
	CrawlTimeout time.Duration
	// ReadTimeout is the HTTP server read timeout
	ReadTimeout time.Duration
	// WriteTimeout is the HTTP server write timeout
	WriteTimeout time.Duration
	// IdleTimeout is the HTTP server idle timeout
	IdleTimeout time.Duration
	// StandardRefreshWindow is the minimum time between standard crawls
	StandardRefreshWindow time.Duration
	// ForcedRefreshWindow is the minimum time between forced refreshes
	ForcedRefreshWindow time.Duration
	// Logger is the structured logger
	Logger *slog.Logger
}

// DefaultConfig returns default configuration values.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:            ":8080",
		CrawlTimeout:          30 * time.Second,
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          60 * time.Second,
		IdleTimeout:           120 * time.Second,
		StandardRefreshWindow: 23 * time.Hour,
		ForcedRefreshWindow:   1 * time.Hour,
	}
}

// Server is the HTTP server for the web interface.
type Server struct {
	config     *Config
	repo       Repository
	crawler    Crawler
	templates  *template.Template
	httpServer *http.Server
	logger     *slog.Logger
}

// Repository defines the database operations needed by the web server.
type Repository interface {
	// GetDomainWithChain retrieves a domain and its current chain with certificates.
	GetDomainWithChain(ctx context.Context, domain string) (*DomainResult, error)
	// GetDomainWithChainForPort retrieves a domain target and its current chain with certificates.
	GetDomainWithChainForPort(ctx context.Context, domain string, port int) (*DomainResult, error)
	// GetCertificateByHash retrieves a certificate by its hash.
	GetCertificateByHash(ctx context.Context, hash []byte) (*CertificateResult, error)
	// CertificateExists checks whether a certificate is already present in the catalog.
	CertificateExists(ctx context.Context, hash []byte) (bool, error)
	// FindCertificatesBySKI finds certificates whose SKI matches the given value.
	// Used for building the certificate trust path graph.
	FindCertificatesBySKI(ctx context.Context, ski []byte) ([]*CertificateResult, error)
	// CanStandardRefresh checks if a standard refresh is allowed for the domain.
	CanStandardRefresh(ctx context.Context, domain string, window time.Duration) (bool, time.Duration, error)
	// CanStandardRefreshForPort checks if a standard refresh is allowed for the domain target.
	CanStandardRefreshForPort(ctx context.Context, domain string, port int, window time.Duration) (bool, time.Duration, error)
	// CanForcedRefresh checks if a forced refresh is allowed for the domain.
	CanForcedRefresh(ctx context.Context, domain string, window time.Duration) (bool, time.Duration, error)
	// CanForcedRefreshForPort checks if a forced refresh is allowed for the domain target.
	CanForcedRefreshForPort(ctx context.Context, domain string, port int, window time.Duration) (bool, time.Duration, error)
	// AcquireLock tries to acquire a crawl lock for the domain.
	AcquireLock(ctx context.Context, domain string, lockID string, ttl time.Duration) (bool, error)
	// AcquireLockForPort tries to acquire a crawl lock for the domain target.
	AcquireLockForPort(ctx context.Context, domain string, port int, lockID string, ttl time.Duration) (bool, error)
	// ReleaseLock releases a crawl lock for the domain.
	ReleaseLock(ctx context.Context, domain string, lockID string) error
	// ReleaseLockForPort releases a crawl lock for the domain target.
	ReleaseLockForPort(ctx context.Context, domain string, port int, lockID string) error
	// RecordCrawlResult records the result of a crawl operation.
	RecordCrawlResult(ctx context.Context, result *CrawlResultInput) error
	// StoreCertificate stores a single certificate in the database.
	StoreCertificate(ctx context.Context, cert *CertificateResult) error
}

// Crawler defines the TLS crawling operations.
type Crawler interface {
	// Crawl performs a TLS handshake and returns the certificate chain.
	Crawl(ctx context.Context, domain string) (*CrawlOutput, error)
	// CrawlPort performs a TLS handshake on the specified port and returns the certificate chain.
	CrawlPort(ctx context.Context, domain string, port int) (*CrawlOutput, error)
}

// New creates a new web server.
func New(cfg *Config, repo Repository, crawler Crawler) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	assetVersions, err := buildAssetVersions(staticFS, versionedAssetPaths)
	if err != nil {
		return nil, fmt.Errorf("build asset versions: %w", err)
	}

	// Define template functions
	funcMap := template.FuncMap{
		// trustedHTML converts a string to template.HTML. Only use with trusted,
		// developer-controlled content (e.g., RFC links in reserved domain errors).
		"trustedHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"assetURL": func(path string) string {
			return assetURL(path, assetVersions)
		},
	}

	// Parse templates with custom functions
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	s := &Server{
		config:    cfg,
		repo:      repo,
		crawler:   crawler,
		templates: tmpl,
		logger:    logger,
	}

	return s, nil
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("create static fs: %w", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Routes - GET endpoints are read-only, POST endpoints can trigger crawls
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("POST /inspect", s.wrapWithOriginCheck(s.handleInspect))
	mux.HandleFunc("POST /refresh", s.wrapWithOriginCheck(s.handleRefresh))
	mux.HandleFunc("POST /manual", s.wrapWithOriginCheck(s.handleManualCert))
	mux.HandleFunc("GET /cert/{hash}", s.handleCertDetails)
	mux.HandleFunc("GET /download", s.handleDownload)

	// Wrap with security headers middleware
	handler := s.securityHeadersMiddleware(mux)

	s.httpServer = &http.Server{
		Addr:         s.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	s.logger.Info("starting web server", "addr", s.config.ListenAddr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// wrapWithOriginCheck wraps a handler with cross-site request protection.
// This prevents cross-site requests from triggering crawls by checking
// Origin and Sec-Fetch-Site headers.
func (s *Server) wrapWithOriginCheck(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check Sec-Fetch-Site header (modern browsers)
		secFetchSite := r.Header.Get("Sec-Fetch-Site")
		if secFetchSite != "" && secFetchSite != "same-origin" && secFetchSite != "same-site" && secFetchSite != "none" {
			s.logger.Warn("cross-site request blocked", "sec-fetch-site", secFetchSite, "path", r.URL.Path)
			http.Error(w, "Cross-site requests are not allowed", http.StatusForbidden)
			return
		}

		// Check Origin header if present
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Get the host from the request
			host := r.Host
			if host == "" {
				host = r.URL.Host
			}

			// Build expected origins (http and https)
			expectedHTTP := "http://" + host
			expectedHTTPS := "https://" + host

			// Allow if origin matches either scheme
			if origin != expectedHTTP && origin != expectedHTTPS {
				s.logger.Warn("cross-origin request blocked", "origin", origin, "host", host, "path", r.URL.Path)
				http.Error(w, "Cross-origin requests are not allowed", http.StatusForbidden)
				return
			}
		}

		handler(w, r)
	}
}

// securityHeadersMiddleware adds security headers to all responses.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		scriptSrc := []string{
			"'self'",
			"'unsafe-inline'",
			"https://cdn.jsdelivr.net",
			"https://static.cloudflareinsights.com",
		}

		cspDirectives := []string{
			"default-src 'self'",
			"script-src " + strings.Join(scriptSrc, " "),
			"script-src-elem " + strings.Join(scriptSrc, " "),
			"style-src 'self' 'unsafe-inline'",
			// Optional: lock down other common sinks.
			// "img-src 'self' data:",
			// "font-src 'self'",
			// "connect-src 'self'",
		}

		w.Header().Set("Content-Security-Policy", strings.Join(cspDirectives, "; "))

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}
