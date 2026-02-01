package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// mockRepository implements the Repository interface for testing.
type mockRepository struct {
	domainResult      *DomainResult
	certificateResult *CertificateResult
	canStandard       bool
	standardWait      time.Duration
	canForced         bool
	forcedWait        time.Duration
	lockAcquired      bool
	crawlResults      []*CrawlResultInput
}

func (m *mockRepository) GetDomainWithChain(ctx context.Context, domain string) (*DomainResult, error) {
	if m.domainResult != nil && m.domainResult.Domain == domain {
		return m.domainResult, nil
	}
	return &DomainResult{Domain: domain}, nil
}

func (m *mockRepository) GetCertificateByHash(ctx context.Context, hash []byte) (*CertificateResult, error) {
	if m.certificateResult != nil {
		return m.certificateResult, nil
	}
	return nil, context.DeadlineExceeded
}

func (m *mockRepository) CanStandardRefresh(ctx context.Context, domain string, window time.Duration) (bool, time.Duration, error) {
	return m.canStandard, m.standardWait, nil
}

func (m *mockRepository) CanForcedRefresh(ctx context.Context, domain string, window time.Duration) (bool, time.Duration, error) {
	return m.canForced, m.forcedWait, nil
}

func (m *mockRepository) AcquireLock(ctx context.Context, domain string, lockID string, ttl time.Duration) (bool, error) {
	return m.lockAcquired, nil
}

func (m *mockRepository) ReleaseLock(ctx context.Context, domain string, lockID string) error {
	return nil
}

func (m *mockRepository) RecordCrawlResult(ctx context.Context, result *CrawlResultInput) error {
	m.crawlResults = append(m.crawlResults, result)
	return nil
}

// mockCrawler implements the Crawler interface for testing.
type mockCrawler struct {
	result *CrawlOutput
	err    error
}

func (m *mockCrawler) Crawl(ctx context.Context, domain string) (*CrawlOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.result != nil {
		return m.result, nil
	}
	return &CrawlOutput{
		Domain: domain,
		Chain: []*CertificateResult{
			{
				CertHash:  make([]byte, 32),
				PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
				NotBefore: time.Now().Add(-24 * time.Hour),
				NotAfter:  time.Now().Add(365 * 24 * time.Hour),
			},
		},
	}, nil
}

func TestHandleIndex(t *testing.T) {
	repo := &mockRepository{}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	server.handleIndex(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Cert Observatory") {
		t.Error("Expected page to contain 'Cert Observatory'")
	}

	// Ensure no CSRF token is present (removed per requirements)
	if strings.Contains(body, "csrf_token") {
		t.Error("Page should not contain CSRF token field")
	}

	if !strings.Contains(body, "UnitVectorY Labs") {
		t.Error("Expected page to contain footer with UnitVectorY Labs")
	}
}

func TestHandleInspect_ValidDomain(t *testing.T) {
	repo := &mockRepository{
		canStandard:  true,
		canForced:    true,
		lockAcquired: true,
	}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create request with form data (no CSRF needed)
	form := url.Values{}
	form.Set("domain", "github.com")

	req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleInspect(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandleInspect_InvalidDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr string
	}{
		{"empty domain", "", "enter a domain"},
		{"url with scheme", "https://example.com", "without http"},
		{"domain with port", "example.com:443", "without a port"},
		{"domain with path", "example.com/path", "without any path"},
		{"ip address", "192.168.1.1", "IP addresses are not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockRepository{}
			crawler := &mockCrawler{}

			server, err := New(DefaultConfig(), repo, crawler)
			if err != nil {
				t.Fatalf("Failed to create server: %v", err)
			}

			form := url.Values{}
			form.Set("domain", tt.domain)

			req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Host = "localhost:8080"

			w := httptest.NewRecorder()
			server.handleInspect(w, req)

			body := w.Body.String()
			if !strings.Contains(strings.ToLower(body), strings.ToLower(tt.wantErr)) {
				t.Errorf("Expected error containing %q, got: %s", tt.wantErr, body)
			}
		})
	}
}

func TestOriginValidation_CrossOrigin(t *testing.T) {
	repo := &mockRepository{
		canStandard:  true,
		canForced:    true,
		lockAcquired: true,
	}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	form := url.Values{}
	form.Set("domain", "github.com")

	// Test cross-origin request (should be blocked)
	req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	handler := server.wrapWithOriginCheck(server.handleInspect)
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for cross-origin request, got %d", w.Code)
	}
}

func TestOriginValidation_SameOrigin(t *testing.T) {
	repo := &mockRepository{
		canStandard:  true,
		canForced:    true,
		lockAcquired: true,
	}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	form := url.Values{}
	form.Set("domain", "github.com")

	// Test same-origin request (should be allowed)
	req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://localhost:8080")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	handler := server.wrapWithOriginCheck(server.handleInspect)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for same-origin request, got %d", w.Code)
	}
}

func TestOriginValidation_SecFetchSite(t *testing.T) {
	repo := &mockRepository{}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	form := url.Values{}
	form.Set("domain", "github.com")

	// Test cross-site request via Sec-Fetch-Site header
	req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	handler := server.wrapWithOriginCheck(server.handleInspect)
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for cross-site Sec-Fetch-Site, got %d", w.Code)
	}
}

func TestHandleInspect_CachedResult(t *testing.T) {
	repo := &mockRepository{
		domainResult: &DomainResult{
			Domain:   "github.com",
			HasChain: true,
			Chain: []*CertificateResult{
				{
					CertHash:  make([]byte, 32),
					PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
					NotBefore: time.Now().Add(-24 * time.Hour),
					NotAfter:  time.Now().Add(365 * 24 * time.Hour),
				},
			},
			UpdatedAt: time.Now().Add(-1 * time.Hour),
		},
		canStandard: false, // Not allowed to refresh
		canForced:   true,
	}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	form := url.Values{}
	form.Set("domain", "github.com")

	req := httptest.NewRequest(http.MethodPost, "/inspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleInspect(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Cached") {
		t.Error("Expected result to show cached status")
	}
}

func TestHandleRefresh_NotAllowed(t *testing.T) {
	repo := &mockRepository{
		canForced:  false,
		forcedWait: 30 * time.Minute,
	}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	form := url.Values{}
	form.Set("domain", "github.com")

	req := httptest.NewRequest(http.MethodPost, "/refresh", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleRefresh(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Refresh Not Available") {
		t.Error("Expected refresh not available message")
	}
}

func TestSecurityHeaders(t *testing.T) {
	repo := &mockRepository{}
	crawler := &mockCrawler{}

	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create a test handler
	handler := server.securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-XSS-Protection":       "1; mode=block",
	}

	for header, expected := range expectedHeaders {
		if got := w.Header().Get(header); got != expected {
			t.Errorf("Expected header %s=%q, got %q", header, expected, got)
		}
	}

	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Expected Content-Security-Policy header")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30 seconds"},
		{5 * time.Minute, "5 minutes"},
		{1 * time.Hour, "1 hour"},
		{3 * time.Hour, "3 hours"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.expected {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.duration, got, tt.expected)
			}
		})
	}
}

func TestIsIPLiteral(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"1.2.3.4", true},
		{"example.com", false},
		{"test.example.com", false},
		{"::1", true}, // IPv6 with colon
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isIPLiteral(tt.input)
			if got != tt.expected {
				t.Errorf("isIPLiteral(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
