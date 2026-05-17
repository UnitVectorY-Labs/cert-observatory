package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
)

// mockRepository implements the Repository interface for testing.
type mockRepository struct {
	domainResult      *DomainResult
	certificateResult *CertificateResult
	skiCertificates   []*CertificateResult
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

func (m *mockRepository) FindCertificatesBySKI(ctx context.Context, ski []byte) ([]*CertificateResult, error) {
	return m.skiCertificates, nil
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

func (m *mockRepository) StoreCertificate(ctx context.Context, cert *CertificateResult) error {
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

	if !strings.Contains(body, "/static/css/style.css?v=") {
		t.Error("Expected stylesheet URL to include cache-busting version")
	}

	if !strings.Contains(body, "/static/js/script.js?v=") {
		t.Error("Expected script URL to include cache-busting version")
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
			req.Header.Set("HX-Request", "true") // Simulate HTMX request
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
	req.Header.Set("HX-Request", "true") // Simulate HTMX request
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleInspect(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "cached") {
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
	req.Header.Set("HX-Request", "true") // Simulate HTMX request
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

func TestHandleInspect_ReservedDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		wantStatus int
		wantErr    string
	}{
		{"example.com", "example.com", http.StatusBadRequest, "reserved"},
		{"www.example.com", "www.example.com", http.StatusBadRequest, "reserved"},
		{"test TLD", "foo.test", http.StatusBadRequest, "reserved"},
		{"local domain", "printer.local", http.StatusBadRequest, "local"},
		{"onion domain", "hidden.onion", http.StatusBadRequest, "Tor"},
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
			req.Header.Set("HX-Request", "true")
			req.Host = "localhost:8080"

			w := httptest.NewRecorder()
			server.handleInspect(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.wantErr) {
				t.Errorf("Expected error containing %q, got: %s", tt.wantErr, body)
			}
		})
	}
}

// generateTestCA creates a self-signed CA certificate and returns the CA cert and signing key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
t.Helper()
caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate CA key: %v", err)
}
ski := make([]byte, 20)
if _, err := rand.Read(ski); err != nil {
t.Fatalf("generate SKI: %v", err)
}
tmpl := &x509.Certificate{
SerialNumber:          big.NewInt(1),
Subject:               pkix.Name{CommonName: "Test Root CA"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
IsCA:                  true,
BasicConstraintsValid: true,
KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
SubjectKeyId:          ski,
}
der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
if err != nil {
t.Fatalf("create CA cert: %v", err)
}
cert, err := x509.ParseCertificate(der)
if err != nil {
t.Fatalf("parse CA cert: %v", err)
}
return cert, caKey
}

// generateTestLeaf creates a leaf certificate signed by the given CA.
func generateTestLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
t.Helper()
leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate leaf key: %v", err)
}
tmpl := &x509.Certificate{
SerialNumber:          big.NewInt(2),
Subject:               pkix.Name{CommonName: "test.example.com"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(365 * 24 * time.Hour),
KeyUsage:              x509.KeyUsageDigitalSignature,
BasicConstraintsValid: true,
AuthorityKeyId:        caCert.SubjectKeyId,
}
der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
if err != nil {
t.Fatalf("create leaf cert: %v", err)
}
cert, err := x509.ParseCertificate(der)
if err != nil {
t.Fatalf("parse leaf cert: %v", err)
}
return cert
}

// pemEncodeTest encodes a DER certificate as PEM for testing.
func pemEncodeTest(der []byte) string {
return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestHandleManualCert_EmptyPEM(t *testing.T) {
repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", "")
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "No Certificate") {
t.Error("expected 'No Certificate' error")
}
}

func TestHandleManualCert_InvalidPEM(t *testing.T) {
repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", "not a pem certificate")
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Invalid PEM") {
t.Error("expected 'Invalid PEM' error")
}
}

func TestHandleManualCert_SelfSigned(t *testing.T) {
caCert, _ := generateTestCA(t)

repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(caCert.Raw))
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Self-Signed") {
t.Error("expected self-signed error")
}
}

func TestHandleManualCert_UntrustedCert(t *testing.T) {
caCert, caKey := generateTestCA(t)
leafCert := generateTestLeaf(t, caCert, caKey)

// repo has no matching SKI candidates → untrusted
repo := &mockRepository{skiCertificates: nil}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(leafCert.Raw))
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Untrusted") {
t.Error("expected untrusted error")
}
}

func TestHandleManualCert_ValidCert(t *testing.T) {
caCert, caKey := generateTestCA(t)
leafCert := generateTestLeaf(t, caCert, caKey)

// Provide the CA cert as a trusted SKI candidate
caInfo := certutil.ParseX509Certificate(caCert)
skiCand := &CertificateResult{
CertHash:  caInfo.CertHash,
DER:       caInfo.DER,
PEM:       caInfo.PEM(),
Subject:   caInfo.Subject,
Issuer:    caInfo.Issuer,
NotBefore: caInfo.NotBefore,
NotAfter:  caInfo.NotAfter,
SKI:       caInfo.SKI,
AKI:       caInfo.AKI,
Parsed:    caInfo.Parsed,
}

repo := &mockRepository{skiCertificates: []*CertificateResult{skiCand}}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(leafCert.Raw))
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusOK {
t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
}
if !strings.Contains(w.Body.String(), "manual import") {
t.Error("expected 'manual import' status chip in results")
}
}

func TestHandleIndex_ManualMode(t *testing.T) {
repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

req := httptest.NewRequest(http.MethodGet, "/?manual", nil)
w := httptest.NewRecorder()
server.handleIndex(w, req)

if w.Code != http.StatusOK {
t.Errorf("expected 200, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Import Certificate") {
t.Error("expected 'Import Certificate' heading in manual mode")
}
}

func TestHandleManualCert_NonCertificatePEMBlock(t *testing.T) {
repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

// Generate a private key PEM block (not a CERTIFICATE)
privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate key: %v", err)
}
keyDER, err := x509.MarshalECPrivateKey(privKey)
if err != nil {
t.Fatalf("marshal key: %v", err)
}
keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

form := url.Values{}
form.Set("pem", keyPEM)
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Invalid PEM") {
t.Errorf("expected 'Invalid PEM' error, got: %s", w.Body.String())
}
}

func TestHandleManualCert_MultiplePEMBlocks(t *testing.T) {
caCert, caKey := generateTestCA(t)
leafCert := generateTestLeaf(t, caCert, caKey)

// Submit two certificates in the PEM field
twoCerts := pemEncodeTest(leafCert.Raw) + pemEncodeTest(caCert.Raw)

repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", twoCerts)
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Multiple PEM Blocks") {
t.Errorf("expected 'Multiple PEM Blocks' error, got: %s", w.Body.String())
}
}

func TestHandleManualCert_TrailingPEMBlock(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateTestLeaf(t, caCert, caKey)

	// Submit a certificate followed by another PEM block (EC PRIVATE KEY)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	combined := pemEncodeTest(leafCert.Raw) + keyPEM

	repo := &mockRepository{}
	crawler := &mockCrawler{}
	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	form := url.Values{}
	form.Set("pem", combined)
	req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleManualCert(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	// EC PRIVATE KEY is a decodable PEM block, so this hits the "Multiple PEM Blocks" path
	if !strings.Contains(w.Body.String(), "Multiple PEM Blocks") {
		t.Errorf("expected 'Multiple PEM Blocks' error, got: %s", w.Body.String())
	}
}

func TestHandleManualCert_TrailingNonPEMJunk(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	leafCert := generateTestLeaf(t, caCert, caKey)

	// Append non-PEM junk text that cannot be decoded by pem.Decode
	combined := pemEncodeTest(leafCert.Raw) + "this is junk data that is not a PEM block"

	repo := &mockRepository{}
	crawler := &mockCrawler{}
	server, err := New(DefaultConfig(), repo, crawler)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	form := url.Values{}
	form.Set("pem", combined)
	req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	server.handleManualCert(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	// Non-PEM junk can't be decoded; it stays in `rest` → hits the "Unexpected Data" path
	if !strings.Contains(w.Body.String(), "Unexpected Data") {
		t.Errorf("expected 'Unexpected Data' error, got: %s", w.Body.String())
	}
}

func TestHandleManualCert_MissingAKI(t *testing.T) {
// Generate a leaf cert signed by a CA but without AKI extension
caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate CA key: %v", err)
}
caTemplate := &x509.Certificate{
SerialNumber:          big.NewInt(1),
Subject:               pkix.Name{CommonName: "Test Root CA"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
IsCA:                  true,
BasicConstraintsValid: true,
KeyUsage:              x509.KeyUsageCertSign,
SubjectKeyId:          []byte{1, 2, 3, 4, 5},
}
caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
if err != nil {
t.Fatalf("create CA: %v", err)
}
caCert, _ := x509.ParseCertificate(caDER)

leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate leaf key: %v", err)
}
// Leaf cert has NO AuthorityKeyId
leafTemplate := &x509.Certificate{
SerialNumber:          big.NewInt(2),
Subject:               pkix.Name{CommonName: "no-aki.example.com"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(365 * 24 * time.Hour),
KeyUsage:              x509.KeyUsageDigitalSignature,
BasicConstraintsValid: true,
// AuthorityKeyId intentionally omitted
}
leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
if err != nil {
t.Fatalf("create leaf: %v", err)
}
leafCert, _ := x509.ParseCertificate(leafDER)

repo := &mockRepository{}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(leafCert.Raw))
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400, got %d", w.Code)
}
if !strings.Contains(w.Body.String(), "Untrusted Certificate") {
t.Errorf("expected 'Untrusted Certificate' error for missing AKI, got: %s", w.Body.String())
}
}

func TestHandleManualCert_NonCAIssuerRejected(t *testing.T) {
// A cert signed by a non-CA cert (IsCA=false) should be rejected
// because CheckSignatureFrom enforces CA status
nonCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate key: %v", err)
}
ski := []byte{10, 20, 30, 40, 50}
// Create a non-CA "signer" cert (IsCA=false)
nonCATemplate := &x509.Certificate{
SerialNumber:          big.NewInt(1),
Subject:               pkix.Name{CommonName: "Not A CA"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
IsCA:                  false,
BasicConstraintsValid: true,
SubjectKeyId:          ski,
}
nonCADER, err := x509.CreateCertificate(rand.Reader, nonCATemplate, nonCATemplate, &nonCAKey.PublicKey, nonCAKey)
if err != nil {
t.Fatalf("create non-CA: %v", err)
}
nonCACert, _ := x509.ParseCertificate(nonCADER)

// Create a leaf signed by the non-CA cert
leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
t.Fatalf("generate leaf key: %v", err)
}
leafTemplate := &x509.Certificate{
SerialNumber:          big.NewInt(2),
Subject:               pkix.Name{CommonName: "leaf.example.com"},
NotBefore:             time.Now().Add(-24 * time.Hour),
NotAfter:              time.Now().Add(365 * 24 * time.Hour),
KeyUsage:              x509.KeyUsageDigitalSignature,
BasicConstraintsValid: true,
AuthorityKeyId:        ski,
}
leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, nonCACert, &leafKey.PublicKey, nonCAKey)
if err != nil {
t.Fatalf("create leaf: %v", err)
}
leafCert, _ := x509.ParseCertificate(leafDER)

// The non-CA cert is in the DB as a candidate (SKI matches)
nonCAInfo := certutil.ParseX509Certificate(nonCACert)
skiCand := &CertificateResult{
CertHash:  nonCAInfo.CertHash,
DER:       nonCAInfo.DER,
PEM:       nonCAInfo.PEM(),
Subject:   nonCAInfo.Subject,
Issuer:    nonCAInfo.Issuer,
NotBefore: nonCAInfo.NotBefore,
NotAfter:  nonCAInfo.NotAfter,
SKI:       nonCAInfo.SKI,
AKI:       nonCAInfo.AKI,
Parsed:    nonCAInfo.Parsed,
}

repo := &mockRepository{skiCertificates: []*CertificateResult{skiCand}}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(leafCert.Raw))
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Header.Set("HX-Request", "true")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusBadRequest {
t.Errorf("expected 400 for non-CA issuer, got %d: %s", w.Code, w.Body.String())
}
if !strings.Contains(w.Body.String(), "Untrusted") {
t.Errorf("expected untrusted error for non-CA issuer, got: %s", w.Body.String())
}
}

func TestHandleManualCert_FullPagePreservesManualMode(t *testing.T) {
caCert, caKey := generateTestCA(t)
leafCert := generateTestLeaf(t, caCert, caKey)

caInfo := certutil.ParseX509Certificate(caCert)
skiCand := &CertificateResult{
CertHash:  caInfo.CertHash,
DER:       caInfo.DER,
PEM:       caInfo.PEM(),
Subject:   caInfo.Subject,
Issuer:    caInfo.Issuer,
NotBefore: caInfo.NotBefore,
NotAfter:  caInfo.NotAfter,
SKI:       caInfo.SKI,
AKI:       caInfo.AKI,
Parsed:    caInfo.Parsed,
}

repo := &mockRepository{skiCertificates: []*CertificateResult{skiCand}}
crawler := &mockCrawler{}
server, err := New(DefaultConfig(), repo, crawler)
if err != nil {
t.Fatalf("create server: %v", err)
}

form := url.Values{}
form.Set("pem", pemEncodeTest(leafCert.Raw))
// No HX-Request header → full page response
req := httptest.NewRequest(http.MethodPost, "/manual", strings.NewReader(form.Encode()))
req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
req.Host = "localhost:8080"

w := httptest.NewRecorder()
server.handleManualCert(w, req)

if w.Code != http.StatusOK {
t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
}
// Full page response should show the PEM textarea (manual mode form), not the domain input
body := w.Body.String()
if !strings.Contains(body, "Import Certificate") {
t.Errorf("expected 'Import Certificate' heading (manual mode) in full-page response, got domain form instead")
}
}

func TestHandleDownload_MissingParams(t *testing.T) {
	server, err := New(DefaultConfig(), &mockRepository{}, &mockCrawler{})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download", nil)
	w := httptest.NewRecorder()
	server.handleDownload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing params, got %d", w.Code)
	}
}

func TestHandleDownload_InvalidDomain(t *testing.T) {
	server, err := New(DefaultConfig(), &mockRepository{}, &mockCrawler{})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download?domain=not-valid!!!", nil)
	w := httptest.NewRecorder()
	server.handleDownload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", w.Code)
	}
}

func TestHandleDownload_DomainNotFound(t *testing.T) {
	// mockRepository returns a DomainResult with HasChain=false by default
	repo := &mockRepository{}
	server, err := New(DefaultConfig(), repo, &mockCrawler{})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download?domain=github.com", nil)
	w := httptest.NewRecorder()
	server.handleDownload(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for domain with no chain, got %d", w.Code)
	}
}

func TestHandleDownload_DomainWithChain(t *testing.T) {
	pemStr := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----\n"
	repo := &mockRepository{
		domainResult: &DomainResult{
			Domain:   "github.com",
			HasChain: true,
			Chain: []*CertificateResult{
				{
					CertHash:  make([]byte, 32),
					PEM:       pemStr,
					Subject:   "CN=github.com",
					NotBefore: time.Now().Add(-24 * time.Hour),
					NotAfter:  time.Now().Add(365 * 24 * time.Hour),
				},
			},
			UpdatedAt: time.Now(),
		},
		canForced: true,
	}
	server, err := New(DefaultConfig(), repo, &mockCrawler{})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download?domain=github.com&showNonChainCerts=true", nil)
	w := httptest.NewRecorder()
	server.handleDownload(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("expected Content-Type application/x-pem-file, got %s", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "github.com-certificates.pem") {
		t.Errorf("expected filename github.com-certificates.pem in Content-Disposition, got %s", cd)
	}
	body := w.Body.String()
	if !strings.Contains(body, "-----BEGIN CERTIFICATE-----") {
		t.Error("expected PEM content in response body")
	}
}

func TestHandleDownload_InvalidCertHash(t *testing.T) {
	server, err := New(DefaultConfig(), &mockRepository{}, &mockCrawler{})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/download?cert=notahex", nil)
	w := httptest.NewRecorder()
	server.handleDownload(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid cert hash, got %d", w.Code)
	}
}

func TestSanitizeDownloadFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"github.com", "github.com"},
		{"my-cert", "my-cert"},
		{"CN=github.com, O=GitHub", "CN_github.com__O_GitHub"},
		{"", "certificates"},
		{"hello world", "hello_world"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeDownloadFilename(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeDownloadFilename(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuildNormalDownloadURL(t *testing.T) {
	url := buildNormalDownloadURL("github.com", ChainGraphFilters{ShowNonChainCerts: true, ShowExpired: false})
	if !strings.Contains(url, "domain=github.com") {
		t.Errorf("expected domain param in URL, got %s", url)
	}
	if !strings.Contains(url, "showNonChainCerts=true") {
		t.Errorf("expected showNonChainCerts param in URL, got %s", url)
	}
	if strings.Contains(url, "showExpired") {
		t.Errorf("expected no showExpired param when false, got %s", url)
	}
}

func TestBuildManualDownloadURL(t *testing.T) {
	u := buildManualDownloadURL("abcdef1234", ChainGraphFilters{ShowExpired: true})
	if !strings.Contains(u, "cert=abcdef1234") {
		t.Errorf("expected cert param in URL, got %s", u)
	}
	if !strings.Contains(u, "showExpired=true") {
		t.Errorf("expected showExpired param in URL, got %s", u)
	}
}
