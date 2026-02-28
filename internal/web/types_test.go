package web

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, pub interface{}, priv interface{}) *x509.Certificate {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func TestFormatPublicKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatPublicKey(cert)
	if result != "RSA 2048 bits" {
		t.Errorf("formatPublicKey(RSA 2048) = %q, want %q", result, "RSA 2048 bits")
	}
}

func TestFormatPublicKey_RSA4096(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatPublicKey(cert)
	if result != "RSA 4096 bits" {
		t.Errorf("formatPublicKey(RSA 4096) = %q, want %q", result, "RSA 4096 bits")
	}
}

func TestFormatPublicKey_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatPublicKey(cert)
	if result != "ECDSA P-256" {
		t.Errorf("formatPublicKey(ECDSA P-256) = %q, want %q", result, "ECDSA P-256")
	}
}

func TestFormatPublicKey_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatPublicKey(cert)
	if result != "ECDSA P-384" {
		t.Errorf("formatPublicKey(ECDSA P-384) = %q, want %q", result, "ECDSA P-384")
	}
}

func TestFormatPublicKey_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	cert := generateTestCert(t, pub, priv)
	result := formatPublicKey(cert)
	if result != "Ed25519" {
		t.Errorf("formatPublicKey(Ed25519) = %q, want %q", result, "Ed25519")
	}
}

func TestFormatKeyLength_RSA2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatKeyLength(cert)
	if result != "2048 bits" {
		t.Errorf("formatKeyLength(RSA 2048) = %q, want %q", result, "2048 bits")
	}
}

func TestFormatKeyLength_RSA4096(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatKeyLength(cert)
	if result != "4096 bits" {
		t.Errorf("formatKeyLength(RSA 4096) = %q, want %q", result, "4096 bits")
	}
}

func TestFormatKeyLength_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatKeyLength(cert)
	if result != "256 bits" {
		t.Errorf("formatKeyLength(ECDSA P-256) = %q, want %q", result, "256 bits")
	}
}

func TestFormatKeyLength_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)
	result := formatKeyLength(cert)
	if result != "384 bits" {
		t.Errorf("formatKeyLength(ECDSA P-384) = %q, want %q", result, "384 bits")
	}
}

func TestFormatKeyLength_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	cert := generateTestCert(t, pub, priv)
	result := formatKeyLength(cert)
	if result != "256 bits" {
		t.Errorf("formatKeyLength(Ed25519) = %q, want %q", result, "256 bits")
	}
}

func TestCertToViewData_KeyLength(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)

	result := &CertificateResult{
		CertHash:  make([]byte, 32),
		PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Parsed:    cert,
	}

	view := certToViewData(result)
	if view.KeyLength != "256 bits" {
		t.Errorf("certToViewData KeyLength = %q, want %q", view.KeyLength, "256 bits")
	}
	if view.PublicKeyInfo != "ECDSA P-256" {
		t.Errorf("certToViewData PublicKeyInfo = %q, want %q", view.PublicKeyInfo, "ECDSA P-256")
	}
}

func TestCertToViewData_Fingerprints(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	cert := generateTestCert(t, &key.PublicKey, key)

	result := &CertificateResult{
		CertHash:  make([]byte, 32),
		PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Parsed:    cert,
	}

	view := certToViewData(result)

	// SHA-1 fingerprint should be 20 bytes = 59 characters with colons (20*2 + 19 colons)
	if view.SHA1Fingerprint == "" {
		t.Error("certToViewData SHA1Fingerprint is empty")
	}
	if len(strings.Split(view.SHA1Fingerprint, ":")) != 20 {
		t.Errorf("certToViewData SHA1Fingerprint has wrong number of hex pairs: got %d, want 20", len(strings.Split(view.SHA1Fingerprint, ":")))
	}

	// SHA-256 fingerprint should be 32 bytes = 95 characters with colons (32*2 + 31 colons)
	if view.SHA256Fingerprint == "" {
		t.Error("certToViewData SHA256Fingerprint is empty")
	}
	if len(strings.Split(view.SHA256Fingerprint, ":")) != 32 {
		t.Errorf("certToViewData SHA256Fingerprint has wrong number of hex pairs: got %d, want 32", len(strings.Split(view.SHA256Fingerprint, ":")))
	}

	// Verify lowercase format
	if view.SHA1Fingerprint != strings.ToLower(view.SHA1Fingerprint) {
		t.Errorf("certToViewData SHA1Fingerprint should be lowercase: %q", view.SHA1Fingerprint)
	}
	if view.SHA256Fingerprint != strings.ToLower(view.SHA256Fingerprint) {
		t.Errorf("certToViewData SHA256Fingerprint should be lowercase: %q", view.SHA256Fingerprint)
	}
}

func TestFormatHexBytes_Lowercase(t *testing.T) {
	input := []byte{0xF8, 0x87, 0x8B, 0x2D, 0xBD}
	result := formatHexBytes(input)
	expected := "f8:87:8b:2d:bd"
	if result != expected {
		t.Errorf("formatHexBytes = %q, want %q", result, expected)
	}
}

func TestFormatCertDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"less than a day", 12 * time.Hour, "less than a day"},
		{"one day", 24 * time.Hour, "1 day"},
		{"multiple days", 15 * 24 * time.Hour, "15 days"},
		{"30 days", 30 * 24 * time.Hour, "1 month"},
		{"60 days", 60 * 24 * time.Hour, "2 months"},
		{"90 days", 90 * 24 * time.Hour, "3 months"},
		{"45 days", 45 * 24 * time.Hour, "1 month, 15 days"},
		{"365 days", 365 * 24 * time.Hour, "1 year"},
		{"730 days", 730 * 24 * time.Hour, "2 years"},
		{"400 days", 400 * 24 * time.Hour, "1 year, 1 month"},
		{"negative less than a day", -12 * time.Hour, "less than a day"},
		{"negative 90 days", -90 * 24 * time.Hour, "3 months"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCertDuration(tt.duration)
			if got != tt.expected {
				t.Errorf("formatCertDuration(%v) = %q, want %q", tt.duration, got, tt.expected)
			}
		})
	}
}

func TestCertToViewData_ValidityFields(t *testing.T) {
	now := time.Now()
	result := &CertificateResult{
		CertHash:  make([]byte, 32),
		PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
		NotBefore: now.Add(-30 * 24 * time.Hour),
		NotAfter:  now.Add(60 * 24 * time.Hour),
	}

	view := certToViewData(result)
	if view.ValidityDays != 90 {
		t.Errorf("certToViewData ValidityDays = %d, want 90", view.ValidityDays)
	}
	if view.ExpiresIn == "" {
		t.Error("certToViewData ExpiresIn is empty")
	}
	if view.IsExpired {
		t.Error("certToViewData IsExpired should be false")
	}
}

func TestCertToViewData_ExpiredCert(t *testing.T) {
	now := time.Now()
	result := &CertificateResult{
		CertHash:  make([]byte, 32),
		PEM:       "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
		NotBefore: now.Add(-90 * 24 * time.Hour),
		NotAfter:  now.Add(-30 * 24 * time.Hour),
	}

	view := certToViewData(result)
	if view.ValidityDays != 60 {
		t.Errorf("certToViewData ValidityDays = %d, want 60", view.ValidityDays)
	}
	if !view.IsExpired {
		t.Error("certToViewData IsExpired should be true")
	}
	if view.ExpiresIn == "" {
		t.Error("certToViewData ExpiresIn should not be empty for expired cert")
	}
}
