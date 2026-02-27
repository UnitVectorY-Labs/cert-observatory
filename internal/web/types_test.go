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
