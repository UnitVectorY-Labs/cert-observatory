package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// generateTestPEMBundle creates a PEM bundle with the specified number of valid certificates.
func generateTestPEMBundle(t *testing.T, count int) []byte {
	t.Helper()

	var bundle []byte
	for i := range count {
		cert := generateTestCert(t, fmt.Sprintf("test-cert-%d", i))
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		bundle = append(bundle, pem.EncodeToMemory(pemBlock)...)
	}
	return bundle
}

// generateTestCert creates a self-signed test certificate.
func generateTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Invalid PEM for testing
const invalidPEMBundle = `-----BEGIN CERTIFICATE-----
not valid base64 data here
-----END CERTIFICATE-----
`

func TestParsePEMBundle(t *testing.T) {
	// Generate valid test bundle
	validBundle := generateTestPEMBundle(t, 2)

	tests := []struct {
		name             string
		input            []byte
		expectedCerts    int
		expectedFailures int
	}{
		{
			name:             "valid bundle with 2 certs",
			input:            validBundle,
			expectedCerts:    2,
			expectedFailures: 0,
		},
		{
			name:             "invalid PEM (malformed base64)",
			input:            []byte(invalidPEMBundle),
			expectedCerts:    0,
			expectedFailures: 0, // pem.Decode fails silently, doesn't count as parse failure
		},
		{
			name:             "empty input",
			input:            []byte(""),
			expectedCerts:    0,
			expectedFailures: 0,
		},
		{
			name:             "no PEM blocks",
			input:            []byte("this is just some text\nno certificates here\n"),
			expectedCerts:    0,
			expectedFailures: 0,
		},
		{
			name:             "private key (not certificate)",
			input:            []byte("-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n"),
			expectedCerts:    0,
			expectedFailures: 0, // Private keys are skipped, not counted as failures
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, failures := ParsePEMBundle(tt.input)

			if len(certs) != tt.expectedCerts {
				t.Errorf("got %d certs, want %d", len(certs), tt.expectedCerts)
			}

			if failures != tt.expectedFailures {
				t.Errorf("got %d failures, want %d", failures, tt.expectedFailures)
			}

			// Verify that parsed certs have required fields
			for i, cert := range certs {
				if len(cert.CertHash) != 32 {
					t.Errorf("cert[%d] has invalid hash length: %d", i, len(cert.CertHash))
				}
				if cert.PEM() == "" {
					t.Errorf("cert[%d] has empty PEM", i)
				}
				if cert.Parsed == nil {
					t.Errorf("cert[%d] has nil Parsed", i)
				}
			}
		})
	}
}

func TestParsePEMBundle_MixedValidInvalid(t *testing.T) {
	// Create a bundle with 1 valid cert and 1 invalid (valid PEM but invalid cert data)
	validCert := generateTestCert(t, "valid-cert")
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: validCert.Raw,
	}

	// Create an invalid cert: valid PEM format but garbage certificate data
	invalidPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a valid certificate DER"),
	}

	mixedBundle := pem.EncodeToMemory(pemBlock)
	mixedBundle = append(mixedBundle, pem.EncodeToMemory(invalidPEMBlock)...)

	certs, failures := ParsePEMBundle(mixedBundle)

	if len(certs) != 1 {
		t.Errorf("got %d certs, want 1", len(certs))
	}

	if failures != 1 {
		t.Errorf("got %d failures, want 1", failures)
	}
}

func TestParsePEMBundle_CertProperties(t *testing.T) {
	bundle := generateTestPEMBundle(t, 2)
	certs, failures := ParsePEMBundle(bundle)

	if failures != 0 {
		t.Errorf("unexpected failures: %d", failures)
	}

	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}

	// Check that we can access parsed certificate properties
	for i, cert := range certs {
		if cert.Parsed.Subject.CommonName == "" {
			t.Errorf("cert[%d] has empty CommonName", i)
		}

		if cert.NotBefore.IsZero() {
			t.Errorf("cert[%d] has zero NotBefore", i)
		}

		if cert.NotAfter.IsZero() {
			t.Errorf("cert[%d] has zero NotAfter", i)
		}
	}
}
