package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// generateTestCertificate creates a self-signed test certificate with the given options.
func generateTestCertificate(t *testing.T, opts struct {
	CommonName string
	SKI        []byte
	AKI        []byte
	NotBefore  time.Time
	NotAfter   time.Time
}) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		NotBefore:             opts.NotBefore,
		NotAfter:              opts.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if opts.SKI != nil {
		template.SubjectKeyId = opts.SKI
	}
	if opts.AKI != nil {
		template.AuthorityKeyId = opts.AKI
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

func TestComputeCertHash_Deterministic(t *testing.T) {
	// Fixed DER bytes for deterministic testing
	// This is a simple byte sequence that represents the same "certificate" data
	fixedDER := []byte("test certificate DER bytes for hashing")

	hash1 := ComputeCertHash(fixedDER)
	hash2 := ComputeCertHash(fixedDER)

	if !bytes.Equal(hash1, hash2) {
		t.Error("ComputeCertHash should produce deterministic results")
	}

	// Verify hash is 32 bytes (SHA-256)
	if len(hash1) != 32 {
		t.Errorf("Hash should be 32 bytes, got %d", len(hash1))
	}

	// Verify it matches expected SHA-256
	expected := sha256.Sum256(fixedDER)
	if !bytes.Equal(hash1, expected[:]) {
		t.Error("Hash should match SHA-256 computation")
	}
}

func TestComputeCertHash_DifferentInputs(t *testing.T) {
	der1 := []byte("certificate one")
	der2 := []byte("certificate two")

	hash1 := ComputeCertHash(der1)
	hash2 := ComputeCertHash(der2)

	if bytes.Equal(hash1, hash2) {
		t.Error("Different inputs should produce different hashes")
	}
}

func TestComputeChainHash_Deterministic(t *testing.T) {
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	hash3 := make([]byte, 32)

	// Fill with deterministic values
	for i := range hash1 {
		hash1[i] = byte(i)
		hash2[i] = byte(i + 32)
		hash3[i] = byte(i + 64)
	}

	chainHashes := [][]byte{hash1, hash2, hash3}

	result1 := ComputeChainHash(chainHashes)
	result2 := ComputeChainHash(chainHashes)

	if !bytes.Equal(result1, result2) {
		t.Error("ComputeChainHash should produce deterministic results")
	}

	// Verify result is 32 bytes
	if len(result1) != 32 {
		t.Errorf("Chain hash should be 32 bytes, got %d", len(result1))
	}
}

func TestComputeChainHash_OrderMatters(t *testing.T) {
	hashA := make([]byte, 32)
	hashB := make([]byte, 32)

	for i := range hashA {
		hashA[i] = byte(i)
		hashB[i] = byte(i + 100)
	}

	// Order [A, B]
	chain1 := [][]byte{hashA, hashB}
	// Order [B, A]
	chain2 := [][]byte{hashB, hashA}

	result1 := ComputeChainHash(chain1)
	result2 := ComputeChainHash(chain2)

	if bytes.Equal(result1, result2) {
		t.Error("Different order should produce different chain hashes")
	}
}

func TestComputeChainHash_DifferentLengths(t *testing.T) {
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)

	for i := range hash1 {
		hash1[i] = byte(i)
		hash2[i] = byte(i + 32)
	}

	// Chain with 1 cert
	chain1 := [][]byte{hash1}
	// Chain with 2 certs
	chain2 := [][]byte{hash1, hash2}

	result1 := ComputeChainHash(chain1)
	result2 := ComputeChainHash(chain2)

	if bytes.Equal(result1, result2) {
		t.Error("Chains of different lengths should produce different hashes")
	}
}

func TestComputeChainHash_EncodingFormat(t *testing.T) {
	// Test that the encoding format matches the specification:
	// 4 bytes count (big-endian) + 32 bytes per hash
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)

	for i := range hash1 {
		hash1[i] = 0x01
		hash2[i] = 0x02
	}

	chainHashes := [][]byte{hash1, hash2}

	// Manually construct the expected data
	expectedData := make([]byte, 4+32+32)
	binary.BigEndian.PutUint32(expectedData[0:4], 2)
	copy(expectedData[4:36], hash1)
	copy(expectedData[36:68], hash2)

	expectedHash := sha256.Sum256(expectedData)
	result := ComputeChainHash(chainHashes)

	if !bytes.Equal(result, expectedHash[:]) {
		t.Errorf("Chain hash encoding mismatch.\nExpected: %s\nGot: %s",
			hex.EncodeToString(expectedHash[:]),
			hex.EncodeToString(result))
	}
}

func TestComputeChainHash_Empty(t *testing.T) {
	// Empty chain should still produce a deterministic hash
	result1 := ComputeChainHash([][]byte{})
	result2 := ComputeChainHash([][]byte{})

	if !bytes.Equal(result1, result2) {
		t.Error("Empty chain should produce deterministic hash")
	}

	if len(result1) != 32 {
		t.Errorf("Empty chain hash should be 32 bytes, got %d", len(result1))
	}
}

func TestParseCertificate(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	notAfter := now.Add(365 * 24 * time.Hour)

	cert := generateTestCertificate(t, struct {
		CommonName string
		SKI        []byte
		AKI        []byte
		NotBefore  time.Time
		NotAfter   time.Time
	}{
		CommonName: "test.example.com",
		SKI:        []byte("subject-key-id-12345"),
		AKI:        []byte("authority-key-id-67890"),
		NotBefore:  now,
		NotAfter:   notAfter,
	})

	info, err := ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Verify hash is 32 bytes
	if len(info.CertHash) != 32 {
		t.Errorf("CertHash should be 32 bytes, got %d", len(info.CertHash))
	}

	// Verify PEM is not empty and contains expected header
	if info.PEM() == "" {
		t.Error("PEM should not be empty")
	}
	if !bytes.Contains([]byte(info.PEM()), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM should contain certificate header")
	}

	// Verify DER matches original
	if !bytes.Equal(info.DER, cert.Raw) {
		t.Error("DER should match original")
	}

	// Verify SKI was extracted
	if !bytes.Equal(info.SKI, []byte("subject-key-id-12345")) {
		t.Errorf("SKI mismatch: got %v", info.SKI)
	}

	// Verify AKI was extracted
	if !bytes.Equal(info.AKI, []byte("authority-key-id-67890")) {
		t.Errorf("AKI mismatch: got %v", info.AKI)
	}

	// Verify parsed certificate is available
	if info.Parsed == nil {
		t.Error("Parsed certificate should be available")
	}
}

func TestParseChain(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	// Generate a chain of 3 certificates
	certs := make([]*x509.Certificate, 3)
	for i := range certs {
		certs[i] = generateTestCertificate(t, struct {
			CommonName string
			SKI        []byte
			AKI        []byte
			NotBefore  time.Time
			NotAfter   time.Time
		}{
			CommonName: "cert-" + string(rune('a'+i)),
			NotBefore:  now,
			NotAfter:   now.Add(365 * 24 * time.Hour),
		})
	}

	chain := ParseChain(certs)

	if chain == nil {
		t.Fatal("ParseChain should not return nil")
	}

	// Verify depth
	if chain.Depth != 3 {
		t.Errorf("Depth should be 3, got %d", chain.Depth)
	}

	// Verify chain hash is 32 bytes
	if len(chain.ChainHash) != 32 {
		t.Errorf("ChainHash should be 32 bytes, got %d", len(chain.ChainHash))
	}

	// Verify leaf cert hash matches first cert
	if !bytes.Equal(chain.LeafCertHash, chain.Certs[0].CertHash) {
		t.Error("LeafCertHash should match first cert hash")
	}

	// Verify all certs are parsed
	if len(chain.Certs) != 3 {
		t.Errorf("Should have 3 cert infos, got %d", len(chain.Certs))
	}
}

func TestParseChain_Empty(t *testing.T) {
	chain := ParseChain([]*x509.Certificate{})
	if chain != nil {
		t.Error("ParseChain should return nil for empty chain")
	}
}

func TestParseChain_Nil(t *testing.T) {
	chain := ParseChain(nil)
	if chain != nil {
		t.Error("ParseChain should return nil for nil input")
	}
}

func TestChainToPEM(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	certs := make([]*x509.Certificate, 2)
	for i := range certs {
		certs[i] = generateTestCertificate(t, struct {
			CommonName string
			SKI        []byte
			AKI        []byte
			NotBefore  time.Time
			NotAfter   time.Time
		}{
			CommonName: "cert-" + string(rune('a'+i)),
			NotBefore:  now,
			NotAfter:   now.Add(365 * 24 * time.Hour),
		})
	}

	chain := ParseChain(certs)
	pemOutput := ChainToPEM(chain.Certs)

	// Should contain two certificate blocks
	if !bytes.Contains([]byte(pemOutput), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("PEM output should contain certificate header")
	}

	// Count certificate blocks
	count := 0
	for i := 0; i < len(pemOutput)-26; i++ {
		if pemOutput[i:i+27] == "-----BEGIN CERTIFICATE-----" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("Expected 2 certificate blocks, found %d", count)
	}
}
