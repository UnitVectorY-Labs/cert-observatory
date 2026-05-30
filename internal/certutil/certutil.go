// Package certutil provides utilities for parsing, hashing, and encoding
// X.509 certificates for the cert-observatory application.
package certutil

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"time"
)

// CertInfo contains extracted information from a certificate.
type CertInfo struct {
	// CertHash is the SHA-256 hash of the DER-encoded certificate (32 bytes)
	CertHash []byte
	// DER is the raw DER-encoded certificate
	DER []byte
	// Subject is the certificate subject distinguished name (RFC 2253 format)
	Subject string
	// Issuer is the certificate issuer distinguished name (RFC 2253 format)
	Issuer string
	// NotBefore is the certificate validity start time
	NotBefore time.Time
	// NotAfter is the certificate validity end time
	NotAfter time.Time
	// SKI is the Subject Key Identifier, if present
	SKI []byte
	// AKI is the Authority Key Identifier, if present
	AKI []byte
	// Parsed is the parsed x509.Certificate for additional access
	Parsed *x509.Certificate
}

// PEM returns the PEM-encoded certificate (computed on demand from DER)
func (c *CertInfo) PEM() string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.DER,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// ParseCertificate parses a DER-encoded certificate and extracts relevant information.
func ParseCertificate(der []byte) (*CertInfo, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return ParseX509Certificate(cert), nil
}

// ParseX509Certificate extracts information from an already-parsed x509.Certificate.
func ParseX509Certificate(cert *x509.Certificate) *CertInfo {
	der := cert.Raw
	hash := sha256.Sum256(der)

	info := &CertInfo{
		CertHash:  hash[:],
		DER:       der,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Parsed:    cert,
	}

	// Extract Subject Key Identifier if present
	if len(cert.SubjectKeyId) > 0 {
		info.SKI = cert.SubjectKeyId
	}

	// Extract Authority Key Identifier if present
	if len(cert.AuthorityKeyId) > 0 {
		info.AKI = cert.AuthorityKeyId
	}

	return info
}

// ComputeCertHash computes the SHA-256 hash of a DER-encoded certificate.
func ComputeCertHash(der []byte) []byte {
	hash := sha256.Sum256(der)
	return hash[:]
}

// ComputeChainHash computes a deterministic hash for an ordered list of certificate hashes.
//
// Encoding format (version 1):
// - 4 bytes: number of certificates (big-endian uint32)
// - For each certificate: 32 bytes of cert_hash
//
// This format is stable, deterministic, and unambiguous.
func ComputeChainHash(certHashes [][]byte) []byte {
	// Calculate total size: 4 (count) + 32 * len(certHashes)
	size := 4 + 32*len(certHashes)
	data := make([]byte, size)

	// Write count as big-endian uint32
	binary.BigEndian.PutUint32(data[0:4], uint32(len(certHashes)))

	// Write each hash
	offset := 4
	for _, hash := range certHashes {
		copy(data[offset:offset+32], hash)
		offset += 32
	}

	// Hash the concatenated data
	result := sha256.Sum256(data)
	return result[:]
}

// ChainInfo contains information about a certificate chain.
type ChainInfo struct {
	// ChainHash is the SHA-256 hash of the ordered certificate hashes
	ChainHash []byte
	// LeafCertHash is the hash of the first certificate (leaf)
	LeafCertHash []byte
	// Depth is the number of certificates in the chain
	Depth int
	// Certs contains the parsed information for each certificate
	Certs []*CertInfo
	// CertHashes contains the ordered list of certificate hashes
	CertHashes [][]byte
}

// ParseChain parses a chain of x509.Certificates and computes chain information.
func ParseChain(certs []*x509.Certificate) *ChainInfo {
	if len(certs) == 0 {
		return nil
	}

	certInfos := make([]*CertInfo, len(certs))
	certHashes := make([][]byte, len(certs))

	for i, cert := range certs {
		info := ParseX509Certificate(cert)
		certInfos[i] = info
		certHashes[i] = info.CertHash
	}

	return &ChainInfo{
		ChainHash:    ComputeChainHash(certHashes),
		LeafCertHash: certHashes[0],
		Depth:        len(certs),
		Certs:        certInfos,
		CertHashes:   certHashes,
	}
}

// ChainToPEM returns the PEM-encoded representation of all certificates in the chain.
func ChainToPEM(certs []*CertInfo) string {
	var result strings.Builder
	for _, cert := range certs {
		result.WriteString(cert.PEM())
	}
	return result.String()
}

// DERToPEM converts DER-encoded certificate bytes to PEM format.
func DERToPEM(der []byte) string {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(pemBlock))
}
