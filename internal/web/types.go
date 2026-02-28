package web

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
)

// DomainResult represents domain data from the database.
type DomainResult struct {
	Domain    string
	HasChain  bool
	Chain     []*CertificateResult
	UpdatedAt time.Time
}

// CertificateResult represents certificate data from the database.
type CertificateResult struct {
	CertHash  []byte
	DER       []byte
	PEM       string
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	SKI       []byte
	AKI       []byte
	Position  int
	Parsed    *x509.Certificate
}

// CrawlOutput represents the output of a crawl operation.
type CrawlOutput struct {
	Domain string
	Chain  []*CertificateResult
}

// CrawlResultInput is the input for recording a crawl result.
type CrawlResultInput struct {
	Domain  string
	Success bool
	Forced  bool
	Chain   []*CertificateResult
}

// CertViewData is the view model for certificate display.
type CertViewData struct {
	HashHex              string
	Position             int
	PEM                  string
	SubjectCN            string
	SubjectDN            string
	IssuerDN             string
	NotBeforeFormatted   string
	NotAfterFormatted    string
	NotBefore            time.Time
	NotAfter             time.Time
	IsExpired            bool
	IsNotYetValid        bool
	ValidityDays         int
	ExpiresIn            string
	IsCA                 bool
	IsSelfSigned         bool
	HasPathLenConstraint bool
	PathLenConstraint    int
	SerialNumber         string
	SignatureAlgorithm   string
	PublicKeyInfo        string
	KeyLength            string
	SANs                 []string
	KeyUsage             string
	ExtKeyUsage          string
	SKI                  string
	AKI                  string
	SHA1Fingerprint      string
	SHA256Fingerprint    string
	PossibleIssuers      []string
	// CertLabel is the human-readable label for this certificate's role in the chain
	CertLabel string
	// SubjectColor is the CSS color class for the subject DN
	SubjectColor string
	// IssuerColor is the CSS color class for the issuer DN
	IssuerColor string
}

// ResultsViewData is the view model for the results template.
type ResultsViewData struct {
	Domain             string
	IsCached           bool
	CacheAge           string
	CanForceRefresh    bool
	RefreshAvailableIn string
	LastCrawlFailed    bool
	Chain              []*CertViewData
	// ChainGraph is the certificate trust path graph for the chain visualization section.
	ChainGraph *ChainGraphData
}

// certToViewData converts a CertificateResult to CertViewData.
func certToViewData(cert *CertificateResult) *CertViewData {
	now := time.Now()
	view := &CertViewData{
		HashHex:            hex.EncodeToString(cert.CertHash),
		Position:           cert.Position,
		PEM:                cert.PEM,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		NotBeforeFormatted: cert.NotBefore.Format("Jan 02, 2006 15:04 UTC"),
		NotAfterFormatted:  cert.NotAfter.Format("Jan 02, 2006 15:04 UTC"),
		IsExpired:          now.After(cert.NotAfter),
		IsNotYetValid:      now.Before(cert.NotBefore),
		ValidityDays:       int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24),
		ExpiresIn:          formatCertDuration(cert.NotAfter.Sub(now)),
	}

	if len(cert.SKI) > 0 {
		view.SKI = formatHexBytes(cert.SKI)
	}
	if len(cert.AKI) > 0 {
		view.AKI = formatHexBytes(cert.AKI)
	}

	// Parse certificate for additional details
	if cert.Parsed != nil {
		populateFromParsedCert(view, cert.Parsed)
	} else if cert.PEM != "" {
		// Try to parse from PEM
		if parsed, err := parsePEM(cert.PEM); err == nil {
			populateFromParsedCert(view, parsed)
		}
	}

	return view
}

func populateFromParsedCert(view *CertViewData, cert *x509.Certificate) {
	view.SubjectCN = extractCN(cert.Subject.String())
	view.SubjectDN = cert.Subject.String()
	view.IssuerDN = cert.Issuer.String()
	view.IsCA = cert.IsCA
	view.IsSelfSigned = isSelfSigned(cert)
	view.HasPathLenConstraint = cert.BasicConstraintsValid && cert.MaxPathLen >= 0
	view.PathLenConstraint = cert.MaxPathLen
	view.SerialNumber = formatSerialNumber(cert.SerialNumber.Bytes())
	view.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	view.PublicKeyInfo = formatPublicKey(cert)
	view.KeyLength = formatKeyLength(cert)

	// Subject Alternative Names
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		for _, name := range cert.DNSNames {
			view.SANs = append(view.SANs, "DNS:"+name)
		}
		for _, ip := range cert.IPAddresses {
			view.SANs = append(view.SANs, "IP:"+ip.String())
		}
		for _, email := range cert.EmailAddresses {
			view.SANs = append(view.SANs, "Email:"+email)
		}
	}

	// Key Usage
	view.KeyUsage = formatKeyUsage(cert.KeyUsage)

	// Extended Key Usage
	view.ExtKeyUsage = formatExtKeyUsage(cert.ExtKeyUsage)

	// Fingerprints computed from raw DER bytes
	if len(cert.Raw) > 0 {
		sha1Sum := sha1.Sum(cert.Raw)
		view.SHA1Fingerprint = formatHexBytes(sha1Sum[:])
		sha256Sum := sha256.Sum256(cert.Raw)
		view.SHA256Fingerprint = formatHexBytes(sha256Sum[:])
	}
}

func extractCN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return dn
}

func formatHexBytes(b []byte) string {
	hex := make([]string, len(b))
	for i, v := range b {
		hex[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(hex, ":")
}

func formatSerialNumber(b []byte) string {
	hex := make([]string, len(b))
	for i, v := range b {
		hex[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(hex, ":")
}

func formatPublicKey(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return fmt.Sprintf("RSA %d bits", pub.N.BitLen())
		}
		return "RSA"
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
		}
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func formatKeyLength(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return fmt.Sprintf("%d bits", pub.N.BitLen())
		}
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return fmt.Sprintf("%d bits", pub.Curve.Params().BitSize)
		}
	case x509.Ed25519:
		if _, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			return "256 bits"
		}
	}
	return ""
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return strings.Join(usages, ", ")
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) string {
	var usages []string
	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return strings.Join(usages, ", ")
}

// formatCertDuration formats a duration for certificate context using an
// appropriate combination of years, months, and days.
func formatCertDuration(d time.Duration) string {
	totalDays := int(d.Hours() / 24)
	if totalDays < 0 {
		totalDays = -totalDays
	}
	if totalDays == 0 {
		return "less than a day"
	}

	years := totalDays / 365
	remaining := totalDays % 365
	months := remaining / 30
	days := remaining % 30

	var parts []string
	if years > 0 {
		if years == 1 {
			parts = append(parts, "1 year")
		} else {
			parts = append(parts, fmt.Sprintf("%d years", years))
		}
	}
	if months > 0 {
		if months == 1 {
			parts = append(parts, "1 month")
		} else {
			parts = append(parts, fmt.Sprintf("%d months", months))
		}
	}
	if days > 0 && years == 0 {
		if days == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", days))
		}
	}

	if len(parts) == 0 {
		if totalDays == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", totalDays)
	}

	return strings.Join(parts, ", ")
}

func parsePEM(pem string) (*x509.Certificate, error) {
	info, err := certutil.ParseCertificate([]byte(pem))
	if err != nil {
		return nil, err
	}
	return info.Parsed, nil
}

// isSelfSigned checks if a certificate is self-signed by comparing Subject and Issuer.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

// chainColorPalette defines the colors used for matching subject/issuer pairs.
// These colors are compatible with the dark theme.
var chainColorPalette = []string{
	"chain-color-1", // teal
	"chain-color-2", // purple
	"chain-color-3", // blue
	"chain-color-4", // pink
	"chain-color-5", // green
}

// assignChainLabelsAndColors assigns labels and color classes to certificates in a chain.
func assignChainLabelsAndColors(chain []*CertViewData) {
	if len(chain) == 0 {
		return
	}

	// Build a map of SubjectDN to color class
	dnColorMap := make(map[string]string)
	colorIndex := 0

	// First pass: assign colors to all unique SubjectDNs
	for _, cert := range chain {
		if _, exists := dnColorMap[cert.SubjectDN]; !exists {
			dnColorMap[cert.SubjectDN] = chainColorPalette[colorIndex%len(chainColorPalette)]
			colorIndex++
		}
	}

	// Second pass: assign colors to subject and issuer, and determine labels
	for i, cert := range chain {
		// Assign subject color
		cert.SubjectColor = dnColorMap[cert.SubjectDN]

		// Assign issuer color (if issuer matches a subject in the chain)
		if color, exists := dnColorMap[cert.IssuerDN]; exists {
			cert.IssuerColor = color
		}

		// Determine the certificate label
		if i == 0 {
			// First certificate in chain (server/leaf certificate)
			if cert.IsSelfSigned {
				cert.CertLabel = "Self Signed Server Certificate"
			} else {
				cert.CertLabel = "Server Certificate"
			}
		} else {
			// Not the first certificate
			if cert.IsSelfSigned {
				cert.CertLabel = "Root CA"
			} else if cert.IsCA {
				cert.CertLabel = "Intermediate CA"
			} else {
				cert.CertLabel = fmt.Sprintf("Certificate #%d", i)
			}
		}
	}
}

func buildResultsViewData(result *DomainResult, isCached bool, canForce bool, waitTime time.Duration, lastCrawlFailed bool) *ResultsViewData {
	data := &ResultsViewData{
		Domain:          result.Domain,
		IsCached:        isCached,
		CanForceRefresh: canForce,
		LastCrawlFailed: lastCrawlFailed,
	}

	if isCached && !result.UpdatedAt.IsZero() {
		age := time.Since(result.UpdatedAt)
		data.CacheAge = formatDuration(age) + " ago"
	}

	if !canForce && waitTime > 0 {
		data.RefreshAvailableIn = formatDuration(waitTime)
	}

	for _, cert := range result.Chain {
		data.Chain = append(data.Chain, certToViewData(cert))
	}

	// Assign labels and colors to the chain
	assignChainLabelsAndColors(data.Chain)

	return data
}
