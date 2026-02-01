package web

import (
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
	PEM       string
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
	IsCA                 bool
	HasPathLenConstraint bool
	PathLenConstraint    int
	SerialNumber         string
	SignatureAlgorithm   string
	PublicKeyInfo        string
	SANs                 []string
	KeyUsage             string
	ExtKeyUsage          string
	SKI                  string
	AKI                  string
	PossibleIssuers      []string
}

// ResultsViewData is the view model for the results template.
type ResultsViewData struct {
	Domain             string
	CSRFToken          string
	IsCached           bool
	CacheAge           string
	CanForceRefresh    bool
	RefreshAvailableIn string
	LastCrawlFailed    bool
	Chain              []*CertViewData
}

// certToViewData converts a CertificateResult to CertViewData.
func certToViewData(cert *CertificateResult) *CertViewData {
	view := &CertViewData{
		HashHex:            hex.EncodeToString(cert.CertHash),
		Position:           cert.Position,
		PEM:                cert.PEM,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		NotBeforeFormatted: cert.NotBefore.Format("Jan 02, 2006 15:04 UTC"),
		NotAfterFormatted:  cert.NotAfter.Format("Jan 02, 2006 15:04 UTC"),
		IsExpired:          time.Now().After(cert.NotAfter),
		IsNotYetValid:      time.Now().Before(cert.NotBefore),
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
	view.HasPathLenConstraint = cert.BasicConstraintsValid && cert.MaxPathLen >= 0
	view.PathLenConstraint = cert.MaxPathLen
	view.SerialNumber = formatSerialNumber(cert.SerialNumber.Bytes())
	view.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	view.PublicKeyInfo = formatPublicKey(cert)

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
		hex[i] = fmt.Sprintf("%02X", v)
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
		if cert.PublicKey != nil {
			// Try to get bit size
			if rsa, ok := cert.PublicKey.(interface{ Size() int }); ok {
				return fmt.Sprintf("RSA %d bits", rsa.Size()*8)
			}
		}
		return "RSA"
	case x509.ECDSA:
		if cert.PublicKey != nil {
			if ec, ok := cert.PublicKey.(interface{ Params() interface{ BitSize() int } }); ok {
				return fmt.Sprintf("ECDSA P-%d", ec.Params().BitSize())
			}
		}
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
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

func parsePEM(pem string) (*x509.Certificate, error) {
	info, err := certutil.ParseCertificate([]byte(pem))
	if err != nil {
		return nil, err
	}
	return info.Parsed, nil
}

func buildResultsViewData(result *DomainResult, csrfToken string, isCached bool, canForce bool, waitTime time.Duration, lastCrawlFailed bool) *ResultsViewData {
	data := &ResultsViewData{
		Domain:          result.Domain,
		CSRFToken:       csrfToken,
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

	return data
}
