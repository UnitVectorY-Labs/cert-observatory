// Package distrust collects explicit platform distrust rules. It does not perform
// general certificate revocation or browser path validation.
package distrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

const OneCRL = "mozilla_onecrl"
const CCADB = "ccadb"
const OneCRLURL = "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records"
const CCADBURL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV5"

// Rule preserves a source's matching method, rather than requiring the certificate
// to have already been observed. Serial numbers are unsigned, big-endian integers.
type Rule struct {
	Source, SourceRecordID, Platform, Status, MatchType                           string
	CertificateSHA256, IssuerNameDER, SerialNumber, SubjectNameDER, PublicKeyHash []byte
	Reason, ReferenceURL                                                          string
	EffectiveAt                                                                   *time.Time
	FirstSeenAt, LastSeenAt                                                       time.Time
	WithdrawnAt                                                                   *time.Time
}

func (r Rule) Validate() error {
	if r.Source != OneCRL && r.Source != CCADB {
		return fmt.Errorf("unknown source %q", r.Source)
	}
	if r.SourceRecordID == "" {
		return fmt.Errorf("missing source record ID")
	}
	switch r.Platform {
	case "mozilla", "apple", "chrome", "microsoft":
	default:
		return fmt.Errorf("unknown platform %q", r.Platform)
	}
	switch r.Status {
	case "blocked", "disabled", "removed":
	default:
		return fmt.Errorf("unknown status %q", r.Status)
	}
	switch r.MatchType {
	case "certificate_sha256":
		if len(r.CertificateSHA256) != 32 || len(r.IssuerNameDER)+len(r.SerialNumber)+len(r.SubjectNameDER)+len(r.PublicKeyHash) != 0 {
			return fmt.Errorf("invalid fingerprint rule")
		}
	case "issuer_serial":
		if len(r.IssuerNameDER) == 0 || len(r.SerialNumber) == 0 || len(r.CertificateSHA256)+len(r.SubjectNameDER)+len(r.PublicKeyHash) != 0 {
			return fmt.Errorf("invalid issuer/serial rule")
		}
	case "subject_public_key_hash":
		if len(r.SubjectNameDER) == 0 || len(r.PublicKeyHash) != 32 || len(r.CertificateSHA256)+len(r.IssuerNameDER)+len(r.SerialNumber) != 0 {
			return fmt.Errorf("invalid subject/key rule")
		}
	default:
		return fmt.Errorf("unknown match type %q", r.MatchType)
	}
	return nil
}

func (r Rule) Matches(c *x509.Certificate, now time.Time) bool {
	if c == nil || !c.IsCA || r.WithdrawnAt != nil || (r.EffectiveAt != nil && now.Before(*r.EffectiveAt)) {
		return false
	}
	switch r.MatchType {
	case "certificate_sha256":
		h := sha256.Sum256(c.Raw)
		return bytes.Equal(r.CertificateSHA256, h[:])
	case "issuer_serial":
		return c.SerialNumber != nil && bytes.Equal(r.IssuerNameDER, c.RawIssuer) && bytes.Equal(r.SerialNumber, c.SerialNumber.Bytes())
	case "subject_public_key_hash":
		// Mozilla hashes the full DER SubjectPublicKeyInfo, not the BIT STRING alone.
		h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		return bytes.Equal(r.SubjectNameDER, c.RawSubject) && bytes.Equal(r.PublicKeyHash, h[:])
	}
	return false
}

// SourceLabel is the display name of the evidence provider.
func (r Rule) SourceLabel() string {
	if r.Source == OneCRL {
		return "Mozilla OneCRL"
	}
	return "CCADB"
}

func (r Rule) Label() string {
	platform := map[string]string{"mozilla": "Mozilla", "apple": "Apple", "chrome": "Chrome", "microsoft": "Microsoft"}[r.Platform]
	if r.Status == "removed" {
		return "Removed from " + platform + " root store"
	}
	return strings.ToUpper(r.Status[:1]) + r.Status[1:] + " by " + platform
}

// SourceState is separate from individual rules, so an unchanged feed can be fresh.
type SourceState struct {
	Source           string
	LastAttemptedAt  time.Time
	LastSuccessfulAt *time.Time
	ActiveRules      int
	LastError        string
}

func (s SourceState) Stale(now time.Time) bool {
	age := 48 * time.Hour
	if s.Source == OneCRL {
		age = 2 * time.Hour
	}
	return s.LastSuccessfulAt == nil || now.Sub(*s.LastSuccessfulAt) > age || s.LastError != ""
}

type Snapshot struct {
	Rules   []Rule
	Sources []SourceState
}
