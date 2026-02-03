// Package domain provides validation and normalization of domain names
// for TLS certificate crawling operations.
package domain

import (
	"errors"
	"strings"
)

var (
	// ErrReservedDomain indicates the domain is a reserved name per RFC 2606 or similar standards
	ErrReservedDomain = errors.New("reserved domain name")
	// ErrLocalDomain indicates the domain uses the .local TLD
	ErrLocalDomain = errors.New("local domain name")
	// ErrOnionDomain indicates the domain uses the .onion TLD
	ErrOnionDomain = errors.New("onion domain name")
)

// ReservedDomainInfo contains information about why a domain is reserved.
type ReservedDomainInfo struct {
	// Reason is a human-readable explanation of why the domain is reserved
	Reason string
	// RFCLink is an optional link to the relevant RFC
	RFCLink string
}

// reservedTLDs are TLDs reserved by RFC 2606 for testing and documentation.
// These will never resolve to real certificates.
// See: https://www.rfc-editor.org/rfc/rfc2606.html
var reservedTLDs = map[string]ReservedDomainInfo{
	"test": {
		Reason:  "The .test TLD is reserved for testing purposes and will never be registered.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
	"example": {
		Reason:  "The .example TLD is reserved for documentation and examples.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
	"invalid": {
		Reason:  "The .invalid TLD is reserved to indicate invalid domain names.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
	"localhost": {
		Reason:  "The .localhost TLD is reserved for loopback addresses.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
}

// reservedSecondLevelDomains are second-level domains reserved by RFC 2606.
var reservedSecondLevelDomains = map[string]ReservedDomainInfo{
	"example.com": {
		Reason:  "example.com is reserved for documentation and examples.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
	"example.net": {
		Reason:  "example.net is reserved for documentation and examples.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
	"example.org": {
		Reason:  "example.org is reserved for documentation and examples.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc2606.html",
	},
}

// specialTLDs are TLDs that have special purposes and should not be crawled.
var specialTLDs = map[string]ReservedDomainInfo{
	"local": {
		Reason:  "The .local TLD is used for local network services (mDNS) and cannot be resolved over the public internet.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc6762.html",
	},
	"onion": {
		Reason:  "The .onion TLD is used for Tor hidden services and requires the Tor network to access.",
		RFCLink: "https://www.rfc-editor.org/rfc/rfc7686.html",
	},
}

// CheckReservedDomain checks if a domain is reserved and should not be crawled.
// Returns nil if the domain is not reserved, otherwise returns information about why.
func CheckReservedDomain(domain string) *ReservedDomainInfo {
	if domain == "" {
		return nil
	}

	// Normalize to lowercase
	domain = strings.ToLower(domain)

	// Extract TLD (last label)
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return nil
	}
	tld := labels[len(labels)-1]

	// Check reserved TLDs (RFC 2606)
	if info, ok := reservedTLDs[tld]; ok {
		return &info
	}

	// Check special TLDs (.local, .onion)
	if info, ok := specialTLDs[tld]; ok {
		return &info
	}

	// Check reserved second-level domains (RFC 2606)
	// Extract the base domain (last two labels)
	if len(labels) >= 2 {
		baseDomain := labels[len(labels)-2] + "." + labels[len(labels)-1]
		if info, ok := reservedSecondLevelDomains[baseDomain]; ok {
			return &info
		}
	}

	// Also check if the domain itself is a reserved second-level domain
	if info, ok := reservedSecondLevelDomains[domain]; ok {
		return &info
	}

	return nil
}

// IsReservedDomain returns true if the domain is reserved and should not be crawled.
func IsReservedDomain(domain string) bool {
	return CheckReservedDomain(domain) != nil
}
