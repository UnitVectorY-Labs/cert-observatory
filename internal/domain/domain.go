// Package domain provides validation and normalization of domain names
// for TLS certificate crawling operations.
package domain

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	// ErrEmptyDomain indicates the domain string is empty or only whitespace
	ErrEmptyDomain = errors.New("domain is empty")
	// ErrDomainTooLong indicates the domain exceeds 253 characters
	ErrDomainTooLong = errors.New("domain exceeds maximum length of 253 characters")
	// ErrDomainHasScheme indicates the input contains a URL scheme
	ErrDomainHasScheme = errors.New("domain must not contain a URL scheme (e.g., https://)")
	// ErrDomainHasPort indicates the input contains a port specification
	ErrDomainHasPort = errors.New("domain must not contain a port")
	// ErrInvalidPort indicates the input contains an invalid port specification
	ErrInvalidPort = errors.New("invalid port")
	// ErrDomainHasPath indicates the input contains a path
	ErrDomainHasPath = errors.New("domain must not contain a path")
	// ErrDomainHasQuery indicates the input contains a query string
	ErrDomainHasQuery = errors.New("domain must not contain a query string")
	// ErrDomainTrailingDot indicates the domain ends with a trailing dot
	ErrDomainTrailingDot = errors.New("domain must not end with a trailing dot")
	// ErrDomainInvalidChars indicates the domain contains invalid characters
	ErrDomainInvalidChars = errors.New("domain contains invalid characters")
	// ErrDomainControlChars indicates the domain contains control characters
	ErrDomainControlChars = errors.New("domain contains control characters")
	// ErrDomainInvalidLabel indicates a label within the domain is invalid
	ErrDomainInvalidLabel = errors.New("domain contains an invalid label")
	// ErrDomainLabelTooLong indicates a label exceeds 63 characters
	ErrDomainLabelTooLong = errors.New("domain label exceeds maximum length of 63 characters")
)

const DefaultPort = 443

// Target is a normalized TLS crawl target.
type Target struct {
	Domain string
	Port   int
}

// validHostnameChars matches valid hostname characters (alphanumeric, hyphen)
var validHostnameChars = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// singleCharLabel matches a single alphanumeric character
var singleCharLabel = regexp.MustCompile(`^[a-z0-9]$`)

// schemePattern detects URL schemes
var schemePattern = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)

// NormalizeAndValidate takes a raw domain input, normalizes it, and validates
// it according to the requirements. Returns the normalized domain or an error.
//
// Normalization rules:
//   - Trim surrounding whitespace
//   - Convert to lowercase
//
// Validation rules:
//   - Must not be empty (after trimming)
//   - Must not exceed 253 characters
//   - Must not contain URL scheme (e.g., https://)
//   - Must not contain port specification
//   - Must not contain path components
//   - Must not contain query strings
//   - Must not end with trailing dot
//   - Must not contain control characters or whitespace
//   - Must contain only valid hostname characters
//   - Each label must be 1-63 characters
func NormalizeAndValidate(input string) (string, error) {
	target, err := NormalizeAndValidateTarget(input, false)
	if err != nil {
		return "", err
	}
	return target.Domain, nil
}

// NormalizeAndValidateTarget takes a raw domain input, normalizes it, and
// validates it as a TLS target. When allowPort is true, the input may include a
// numeric port using host:port syntax.
func NormalizeAndValidateTarget(input string, allowPort bool) (*Target, error) {
	// Normalize: trim whitespace
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, ErrEmptyDomain
	}

	// Check for control characters before any other processing
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return nil, ErrDomainControlChars
		}
	}

	// Check for whitespace in the middle
	if strings.ContainsAny(trimmed, " \t\n\r") {
		return nil, ErrDomainInvalidChars
	}

	// Check for URL scheme
	if schemePattern.MatchString(trimmed) {
		return nil, ErrDomainHasScheme
	}

	// Also check for common schemes without the full regex (e.g., "http://", "https://")
	lowerTrimmed := strings.ToLower(trimmed)
	if strings.HasPrefix(lowerTrimmed, "http://") ||
		strings.HasPrefix(lowerTrimmed, "https://") ||
		strings.HasPrefix(lowerTrimmed, "ftp://") {
		return nil, ErrDomainHasScheme
	}

	// Check for path (contains /)
	if strings.Contains(trimmed, "/") {
		return nil, ErrDomainHasPath
	}

	// Check for query string
	if strings.Contains(trimmed, "?") {
		return nil, ErrDomainHasQuery
	}

	port := DefaultPort

	if strings.Contains(trimmed, ":") {
		if !allowPort {
			return nil, ErrDomainHasPort
		}
		host, parsedPort, err := splitHostPort(trimmed)
		if err != nil {
			return nil, err
		}
		trimmed = host
		port = parsedPort
	}

	// Normalize: convert to lowercase
	normalized := strings.ToLower(trimmed)

	// Check for trailing dot
	if strings.HasSuffix(normalized, ".") {
		return nil, ErrDomainTrailingDot
	}

	// Check total length
	if len(normalized) > 253 {
		return nil, ErrDomainTooLong
	}

	// Validate each label
	labels := strings.SplitSeq(normalized, ".")
	for label := range labels {
		if len(label) == 0 {
			return nil, ErrDomainInvalidLabel
		}
		if len(label) > 63 {
			return nil, ErrDomainLabelTooLong
		}

		// Check that label matches valid hostname pattern
		if len(label) == 1 {
			if !singleCharLabel.MatchString(label) {
				return nil, ErrDomainInvalidChars
			}
		} else {
			if !validHostnameChars.MatchString(label) {
				return nil, ErrDomainInvalidChars
			}
		}

		// Labels cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return nil, ErrDomainInvalidLabel
		}
	}

	return &Target{Domain: normalized, Port: port}, nil
}

func splitHostPort(input string) (string, int, error) {
	if strings.Count(input, ":") != 1 {
		return "", 0, ErrDomainHasPort
	}

	parts := strings.SplitN(input, ":", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", 0, ErrInvalidPort
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, ErrInvalidPort
	}

	return parts[0], port, nil
}
