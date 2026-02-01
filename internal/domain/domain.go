// Package domain provides validation and normalization of domain names
// for TLS certificate crawling operations.
package domain

import (
	"errors"
	"regexp"
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
	// Normalize: trim whitespace
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", ErrEmptyDomain
	}

	// Check for control characters before any other processing
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", ErrDomainControlChars
		}
	}

	// Check for whitespace in the middle
	if strings.ContainsAny(trimmed, " \t\n\r") {
		return "", ErrDomainInvalidChars
	}

	// Check for URL scheme
	if schemePattern.MatchString(trimmed) {
		return "", ErrDomainHasScheme
	}

	// Also check for common schemes without the full regex (e.g., "http://", "https://")
	lowerTrimmed := strings.ToLower(trimmed)
	if strings.HasPrefix(lowerTrimmed, "http://") ||
		strings.HasPrefix(lowerTrimmed, "https://") ||
		strings.HasPrefix(lowerTrimmed, "ftp://") {
		return "", ErrDomainHasScheme
	}

	// Check for path (contains /)
	if strings.Contains(trimmed, "/") {
		return "", ErrDomainHasPath
	}

	// Check for query string
	if strings.Contains(trimmed, "?") {
		return "", ErrDomainHasQuery
	}

	// Check for port (contains :)
	if strings.Contains(trimmed, ":") {
		return "", ErrDomainHasPort
	}

	// Normalize: convert to lowercase
	normalized := strings.ToLower(trimmed)

	// Check for trailing dot
	if strings.HasSuffix(normalized, ".") {
		return "", ErrDomainTrailingDot
	}

	// Check total length
	if len(normalized) > 253 {
		return "", ErrDomainTooLong
	}

	// Validate each label
	labels := strings.Split(normalized, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return "", ErrDomainInvalidLabel
		}
		if len(label) > 63 {
			return "", ErrDomainLabelTooLong
		}

		// Check that label matches valid hostname pattern
		if len(label) == 1 {
			if !singleCharLabel.MatchString(label) {
				return "", ErrDomainInvalidChars
			}
		} else {
			if !validHostnameChars.MatchString(label) {
				return "", ErrDomainInvalidChars
			}
		}

		// Labels cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrDomainInvalidLabel
		}
	}

	return normalized, nil
}
