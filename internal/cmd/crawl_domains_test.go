package cmd

import (
	"testing"
	"time"
)

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected string
	}{
		{
			name:     "timeout error",
			errMsg:   "connection timeout",
			expected: "timeout",
		},
		{
			name:     "connection refused",
			errMsg:   "dial tcp: connection refused",
			expected: "connection_refused",
		},
		{
			name:     "DNS error",
			errMsg:   "no such host",
			expected: "dns_error",
		},
		{
			name:     "handshake failure",
			errMsg:   "tls handshake failed",
			expected: "handshake_failure",
		},
		{
			name:     "certificate error",
			errMsg:   "certificate verification failed",
			expected: "certificate_error",
		},
		{
			name:     "network error",
			errMsg:   "network is unreachable",
			expected: "network_error",
		},
		{
			name:     "unknown error",
			errMsg:   "some other error",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeError(&testError{tt.errMsg})
			if result != tt.expected {
				t.Errorf("categorizeError(%q) = %q, want %q", tt.errMsg, result, tt.expected)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestEffectiveAgeCalculationForCrawlDomains(t *testing.T) {
	tests := []struct {
		ageDays       int
		expectedHours int
	}{
		{1, 23},   // 1 day = 23 hours
		{2, 47},   // 2 days = 47 hours
		{7, 167},  // 7 days = 6 days 23 hours = 167 hours
		{30, 719}, // 30 days = 29 days 23 hours = 719 hours
	}

	for _, tt := range tests {
		cfg := &CrawlDomainsConfig{AgeDays: tt.ageDays}
		effectiveHours := (cfg.AgeDays * 24) - 1

		if effectiveHours != tt.expectedHours {
			t.Errorf("effectiveAge for %d days = %d hours, want %d hours",
				tt.ageDays, effectiveHours, tt.expectedHours)
		}
	}
}

func TestDefaultCrawlDomainsConfig(t *testing.T) {
	cfg := DefaultCrawlDomainsConfig()

	if cfg.AgeDays != 1 {
		t.Errorf("AgeDays = %d, want 1", cfg.AgeDays)
	}

	if cfg.Parallel != 2 {
		t.Errorf("Parallel = %d, want 2", cfg.Parallel)
	}

	if cfg.Rate != -1 {
		t.Errorf("Rate = %d, want -1", cfg.Rate)
	}

	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", cfg.Timeout)
	}

	if cfg.MaxCrawlSize != 100 {
		t.Errorf("MaxCrawlSize = %d, want 100", cfg.MaxCrawlSize)
	}

	if cfg.IgnoreErrors {
		t.Errorf("IgnoreErrors = %v, want false", cfg.IgnoreErrors)
	}

	if cfg.IncludeNonPublic {
		t.Errorf("IncludeNonPublic = %v, want false", cfg.IncludeNonPublic)
	}
}
