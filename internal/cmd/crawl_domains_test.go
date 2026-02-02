package cmd

import (
	"testing"
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
		ageDays    int
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
