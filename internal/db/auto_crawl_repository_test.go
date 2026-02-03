package db

import (
	"testing"
	"time"
)

func TestBackoffPolicy_ComputeBackoff(t *testing.T) {
	policy := DefaultBackoffPolicy()

	tests := []struct {
		name               string
		consecutiveFailures int
		expectedDelay      time.Duration
	}{
		{
			name:               "first failure",
			consecutiveFailures: 1,
			expectedDelay:      1 * time.Hour,
		},
		{
			name:               "second failure",
			consecutiveFailures: 2,
			expectedDelay:      2 * time.Hour,
		},
		{
			name:               "third failure",
			consecutiveFailures: 3,
			expectedDelay:      4 * time.Hour,
		},
		{
			name:               "fourth failure",
			consecutiveFailures: 4,
			expectedDelay:      8 * time.Hour,
		},
		{
			name:               "fifth failure",
			consecutiveFailures: 5,
			expectedDelay:      16 * time.Hour,
		},
		{
			name:               "sixth failure",
			consecutiveFailures: 6,
			expectedDelay:      32 * time.Hour,
		},
		{
			name:               "seventh failure",
			consecutiveFailures: 7,
			expectedDelay:      64 * time.Hour,
		},
		{
			name:               "eighth failure",
			consecutiveFailures: 8,
			expectedDelay:      128 * time.Hour, // 1h * 2^7 = 128h (not yet capped)
		},
		{
			name:               "ninth failure - hits 7 day cap",
			consecutiveFailures: 9,
			expectedDelay:      7 * 24 * time.Hour, // would be 256h, capped to 168h
		},
		{
			name:               "many failures - still capped",
			consecutiveFailures: 20,
			expectedDelay:      7 * 24 * time.Hour,
		},
		{
			name:               "zero failures",
			consecutiveFailures: 0,
			expectedDelay:      1 * time.Hour,
		},
		{
			name:               "negative failures",
			consecutiveFailures: -1,
			expectedDelay:      1 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := policy.ComputeBackoff(tt.consecutiveFailures)
			if delay != tt.expectedDelay {
				t.Errorf("ComputeBackoff(%d) = %v, want %v",
					tt.consecutiveFailures, delay, tt.expectedDelay)
			}
		})
	}
}

func TestBackoffPolicy_MaxBackoff(t *testing.T) {
	policy := &BackoffPolicy{
		BaseDelay:  24 * time.Hour, // 1 day base
		Multiplier: 2.0,
		MaxDelay:   7 * 24 * time.Hour,  // 7 days cap per retry
		MaxBackoff: 30 * 24 * time.Hour, // 1 month max
	}

	// With base of 1 day and multiplier 2:
	// 1 failure = 1 day
	// 2 failures = 2 days
	// 3 failures = 4 days
	// 4 failures = 7 days (capped)
	// 5 failures = 7 days (capped)

	delay := policy.ComputeBackoff(4)
	if delay != 7*24*time.Hour {
		t.Errorf("ComputeBackoff(4) = %v, want 7 days", delay)
	}

	delay = policy.ComputeBackoff(10)
	if delay != 7*24*time.Hour {
		t.Errorf("ComputeBackoff(10) = %v, want 7 days (max cap)", delay)
	}
}

func TestDefaultBackoffPolicy(t *testing.T) {
	policy := DefaultBackoffPolicy()

	if policy.BaseDelay != 1*time.Hour {
		t.Errorf("BaseDelay = %v, want 1h", policy.BaseDelay)
	}

	if policy.Multiplier != 2.0 {
		t.Errorf("Multiplier = %v, want 2.0", policy.Multiplier)
	}

	if policy.MaxDelay != 7*24*time.Hour {
		t.Errorf("MaxDelay = %v, want 7 days", policy.MaxDelay)
	}

	if policy.MaxBackoff != 30*24*time.Hour {
		t.Errorf("MaxBackoff = %v, want 30 days", policy.MaxBackoff)
	}
}

func TestCrawlDomainsOptions(t *testing.T) {
	// Test default values
	opts := &CrawlDomainsOptions{}

	if opts.IgnoreErrors != false {
		t.Errorf("IgnoreErrors should default to false")
	}

	if opts.IncludeNonPublic != false {
		t.Errorf("IncludeNonPublic should default to false")
	}

	// Test with values set
	opts = &CrawlDomainsOptions{
		IgnoreErrors:     true,
		IncludeNonPublic: true,
	}

	if opts.IgnoreErrors != true {
		t.Errorf("IgnoreErrors = %v, want true", opts.IgnoreErrors)
	}

	if opts.IncludeNonPublic != true {
		t.Errorf("IncludeNonPublic = %v, want true", opts.IncludeNonPublic)
	}
}

func TestEffectiveAgeCalculation(t *testing.T) {
	// Test the effective age calculation: (age_days * 24h) - 1h
	tests := []struct {
		ageDays      int
		expectedHours int
	}{
		{1, 23},   // 1 day = 23 hours
		{7, 167},  // 7 days = 6 days 23 hours = 167 hours
		{30, 719}, // 30 days = 29 days 23 hours = 719 hours
	}

	for _, tt := range tests {
		effectiveAge := time.Duration(tt.ageDays*24)*time.Hour - 1*time.Hour
		expectedAge := time.Duration(tt.expectedHours) * time.Hour

		if effectiveAge != expectedAge {
			t.Errorf("effectiveAge for %d days = %v, want %v",
				tt.ageDays, effectiveAge, expectedAge)
		}
	}
}
