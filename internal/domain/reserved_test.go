package domain

import "testing"

func TestCheckReservedDomain(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		wantNil    bool
		wantReason string
	}{
		// RFC 2606 reserved TLDs
		{
			name:       "test TLD",
			domain:     "foo.test",
			wantNil:    false,
			wantReason: "The .test TLD is reserved for testing purposes",
		},
		{
			name:       "example TLD",
			domain:     "foo.example",
			wantNil:    false,
			wantReason: "The .example TLD is reserved for documentation",
		},
		{
			name:       "invalid TLD",
			domain:     "foo.invalid",
			wantNil:    false,
			wantReason: "The .invalid TLD is reserved",
		},
		{
			name:       "localhost TLD",
			domain:     "foo.localhost",
			wantNil:    false,
			wantReason: "The .localhost TLD is reserved",
		},

		// RFC 2606 reserved second-level domains
		{
			name:       "example.com",
			domain:     "example.com",
			wantNil:    false,
			wantReason: "example.com is reserved for documentation",
		},
		{
			name:       "www.example.com",
			domain:     "www.example.com",
			wantNil:    false,
			wantReason: "example.com is reserved for documentation",
		},
		{
			name:       "example.net",
			domain:     "example.net",
			wantNil:    false,
			wantReason: "example.net is reserved for documentation",
		},
		{
			name:       "example.org",
			domain:     "subdomain.example.org",
			wantNil:    false,
			wantReason: "example.org is reserved for documentation",
		},

		// Special TLDs
		{
			name:       "local domain",
			domain:     "myprinter.local",
			wantNil:    false,
			wantReason: "The .local TLD is used for local network services",
		},
		{
			name:       "onion domain",
			domain:     "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
			wantNil:    false,
			wantReason: "The .onion TLD is used for Tor hidden services",
		},

		// Valid domains (should return nil)
		{
			name:    "github.com",
			domain:  "github.com",
			wantNil: true,
		},
		{
			name:    "www.google.com",
			domain:  "www.google.com",
			wantNil: true,
		},
		{
			name:    "example-site.com (not example.com)",
			domain:  "example-site.com",
			wantNil: true,
		},
		{
			name:    "myexample.com",
			domain:  "myexample.com",
			wantNil: true,
		},
		{
			name:    "testsite.com (not .test TLD)",
			domain:  "testsite.com",
			wantNil: true,
		},

		// Edge cases
		{
			name:    "empty string",
			domain:  "",
			wantNil: true,
		},
		{
			name:       "uppercase TEST TLD",
			domain:     "FOO.TEST",
			wantNil:    false,
			wantReason: "The .test TLD is reserved",
		},
		{
			name:       "mixed case Example.Com",
			domain:     "Example.Com",
			wantNil:    false,
			wantReason: "example.com is reserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckReservedDomain(tt.domain)

			if tt.wantNil {
				if result != nil {
					t.Errorf("CheckReservedDomain(%q) = %+v, want nil", tt.domain, result)
				}
				return
			}

			if result == nil {
				t.Errorf("CheckReservedDomain(%q) = nil, want non-nil", tt.domain)
				return
			}

			if tt.wantReason != "" && !contains(result.Reason, tt.wantReason) {
				t.Errorf("CheckReservedDomain(%q).Reason = %q, want to contain %q", tt.domain, result.Reason, tt.wantReason)
			}

			// All reserved domains should have an RFC link
			if result.RFCLink == "" {
				t.Errorf("CheckReservedDomain(%q).RFCLink is empty", tt.domain)
			}
		})
	}
}

func TestIsReservedDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"foo.test", true},
		{"foo.invalid", true},
		{"myprinter.local", true},
		{"hidden.onion", true},
		{"github.com", false},
		{"google.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := IsReservedDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("IsReservedDomain(%q) = %v, want %v", tt.domain, result, tt.expected)
			}
		})
	}
}

// contains checks if s contains substr (case-insensitive partial match)
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
