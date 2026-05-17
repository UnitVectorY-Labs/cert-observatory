package domain

import (
	"testing"
)

func TestNormalizeAndValidate(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       string
		wantErr    error
		wantAnyErr bool // if true, just check that an error is returned
	}{
		// Valid cases
		{
			name:  "simple domain",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "uppercase domain normalized",
			input: "EXAMPLE.COM",
			want:  "example.com",
		},
		{
			name:  "mixed case domain normalized",
			input: "Example.COM",
			want:  "example.com",
		},
		{
			name:  "leading whitespace trimmed",
			input: "  example.com",
			want:  "example.com",
		},
		{
			name:  "trailing whitespace trimmed",
			input: "example.com  ",
			want:  "example.com",
		},
		{
			name:  "both whitespace trimmed",
			input: "  example.com  ",
			want:  "example.com",
		},
		{
			name:  "subdomain",
			input: "www.example.com",
			want:  "www.example.com",
		},
		{
			name:  "deep subdomain",
			input: "a.b.c.d.example.com",
			want:  "a.b.c.d.example.com",
		},
		{
			name:  "numeric label",
			input: "123.example.com",
			want:  "123.example.com",
		},
		{
			name:  "hyphenated domain",
			input: "my-domain.example.com",
			want:  "my-domain.example.com",
		},
		{
			name:  "single character labels",
			input: "a.b.c",
			want:  "a.b.c",
		},
		{
			name:  "punycode domain",
			input: "xn--nxasmq5b.com",
			want:  "xn--nxasmq5b.com",
		},
		{
			name:  "github.com",
			input: "github.com",
			want:  "github.com",
		},

		// Invalid cases - empty/whitespace
		{
			name:    "empty string",
			input:   "",
			wantErr: ErrEmptyDomain,
		},
		{
			name:    "only whitespace",
			input:   "   ",
			wantErr: ErrEmptyDomain,
		},
		{
			name:    "only tabs",
			input:   "\t\t",
			wantErr: ErrEmptyDomain,
		},

		// Invalid cases - URL schemes
		{
			name:    "https scheme",
			input:   "https://example.com",
			wantErr: ErrDomainHasScheme,
		},
		{
			name:    "http scheme",
			input:   "http://example.com",
			wantErr: ErrDomainHasScheme,
		},
		{
			name:    "ftp scheme",
			input:   "ftp://example.com",
			wantErr: ErrDomainHasScheme,
		},
		{
			name:    "scheme uppercase",
			input:   "HTTPS://EXAMPLE.COM",
			wantErr: ErrDomainHasScheme,
		},

		// Invalid cases - port
		{
			name:    "with port 443",
			input:   "example.com:443",
			wantErr: ErrDomainHasPort,
		},
		{
			name:    "with port 8080",
			input:   "example.com:8080",
			wantErr: ErrDomainHasPort,
		},

		// Invalid cases - path
		{
			name:    "with path",
			input:   "example.com/path",
			wantErr: ErrDomainHasPath,
		},
		{
			name:    "with trailing slash",
			input:   "example.com/",
			wantErr: ErrDomainHasPath,
		},

		// Invalid cases - query string
		{
			name:    "with query string",
			input:   "example.com?query=1",
			wantErr: ErrDomainHasQuery,
		},

		// Invalid cases - trailing dot
		{
			name:    "trailing dot",
			input:   "example.com.",
			wantErr: ErrDomainTrailingDot,
		},

		// Invalid cases - control characters
		{
			name:    "with null byte",
			input:   "example\x00.com",
			wantErr: ErrDomainControlChars,
		},
		{
			name:    "with tab in middle",
			input:   "example\t.com",
			wantErr: ErrDomainControlChars,
		},

		// Invalid cases - whitespace in middle
		{
			name:    "space in middle",
			input:   "example .com",
			wantErr: ErrDomainInvalidChars,
		},

		// Invalid cases - invalid characters
		{
			name:       "underscore in domain",
			input:      "example_test.com",
			wantAnyErr: true,
		},
		{
			name:       "special characters",
			input:      "example@test.com",
			wantAnyErr: true,
		},
		{
			name:       "unicode characters (not punycode)",
			input:      "例え.jp",
			wantAnyErr: true,
		},

		// Invalid cases - label issues
		{
			name:    "empty label (double dot)",
			input:   "example..com",
			wantErr: ErrDomainInvalidLabel,
		},
		{
			name:       "leading hyphen in label",
			input:      "-example.com",
			wantAnyErr: true,
		},
		{
			name:       "trailing hyphen in label",
			input:      "example-.com",
			wantAnyErr: true,
		},
		{
			name:    "label too long (64 chars)",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", // 64 'a's exceeds 63 char limit
			wantErr: ErrDomainLabelTooLong,
		},

		// Edge cases - length
		{
			name:  "exactly 253 characters",
			input: "a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			want:  "a.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAndValidate(tt.input)

			if tt.wantAnyErr {
				if err == nil {
					t.Errorf("NormalizeAndValidate(%q) = %q, want error", tt.input, got)
				}
				return
			}

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("NormalizeAndValidate(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("NormalizeAndValidate(%q) error = %v, want nil", tt.input, err)
				return
			}

			if got != tt.want {
				t.Errorf("NormalizeAndValidate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeAndValidate_TooLong(t *testing.T) {
	// Create a domain that's too long (254 characters)
	longDomain := "a." + string(make([]byte, 252))
	for i := range longDomain[2:] {
		if i%64 == 63 {
			longDomain = longDomain[:i+2] + "." + longDomain[i+3:]
		}
	}

	// Simpler test: just make a really long string
	longInput := make([]byte, 260)
	for i := range longInput {
		longInput[i] = 'a'
		if i > 0 && i%60 == 0 {
			longInput[i] = '.'
		}
	}

	_, err := NormalizeAndValidate(string(longInput))
	if err != ErrDomainTooLong {
		t.Errorf("Expected ErrDomainTooLong, got %v", err)
	}
}

func TestNormalizeAndValidateTargetWithPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *Target
		wantErr error
	}{
		{
			name:  "default port",
			input: "Example.COM",
			want:  &Target{Domain: "example.com", Port: 443},
		},
		{
			name:  "custom port",
			input: "Example.COM:8443",
			want:  &Target{Domain: "example.com", Port: 8443},
		},
		{
			name:  "lowest valid port",
			input: "example.com:1",
			want:  &Target{Domain: "example.com", Port: 1},
		},
		{
			name:  "highest valid port",
			input: "example.com:65535",
			want:  &Target{Domain: "example.com", Port: 65535},
		},
		{
			name:    "zero port",
			input:   "example.com:0",
			wantErr: ErrInvalidPort,
		},
		{
			name:    "too high port",
			input:   "example.com:65536",
			wantErr: ErrInvalidPort,
		},
		{
			name:    "non numeric port",
			input:   "example.com:https",
			wantErr: ErrInvalidPort,
		},
		{
			name:    "ipv6 literal remains invalid",
			input:   "::1",
			wantErr: ErrDomainHasPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAndValidateTarget(tt.input, true)
			if err != tt.wantErr {
				t.Fatalf("NormalizeAndValidateTarget(%q) error = %v, want %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if got.Domain != tt.want.Domain || got.Port != tt.want.Port {
				t.Fatalf("NormalizeAndValidateTarget(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}
