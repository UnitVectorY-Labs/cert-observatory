package cmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
)

// mockHTTPClient is a mock HTTP client for testing.
type mockHTTPClient struct {
	response *http.Response
	err      error
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

func TestParseToplistResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "standard response with header",
			input:    "domain\ngoogle.com\nfacebook.com\namazon.com\n",
			expected: []string{"google.com", "facebook.com", "amazon.com"},
		},
		{
			name:     "no header",
			input:    "google.com\nfacebook.com\n",
			expected: []string{"google.com", "facebook.com"},
		},
		{
			name:     "with empty lines",
			input:    "domain\n\ngoogle.com\n\nfacebook.com\n\n",
			expected: []string{"google.com", "facebook.com"},
		},
		{
			name:     "with whitespace",
			input:    "domain\n  google.com  \n\tfacebook.com\t\n",
			expected: []string{"google.com", "facebook.com"},
		},
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name:     "only header",
			input:    "domain\n",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseToplistResponse([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != len(tt.expected) {
				t.Errorf("got %d domains, want %d", len(result), len(tt.expected))
				return
			}

			for i, domain := range result {
				if domain != tt.expected[i] {
					t.Errorf("domain[%d] = %q, want %q", i, domain, tt.expected[i])
				}
			}
		})
	}
}

func TestIngestToplist_MissingToken(t *testing.T) {
	cfg := &IngestToplistConfig{
		CloudflareToken: "",
		Stderr:          io.Discard,
		DBConfig:        &db.Config{},
	}

	err := IngestToplist(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for missing token, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error should mention token: %v", err)
	}
}

func TestFetchCloudflareToplist_Success(t *testing.T) {
	responseBody := "domain\nexample.com\ntest.com\n"
	client := &mockHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
		},
	}

	domains, err := fetchCloudflareToplist(context.Background(), client, "https://example.com/api", "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(domains) != 2 {
		t.Errorf("got %d domains, want 2", len(domains))
	}

	expected := []string{"example.com", "test.com"}
	for i, d := range domains {
		if d != expected[i] {
			t.Errorf("domain[%d] = %q, want %q", i, d, expected[i])
		}
	}
}

func TestFetchCloudflareToplist_HTTPError(t *testing.T) {
	client := &mockHTTPClient{
		response: &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(bytes.NewBufferString("unauthorized")),
		},
	}

	_, err := fetchCloudflareToplist(context.Background(), client, "https://example.com/api", "bad-token")
	if err == nil {
		t.Error("expected error for HTTP error, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code 401: %v", err)
	}
}

func TestParseToplistResponse_LargeDomainList(t *testing.T) {
	// Simulate a large response with 10000 domains
	var builder strings.Builder
	builder.WriteString("domain\n")
	for i := 0; i < 10000; i++ {
		builder.WriteString("domain")
		builder.WriteString(strings.Repeat("x", 50)) // Make domain names longer
		builder.WriteString(".com\n")
	}

	domains, err := parseToplistResponse([]byte(builder.String()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(domains) != 10000 {
		t.Errorf("got %d domains, want 10000", len(domains))
	}
}
