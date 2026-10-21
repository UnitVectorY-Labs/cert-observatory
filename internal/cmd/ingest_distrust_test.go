package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

type mockDistrustStore struct {
	sources  []string
	failures []bool
}

func (s *mockDistrustStore) RefreshDistrust(_ context.Context, source string, fetch func() ([]distrust.Rule, error)) error {
	s.sources = append(s.sources, source)
	_, err := fetch()
	s.failures = append(s.failures, err != nil)
	return err
}

type distrustHTTPFunc func(*http.Request) (*http.Response, error)

func (f distrustHTTPFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestIngestDistrustContinuesAfterSourceFailure(t *testing.T) {
	store := &mockDistrustStore{}
	cfg := DefaultIngestDistrustConfig()
	cfg.Store = store
	cfg.Stderr = io.Discard
	cfg.HTTPClient = distrustHTTPFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == distrust.OneCRLURL {
			return nil, errors.New("offline")
		}
		if r.URL.String() != distrust.CCADBURL {
			t.Fatal("unexpected source")
		}
		body := "Salesforce Record ID,Certificate Record Type,SHA-256 Fingerprint,Apple Status,Chrome Status,Microsoft Status,Mozilla Status\nroot,Root Certificate," + strings.Repeat("aa", 32) + ",Blocked,Included,Included,Included\n"
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	if err := IngestDistrust(context.Background(), cfg); err == nil {
		t.Fatal("must report partial failure")
	}
	if len(store.sources) != 2 || !store.failures[0] || store.failures[1] {
		t.Fatalf("unexpected calls %+v", store)
	}
	cfg.Source = distrust.CCADB
	store.sources = nil
	if err := IngestDistrust(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(store.sources) != 1 || store.sources[0] != distrust.CCADB {
		t.Fatal("source selection ignored")
	}
	cfg.Source = "invalid"
	if err := IngestDistrust(context.Background(), cfg); err == nil {
		t.Fatal("expected invalid source error")
	}
}
