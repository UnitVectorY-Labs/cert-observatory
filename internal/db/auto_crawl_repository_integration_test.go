package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
)

func TestRepository_GetEligibleDomainsForCrawlWithOptions_OrderAndLimit(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)
	now := time.Now().UTC()

	insertDomain := func(domain string, popular bool, lastSuccess, lastFailure, noRetryBefore *time.Time) {
		t.Helper()
		_, err := database.Exec(`
			INSERT INTO domains (
				domain, first_seen_at, popular_domain, auto_crawl,
				last_success_at, last_failure_at, no_retry_before
			) VALUES ($1, $2, $3, true, $4, $5, $6)
		`, domain, now, popular, lastSuccess, lastFailure, noRetryBefore)
		if err != nil {
			t.Fatalf("insert domain %s: %v", domain, err)
		}
	}

	lastFailure10Days := now.Add(-10 * 24 * time.Hour)
	lastSuccess8Days := now.Add(-8 * 24 * time.Hour)
	lastSuccess20Days := now.Add(-20 * 24 * time.Hour)
	lastFailure1Day := now.Add(-24 * time.Hour)
	lastSuccess2Hours := now.Add(-2 * time.Hour)
	retryIn2Hours := now.Add(2 * time.Hour)

	insertDomain("never.example.com", true, nil, nil, nil)
	insertDomain("old-failure.example.com", true, nil, &lastFailure10Days, nil)
	insertDomain("old-success.example.com", true, &lastSuccess8Days, nil, nil)
	insertDomain("recent-failure.example.com", true, &lastSuccess20Days, &lastFailure1Day, nil)

	// Excluded by existing eligibility filters:
	insertDomain("too-recent-success.example.com", true, &lastSuccess2Hours, nil, nil)
	insertDomain("in-backoff.example.com", true, nil, &lastFailure10Days, &retryIn2Hours)
	insertDomain("non-public.example.com", false, nil, nil, nil)

	opts := &db.CrawlDomainsOptions{
		IgnoreErrors:     false,
		IncludeNonPublic: false,
	}

	effectiveAge := 23 * time.Hour
	domains, err := repo.GetEligibleDomainsForCrawlWithOptions(ctx, effectiveAge, 10, opts)
	if err != nil {
		t.Fatalf("GetEligibleDomainsForCrawlWithOptions failed: %v", err)
	}

	got := make([]string, 0, len(domains))
	for _, d := range domains {
		got = append(got, d.Domain)
	}

	want := []string{
		"never.example.com",
		"old-failure.example.com",
		"old-success.example.com",
		"recent-failure.example.com",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d domains, got %d: %v", len(want), len(got), got)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected order at index %d: got %s, want %s (all: %v)", i, got[i], want[i], got)
		}
	}

	limited, err := repo.GetEligibleDomainsForCrawlWithOptions(ctx, effectiveAge, 2, opts)
	if err != nil {
		t.Fatalf("GetEligibleDomainsForCrawlWithOptions (limit) failed: %v", err)
	}

	if len(limited) != 2 {
		t.Fatalf("expected 2 domains with limit=2, got %d", len(limited))
	}
	if limited[0].Domain != want[0] || limited[1].Domain != want[1] {
		t.Fatalf("unexpected limited order: got [%s, %s], want [%s, %s]",
			limited[0].Domain, limited[1].Domain, want[0], want[1])
	}
}
