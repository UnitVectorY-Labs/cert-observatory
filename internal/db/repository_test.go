package db_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	_ "github.com/lib/pq"
)

// skipIfNoPostgres skips the test if no Postgres connection is available.
func skipIfNoPostgres(t *testing.T) *db.DB {
	t.Helper()

	host := os.Getenv("TEST_DB_HOST")
	if host == "" {
		host = "localhost"
	}

	cfg := &db.Config{
		Host:     host,
		Port:     5432,
		User:     os.Getenv("TEST_DB_USER"),
		Password: os.Getenv("TEST_DB_PASSWORD"),
		Database: os.Getenv("TEST_DB_NAME"),
		SSLMode:  "disable",
	}

	if cfg.User == "" {
		cfg.User = "postgres"
	}
	if cfg.Database == "" {
		cfg.Database = "cert_observatory_test"
	}

	database, err := db.Open(cfg)
	if err != nil {
		t.Skipf("Skipping integration test: %v", err)
	}

	// Run migrations
	if err := db.RunMigrations(database.DB); err != nil {
		database.Close()
		t.Skipf("Skipping integration test: migrations failed: %v", err)
	}

	// Clean up tables before test
	cleanupTables(t, database.DB)

	return database
}

func cleanupTables(t *testing.T, sqlDB *sql.DB) {
	t.Helper()

	tables := []string{
		"domain_chain_states",
		"domains",
		"chain_certs",
		"chains",
		"cert_signers",
		"certificates",
	}

	for _, table := range tables {
		_, err := sqlDB.Exec("DELETE FROM " + table)
		if err != nil {
			t.Fatalf("Failed to clean table %s: %v", table, err)
		}
	}
}

// createMockCertInfo creates a mock CertInfo for testing.
func createMockCertInfo(t *testing.T, seed byte) *certutil.CertInfo {
	t.Helper()

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = seed + byte(i)
	}

	ski := make([]byte, 20)
	for i := range ski {
		ski[i] = seed + byte(i) + 100
	}

	aki := make([]byte, 20)
	for i := range aki {
		aki[i] = seed + byte(i) + 200
	}

	return &certutil.CertInfo{
		CertHash:  hash,
		PEM:       "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
		DER:       []byte("mock-der"),
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		SKI:       ski,
		AKI:       aki,
	}
}

// createMockChainInfo creates a mock ChainInfo for testing.
func createMockChainInfo(t *testing.T, certs []*certutil.CertInfo) *certutil.ChainInfo {
	t.Helper()

	certHashes := make([][]byte, len(certs))
	for i, cert := range certs {
		certHashes[i] = cert.CertHash
	}

	return &certutil.ChainInfo{
		ChainHash:    certutil.ComputeChainHash(certHashes),
		LeafCertHash: certs[0].CertHash,
		Depth:        len(certs),
		Certs:        certs,
	}
}

func TestRepository_FirstCrawlInsertsDomainCertsChainState(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// Create mock chain
	certs := []*certutil.CertInfo{
		createMockCertInfo(t, 1),
		createMockCertInfo(t, 2),
		createMockCertInfo(t, 3),
	}
	chainInfo := createMockChainInfo(t, certs)

	result := &db.CrawlResult{
		Domain:    "example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}

	// First crawl
	stats, err := repo.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		t.Fatalf("RecordSuccessfulCrawl failed: %v", err)
	}

	// Verify stats
	if !stats.DomainInserted {
		t.Error("Expected domain to be inserted")
	}
	if stats.CertsInserted != 3 {
		t.Errorf("Expected 3 certs inserted, got %d", stats.CertsInserted)
	}
	if !stats.ChainInserted {
		t.Error("Expected chain to be inserted")
	}
	if !stats.ChainStateNewInterval {
		t.Error("Expected new chain state interval")
	}

	// Verify domain exists
	var domainID int64
	err = database.QueryRow("SELECT domain_id FROM domains WHERE domain = $1", "example.com").Scan(&domainID)
	if err != nil {
		t.Fatalf("Domain not found: %v", err)
	}

	// Verify certificates exist
	var certCount int
	err = database.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&certCount)
	if err != nil {
		t.Fatalf("Failed to count certificates: %v", err)
	}
	if certCount != 3 {
		t.Errorf("Expected 3 certificates, got %d", certCount)
	}

	// Verify chain exists
	var chainCount int
	err = database.QueryRow("SELECT COUNT(*) FROM chains").Scan(&chainCount)
	if err != nil {
		t.Fatalf("Failed to count chains: %v", err)
	}
	if chainCount != 1 {
		t.Errorf("Expected 1 chain, got %d", chainCount)
	}

	// Verify chain_certs
	var chainCertCount int
	err = database.QueryRow("SELECT COUNT(*) FROM chain_certs").Scan(&chainCertCount)
	if err != nil {
		t.Fatalf("Failed to count chain_certs: %v", err)
	}
	if chainCertCount != 3 {
		t.Errorf("Expected 3 chain_certs, got %d", chainCertCount)
	}

	// Verify domain_chain_states
	var stateCount int
	err = database.QueryRow("SELECT COUNT(*) FROM domain_chain_states WHERE domain_id = $1 AND ended_at IS NULL", domainID).Scan(&stateCount)
	if err != nil {
		t.Fatalf("Failed to count chain states: %v", err)
	}
	if stateCount != 1 {
		t.Errorf("Expected 1 active chain state, got %d", stateCount)
	}
}

func TestRepository_SecondCrawlSameChainUpdatesInterval(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// Create mock chain
	certs := []*certutil.CertInfo{
		createMockCertInfo(t, 10),
		createMockCertInfo(t, 20),
	}
	chainInfo := createMockChainInfo(t, certs)

	result := &db.CrawlResult{
		Domain:    "same-chain.example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}

	// First crawl
	_, err := repo.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		t.Fatalf("First crawl failed: %v", err)
	}

	// Get initial seen_count
	var initialSeenCount int64
	err = database.QueryRow(`
		SELECT seen_count FROM domain_chain_states 
		WHERE ended_at IS NULL AND chain_hash = $1
	`, chainInfo.ChainHash).Scan(&initialSeenCount)
	if err != nil {
		t.Fatalf("Failed to get initial seen_count: %v", err)
	}

	// Second crawl with same chain
	result.CrawlTime = time.Now().Add(time.Second)
	stats, err := repo.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		t.Fatalf("Second crawl failed: %v", err)
	}

	// Verify no new interval was created
	if stats.ChainStateNewInterval {
		t.Error("Expected no new interval for same chain")
	}

	// Verify seen_count increased
	var newSeenCount int64
	err = database.QueryRow(`
		SELECT seen_count FROM domain_chain_states 
		WHERE ended_at IS NULL AND chain_hash = $1
	`, chainInfo.ChainHash).Scan(&newSeenCount)
	if err != nil {
		t.Fatalf("Failed to get new seen_count: %v", err)
	}

	if newSeenCount != initialSeenCount+1 {
		t.Errorf("Expected seen_count to increase from %d to %d, got %d",
			initialSeenCount, initialSeenCount+1, newSeenCount)
	}

	// Verify only one interval exists
	var stateCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chain_states`).Scan(&stateCount)
	if err != nil {
		t.Fatalf("Failed to count states: %v", err)
	}
	if stateCount != 1 {
		t.Errorf("Expected 1 state interval, got %d", stateCount)
	}
}

func TestRepository_ChangedChainClosesOldInterval(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// First chain
	certs1 := []*certutil.CertInfo{
		createMockCertInfo(t, 30),
	}
	chainInfo1 := createMockChainInfo(t, certs1)

	result1 := &db.CrawlResult{
		Domain:    "changing.example.com",
		ChainInfo: chainInfo1,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}

	// First crawl
	_, err := repo.RecordSuccessfulCrawl(ctx, result1)
	if err != nil {
		t.Fatalf("First crawl failed: %v", err)
	}

	// Second chain (different)
	certs2 := []*certutil.CertInfo{
		createMockCertInfo(t, 40),
		createMockCertInfo(t, 50),
	}
	chainInfo2 := createMockChainInfo(t, certs2)

	result2 := &db.CrawlResult{
		Domain:    "changing.example.com",
		ChainInfo: chainInfo2,
		CrawlTime: time.Now().Add(time.Second),
		Mode:      db.CrawlModeStandard,
	}

	// Second crawl with different chain
	stats, err := repo.RecordSuccessfulCrawl(ctx, result2)
	if err != nil {
		t.Fatalf("Second crawl failed: %v", err)
	}

	if !stats.ChainStateNewInterval {
		t.Error("Expected new interval for different chain")
	}

	if !stats.CurrentChainChanged {
		t.Error("Expected current chain to change")
	}

	// Verify old interval is closed
	var closedCount int
	err = database.QueryRow(`
		SELECT COUNT(*) FROM domain_chain_states 
		WHERE ended_at IS NOT NULL
	`).Scan(&closedCount)
	if err != nil {
		t.Fatalf("Failed to count closed states: %v", err)
	}
	if closedCount != 1 {
		t.Errorf("Expected 1 closed interval, got %d", closedCount)
	}

	// Verify new interval is current
	var activeCount int
	err = database.QueryRow(`
		SELECT COUNT(*) FROM domain_chain_states 
		WHERE ended_at IS NULL AND chain_hash = $1
	`, chainInfo2.ChainHash).Scan(&activeCount)
	if err != nil {
		t.Fatalf("Failed to count active states: %v", err)
	}
	if activeCount != 1 {
		t.Errorf("Expected 1 active interval with new chain, got %d", activeCount)
	}

	// Verify total intervals
	var totalCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chain_states`).Scan(&totalCount)
	if err != nil {
		t.Fatalf("Failed to count total states: %v", err)
	}
	if totalCount != 2 {
		t.Errorf("Expected 2 total intervals, got %d", totalCount)
	}
}

func TestRepository_FailedCrawlUpdatesFailureFields(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	domain := "failing.example.com"
	crawlTime := time.Now()

	// Record failed crawl
	err := repo.RecordFailedCrawl(ctx, domain, crawlTime, db.CrawlModeStandard)
	if err != nil {
		t.Fatalf("RecordFailedCrawl failed: %v", err)
	}

	// Verify domain was created
	var domainID int64
	var consecutiveFailures int
	var lastFailureAt time.Time
	err = database.QueryRow(`
		SELECT domain_id, consecutive_failures, last_failure_at 
		FROM domains WHERE domain = $1
	`, domain).Scan(&domainID, &consecutiveFailures, &lastFailureAt)
	if err != nil {
		t.Fatalf("Failed to query domain: %v", err)
	}

	if consecutiveFailures != 1 {
		t.Errorf("Expected consecutive_failures = 1, got %d", consecutiveFailures)
	}

	// Record another failure
	err = repo.RecordFailedCrawl(ctx, domain, crawlTime.Add(time.Minute), db.CrawlModeStandard)
	if err != nil {
		t.Fatalf("Second RecordFailedCrawl failed: %v", err)
	}

	err = database.QueryRow(`
		SELECT consecutive_failures FROM domains WHERE domain = $1
	`, domain).Scan(&consecutiveFailures)
	if err != nil {
		t.Fatalf("Failed to query domain after second failure: %v", err)
	}

	if consecutiveFailures != 2 {
		t.Errorf("Expected consecutive_failures = 2, got %d", consecutiveFailures)
	}

	// Verify no chain states were created
	var stateCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chain_states WHERE domain_id = $1`, domainID).Scan(&stateCount)
	if err != nil {
		t.Fatalf("Failed to count chain states: %v", err)
	}
	if stateCount != 0 {
		t.Errorf("Expected 0 chain states for failed crawl, got %d", stateCount)
	}
}

func TestRepository_SuccessAfterFailureResetsCounter(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	domain := "recovers.example.com"

	// Record some failures
	for i := 0; i < 3; i++ {
		err := repo.RecordFailedCrawl(ctx, domain, time.Now(), db.CrawlModeStandard)
		if err != nil {
			t.Fatalf("RecordFailedCrawl failed: %v", err)
		}
	}

	// Verify failures accumulated
	var failures int
	err := database.QueryRow(`SELECT consecutive_failures FROM domains WHERE domain = $1`, domain).Scan(&failures)
	if err != nil {
		t.Fatalf("Failed to query domain: %v", err)
	}
	if failures != 3 {
		t.Errorf("Expected 3 failures, got %d", failures)
	}

	// Now succeed
	certs := []*certutil.CertInfo{createMockCertInfo(t, 60)}
	chainInfo := createMockChainInfo(t, certs)
	result := &db.CrawlResult{
		Domain:    domain,
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}

	_, err = repo.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		t.Fatalf("RecordSuccessfulCrawl failed: %v", err)
	}

	// Verify failures reset
	err = database.QueryRow(`SELECT consecutive_failures FROM domains WHERE domain = $1`, domain).Scan(&failures)
	if err != nil {
		t.Fatalf("Failed to query domain after success: %v", err)
	}
	if failures != 0 {
		t.Errorf("Expected 0 failures after success, got %d", failures)
	}
}
