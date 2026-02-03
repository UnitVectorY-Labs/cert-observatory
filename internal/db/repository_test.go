package db_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/db"
	"github.com/lib/pq"
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
		"domain_chains",
		"domains",
		"chains",
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

	// Create valid DER-like bytes (minimal, just for testing)
	der := make([]byte, 100)
	for i := range der {
		der[i] = seed + byte(i)
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
		DER:       der,
		Subject:   "CN=Test Subject " + string(seed),
		Issuer:    "CN=Test Issuer " + string(seed),
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
		CertHashes:   certHashes,
	}
}

func TestRepository_FirstCrawlInsertsDomainCertsChain(t *testing.T) {
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
	if !stats.DomainChainInserted {
		t.Error("Expected domain_chain to be inserted")
	}

	// Verify domain exists
	var domainName string
	err = database.QueryRow("SELECT domain FROM domains WHERE domain = $1", "example.com").Scan(&domainName)
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

	// Verify domain_chains
	var domainChainCount int
	err = database.QueryRow("SELECT COUNT(*) FROM domain_chains WHERE domain = $1", "example.com").Scan(&domainChainCount)
	if err != nil {
		t.Fatalf("Failed to count domain_chains: %v", err)
	}
	if domainChainCount != 1 {
		t.Errorf("Expected 1 domain_chain, got %d", domainChainCount)
	}
}

func TestRepository_SecondCrawlSameChainUpdatesCount(t *testing.T) {
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
		SELECT seen_count FROM domain_chains 
		WHERE domain = $1 AND chain_hash = $2
	`, "same-chain.example.com", chainInfo.ChainHash).Scan(&initialSeenCount)
	if err != nil {
		t.Fatalf("Failed to get initial seen_count: %v", err)
	}

	// Second crawl with same chain
	result.CrawlTime = time.Now().Add(time.Second)
	stats, err := repo.RecordSuccessfulCrawl(ctx, result)
	if err != nil {
		t.Fatalf("Second crawl failed: %v", err)
	}

	// Verify domain_chain was updated (not inserted)
	if stats.DomainChainInserted {
		t.Error("Expected no new domain_chain for same chain")
	}
	if !stats.DomainChainUpdated {
		t.Error("Expected domain_chain to be updated")
	}

	// Verify seen_count increased
	var newSeenCount int64
	err = database.QueryRow(`
		SELECT seen_count FROM domain_chains 
		WHERE domain = $1 AND chain_hash = $2
	`, "same-chain.example.com", chainInfo.ChainHash).Scan(&newSeenCount)
	if err != nil {
		t.Fatalf("Failed to get new seen_count: %v", err)
	}

	if newSeenCount != initialSeenCount+1 {
		t.Errorf("Expected seen_count to increase from %d to %d, got %d",
			initialSeenCount, initialSeenCount+1, newSeenCount)
	}

	// Verify only one domain_chain row exists
	var dcCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chains`).Scan(&dcCount)
	if err != nil {
		t.Fatalf("Failed to count domain_chains: %v", err)
	}
	if dcCount != 1 {
		t.Errorf("Expected 1 domain_chain, got %d", dcCount)
	}
}

func TestRepository_DomainOscillationBetweenChains(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// Chain A
	certsA := []*certutil.CertInfo{
		createMockCertInfo(t, 30),
	}
	chainInfoA := createMockChainInfo(t, certsA)

	// Chain B
	certsB := []*certutil.CertInfo{
		createMockCertInfo(t, 40),
		createMockCertInfo(t, 50),
	}
	chainInfoB := createMockChainInfo(t, certsB)

	domain := "oscillating.example.com"

	// Crawl with chain A
	resultA := &db.CrawlResult{
		Domain:    domain,
		ChainInfo: chainInfoA,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}
	_, err := repo.RecordSuccessfulCrawl(ctx, resultA)
	if err != nil {
		t.Fatalf("First crawl (A) failed: %v", err)
	}

	// Crawl with chain B
	resultB := &db.CrawlResult{
		Domain:    domain,
		ChainInfo: chainInfoB,
		CrawlTime: time.Now().Add(time.Second),
		Mode:      db.CrawlModeStandard,
	}
	_, err = repo.RecordSuccessfulCrawl(ctx, resultB)
	if err != nil {
		t.Fatalf("Second crawl (B) failed: %v", err)
	}

	// Crawl with chain A again (oscillation back)
	resultA.CrawlTime = time.Now().Add(2 * time.Second)
	stats, err := repo.RecordSuccessfulCrawl(ctx, resultA)
	if err != nil {
		t.Fatalf("Third crawl (A again) failed: %v", err)
	}

	// Verify no new domain_chain was inserted for the oscillation back
	if stats.DomainChainInserted {
		t.Error("Expected no new domain_chain when oscillating back to chain A")
	}
	if !stats.DomainChainUpdated {
		t.Error("Expected domain_chain for chain A to be updated")
	}

	// Verify we still have exactly 2 domain_chains (A and B)
	var dcCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chains WHERE domain = $1`, domain).Scan(&dcCount)
	if err != nil {
		t.Fatalf("Failed to count domain_chains: %v", err)
	}
	if dcCount != 2 {
		t.Errorf("Expected 2 domain_chains, got %d", dcCount)
	}

	// Verify chain A has seen_count = 2
	var seenCountA int64
	err = database.QueryRow(`
		SELECT seen_count FROM domain_chains 
		WHERE domain = $1 AND chain_hash = $2
	`, domain, chainInfoA.ChainHash).Scan(&seenCountA)
	if err != nil {
		t.Fatalf("Failed to get seen_count for chain A: %v", err)
	}
	if seenCountA != 2 {
		t.Errorf("Expected seen_count = 2 for chain A, got %d", seenCountA)
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
	var consecutiveFailures int
	var lastFailureAt time.Time
	err = database.QueryRow(`
		SELECT consecutive_failures, last_failure_at 
		FROM domains WHERE domain = $1
	`, domain).Scan(&consecutiveFailures, &lastFailureAt)
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

	// Verify no domain_chains were created
	var dcCount int
	err = database.QueryRow(`SELECT COUNT(*) FROM domain_chains WHERE domain = $1`, domain).Scan(&dcCount)
	if err != nil {
		t.Fatalf("Failed to count domain_chains: %v", err)
	}
	if dcCount != 0 {
		t.Errorf("Expected 0 domain_chains for failed crawl, got %d", dcCount)
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

func TestRepository_InsertSameCertificateTwice(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// Create same certificate twice with different domains
	cert := createMockCertInfo(t, 70)
	chainInfo := createMockChainInfo(t, []*certutil.CertInfo{cert})

	// First crawl
	result1 := &db.CrawlResult{
		Domain:    "domain1.example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}
	stats1, err := repo.RecordSuccessfulCrawl(ctx, result1)
	if err != nil {
		t.Fatalf("First crawl failed: %v", err)
	}
	if stats1.CertsInserted != 1 {
		t.Errorf("Expected 1 cert inserted on first crawl, got %d", stats1.CertsInserted)
	}

	// Second crawl with same certificate
	result2 := &db.CrawlResult{
		Domain:    "domain2.example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}
	stats2, err := repo.RecordSuccessfulCrawl(ctx, result2)
	if err != nil {
		t.Fatalf("Second crawl failed: %v", err)
	}
	if stats2.CertsInserted != 0 {
		t.Errorf("Expected 0 certs inserted on second crawl, got %d", stats2.CertsInserted)
	}

	// Verify only one certificate row exists
	var certCount int
	err = database.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&certCount)
	if err != nil {
		t.Fatalf("Failed to count certificates: %v", err)
	}
	if certCount != 1 {
		t.Errorf("Expected 1 certificate, got %d", certCount)
	}
}

func TestRepository_InsertSameChainTwice(t *testing.T) {
	database := skipIfNoPostgres(t)
	defer database.Close()

	ctx := context.Background()
	repo := db.NewRepository(database)

	// Create chain
	certs := []*certutil.CertInfo{
		createMockCertInfo(t, 80),
		createMockCertInfo(t, 81),
	}
	chainInfo := createMockChainInfo(t, certs)

	// First crawl
	result1 := &db.CrawlResult{
		Domain:    "chain1.example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}
	stats1, err := repo.RecordSuccessfulCrawl(ctx, result1)
	if err != nil {
		t.Fatalf("First crawl failed: %v", err)
	}
	if !stats1.ChainInserted {
		t.Error("Expected chain to be inserted on first crawl")
	}

	// Second crawl with same chain, different domain
	result2 := &db.CrawlResult{
		Domain:    "chain2.example.com",
		ChainInfo: chainInfo,
		CrawlTime: time.Now(),
		Mode:      db.CrawlModeStandard,
	}
	stats2, err := repo.RecordSuccessfulCrawl(ctx, result2)
	if err != nil {
		t.Fatalf("Second crawl failed: %v", err)
	}
	if stats2.ChainInserted {
		t.Error("Expected chain to NOT be inserted on second crawl")
	}

	// Verify only one chain row exists
	var chainCount int
	err = database.QueryRow("SELECT COUNT(*) FROM chains").Scan(&chainCount)
	if err != nil {
		t.Fatalf("Failed to count chains: %v", err)
	}
	if chainCount != 1 {
		t.Errorf("Expected 1 chain, got %d", chainCount)
	}

	// Verify chain ordering is preserved
	var certHashesArray [][]byte
	err = database.QueryRow("SELECT cert_hashes FROM chains WHERE chain_hash = $1", chainInfo.ChainHash).Scan(pq.Array(&certHashesArray))
	if err != nil {
		t.Fatalf("Failed to get cert_hashes: %v", err)
	}
	if len(certHashesArray) != 2 {
		t.Errorf("Expected 2 cert_hashes, got %d", len(certHashesArray))
	}
}
