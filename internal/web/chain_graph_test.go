package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCertBundle holds a generated certificate with its key and parsed result.
type testCertBundle struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	der    []byte
	hash   []byte
	result *CertificateResult
}

// generateSelfSignedRoot creates a self-signed root CA for testing.
func generateSelfSignedRoot(t *testing.T, cn string) *testCertBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}

	ski := make([]byte, 20)
	if _, err := rand.Read(ski); err != nil {
		t.Fatalf("generate SKI: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}

	h := sha256.Sum256(der)
	return &testCertBundle{
		cert: parsed,
		key:  key,
		der:  der,
		hash: h[:],
		result: &CertificateResult{
			CertHash: h[:],
			DER:      der,
			Subject:  parsed.Subject.String(),
			Issuer:   parsed.Issuer.String(),
			SKI:      parsed.SubjectKeyId,
			AKI:      parsed.AuthorityKeyId,
			Parsed:   parsed,
		},
	}
}

// generateSignedIntermediate creates an intermediate CA signed by a parent.
func generateSignedIntermediate(t *testing.T, cn string, parent *testCertBundle) *testCertBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}

	ski := make([]byte, 20)
	if _, err := rand.Read(ski); err != nil {
		t.Fatalf("generate SKI: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        parent.cert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("create intermediate cert: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse intermediate cert: %v", err)
	}

	h := sha256.Sum256(der)
	return &testCertBundle{
		cert: parsed,
		key:  key,
		der:  der,
		hash: h[:],
		result: &CertificateResult{
			CertHash: h[:],
			DER:      der,
			Subject:  parsed.Subject.String(),
			Issuer:   parsed.Issuer.String(),
			SKI:      parsed.SubjectKeyId,
			AKI:      parsed.AuthorityKeyId,
			Parsed:   parsed,
		},
	}
}

// generateLeafCert creates a leaf (server) certificate signed by a parent.
func generateLeafCert(t *testing.T, cn string, parent *testCertBundle) *testCertBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	ski := make([]byte, 20)
	if _, err := rand.Read(ski); err != nil {
		t.Fatalf("generate SKI: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(100),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:      time.Now().Add(-24 * time.Hour),
		NotAfter:       time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       []string{cn},
		SubjectKeyId:   ski,
		AuthorityKeyId: parent.cert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	h := sha256.Sum256(der)
	return &testCertBundle{
		cert: parsed,
		key:  key,
		der:  der,
		hash: h[:],
		result: &CertificateResult{
			CertHash: h[:],
			DER:      der,
			Subject:  parsed.Subject.String(),
			Issuer:   parsed.Issuer.String(),
			SKI:      parsed.SubjectKeyId,
			AKI:      parsed.AuthorityKeyId,
			Parsed:   parsed,
		},
	}
}

// skiLookupRepo is a test repository that resolves FindCertificatesBySKI using a map.
type skiLookupRepo struct {
	mockRepository
	skiMap map[string][]*CertificateResult // hex(SKI) -> certs
}

func newSKILookupRepo() *skiLookupRepo {
	return &skiLookupRepo{
		skiMap: make(map[string][]*CertificateResult),
	}
}

func (r *skiLookupRepo) registerCert(bundle *testCertBundle) {
	if len(bundle.result.SKI) > 0 {
		skiHex := hex.EncodeToString(bundle.result.SKI)
		r.skiMap[skiHex] = append(r.skiMap[skiHex], bundle.result)
	}
}

func (r *skiLookupRepo) FindCertificatesBySKI(ctx context.Context, ski []byte) ([]*CertificateResult, error) {
	skiHex := hex.EncodeToString(ski)
	return r.skiMap[skiHex], nil
}

func TestBuildChainGraph_SimpleChain(t *testing.T) {
	// Scenario: leaf -> intermediate -> root (all in chain)
	root := generateSelfSignedRoot(t, "Test Root CA")
	inter := generateSignedIntermediate(t, "Test Intermediate CA", root)
	leaf := generateLeafCert(t, "test.example.com", inter)

	repo := newSKILookupRepo()
	repo.registerCert(root)
	repo.registerCert(inter)

	chainCerts := []*CertificateResult{leaf.result, inter.result, root.result}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}
	if graph.Root == nil {
		t.Fatal("expected non-nil root node")
	}

	// Root of graph should be the leaf cert
	if graph.Root.SubjectCN != "test.example.com" {
		t.Errorf("expected root node CN 'test.example.com', got %q", graph.Root.SubjectCN)
	}
	if !graph.Root.InChain {
		t.Error("leaf node should be marked InChain")
	}

	// Leaf should have one issuer (intermediate)
	if len(graph.Root.Issuers) != 1 {
		t.Fatalf("expected 1 issuer for leaf, got %d", len(graph.Root.Issuers))
	}
	interNode := graph.Root.Issuers[0]
	if interNode.SubjectCN != "Test Intermediate CA" {
		t.Errorf("expected intermediate CN 'Test Intermediate CA', got %q", interNode.SubjectCN)
	}
	if !interNode.InChain {
		t.Error("intermediate should be marked InChain")
	}

	// Intermediate should have one issuer (root)
	if len(interNode.Issuers) != 1 {
		t.Fatalf("expected 1 issuer for intermediate, got %d", len(interNode.Issuers))
	}
	rootNode := interNode.Issuers[0]
	if rootNode.SubjectCN != "Test Root CA" {
		t.Errorf("expected root CN 'Test Root CA', got %q", rootNode.SubjectCN)
	}
	if !rootNode.IsSelfSigned {
		t.Error("root should be marked self-signed")
	}
	if !rootNode.InChain {
		t.Error("root should be marked InChain")
	}
	// Root should have no further issuers
	if len(rootNode.Issuers) != 0 {
		t.Errorf("expected 0 issuers for root, got %d", len(rootNode.Issuers))
	}

	// AllCerts should have 3 unique entries
	if len(graph.AllCerts) != 3 {
		t.Errorf("expected 3 allCerts, got %d", len(graph.AllCerts))
	}
	if !graph.Legend.HasServerCertificate {
		t.Error("expected server certificate legend item")
	}
	if !graph.Legend.HasIntermediateCA {
		t.Error("expected intermediate CA legend item")
	}
	if !graph.Legend.HasRootCA {
		t.Error("expected root CA legend item")
	}
	if graph.Legend.HasMissing {
		t.Error("did not expect missing legend item")
	}
	if graph.Legend.HasExpired {
		t.Error("did not expect expired legend item")
	}
}

func TestBuildChainGraph_MermaidStylingAndGrouping(t *testing.T) {
	root := generateSelfSignedRoot(t, "Color Root CA")
	inter := generateSignedIntermediate(t, "Color Intermediate CA", root)
	leaf := generateLeafCert(t, "color.example.com", inter)

	repo := newSKILookupRepo()
	repo.registerCert(root)
	repo.registerCert(inter)

	// Only leaf and intermediate are in the presented TLS chain.
	chainCerts := []*CertificateResult{leaf.result, inter.result}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}

	diagram := graph.MermaidDiagram
	if !strings.Contains(diagram, `subgraph tlsChain[" "]`) {
		t.Error("expected mermaid diagram to include tlsChain subgraph")
	}
	if !strings.Contains(diagram, "style tlsChain ") {
		t.Error("expected mermaid diagram to style tlsChain subgraph")
	}
	if !strings.Contains(diagram, "classDef leaf ") {
		t.Error("expected leaf class definition")
	}
	if !strings.Contains(diagram, "classDef intermediate ") {
		t.Error("expected intermediate class definition")
	}
	if !strings.Contains(diagram, "classDef root ") {
		t.Error("expected root class definition")
	}
	if !strings.Contains(diagram, "classDef missing ") {
		t.Error("expected missing class definition")
	}
	if strings.Contains(diagram, "classDef discovered ") {
		t.Error("did not expect discovered class definition")
	}
}

func TestBuildChainGraph_OutOfChainRoot(t *testing.T) {
	// Scenario: chain has only [leaf, intermediate], root is fetched from DB.
	root := generateSelfSignedRoot(t, "Out-Of-Chain Root CA")
	inter := generateSignedIntermediate(t, "Inter CA", root)
	leaf := generateLeafCert(t, "app.example.com", inter)

	repo := newSKILookupRepo()
	repo.registerCert(root)
	repo.registerCert(inter)

	// Only leaf and intermediate in the TLS chain
	chainCerts := []*CertificateResult{leaf.result, inter.result}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}

	// Walk to the root
	if len(graph.Root.Issuers) != 1 {
		t.Fatalf("expected 1 issuer for leaf, got %d", len(graph.Root.Issuers))
	}
	interNode := graph.Root.Issuers[0]
	if !interNode.InChain {
		t.Error("intermediate should be InChain")
	}

	if len(interNode.Issuers) != 1 {
		t.Fatalf("expected 1 issuer for intermediate, got %d", len(interNode.Issuers))
	}
	rootNode := interNode.Issuers[0]
	if rootNode.InChain {
		t.Error("out-of-chain root should NOT be InChain")
	}
	if !rootNode.IsSelfSigned {
		t.Error("out-of-chain root should be self-signed")
	}
	if rootNode.SubjectCN != "Out-Of-Chain Root CA" {
		t.Errorf("expected root CN 'Out-Of-Chain Root CA', got %q", rootNode.SubjectCN)
	}
}

func TestBuildChainGraph_MissingIssuer(t *testing.T) {
	// Scenario: chain has [leaf, intermediate] but root is NOT in DB
	root := generateSelfSignedRoot(t, "Unknown Root")
	inter := generateSignedIntermediate(t, "Inter Missing", root)
	leaf := generateLeafCert(t, "missing.example.com", inter)

	repo := newSKILookupRepo()
	// Register the intermediate but NOT the root
	repo.registerCert(inter)

	chainCerts := []*CertificateResult{leaf.result, inter.result}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}

	interNode := graph.Root.Issuers[0]
	if len(interNode.Issuers) != 1 {
		t.Fatalf("expected 1 issuer placeholder, got %d", len(interNode.Issuers))
	}
	missingNode := interNode.Issuers[0]
	if !missingNode.IsMissing {
		t.Error("expected missing issuer node to be marked IsMissing")
	}
	if missingNode.CertIndex != -1 {
		t.Errorf("expected CertIndex -1 for missing node, got %d", missingNode.CertIndex)
	}
	if !graph.Legend.HasMissing {
		t.Error("expected missing legend item")
	}
	if graph.Legend.HasRootCA {
		t.Error("did not expect root CA legend item when issuer is missing")
	}
}

func TestBuildChainGraph_ExpiredCertLegendAndLabel(t *testing.T) {
	root := generateSelfSignedRoot(t, "Expired Root CA")
	inter := generateSignedIntermediate(t, "Expired Intermediate CA", root)
	leaf := generateLeafCert(t, "expired.example.com", inter)

	expiredAt := time.Now().Add(-1 * time.Hour)
	leaf.cert.NotAfter = expiredAt
	leaf.result.Parsed.NotAfter = expiredAt
	leaf.result.NotAfter = expiredAt

	repo := newSKILookupRepo()
	repo.registerCert(root)
	repo.registerCert(inter)

	chainCerts := []*CertificateResult{leaf.result, inter.result, root.result}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}

	if !graph.Legend.HasExpired {
		t.Fatal("expected expired legend item to be enabled")
	}

	if !strings.Contains(graph.MermaidDiagram, "⛔ expired.example.com") {
		t.Fatalf("expected mermaid diagram to contain expired label prefix, diagram=%q", graph.MermaidDiagram)
	}
}

func TestBuildChainGraph_CrossSigning(t *testing.T) {
	// Scenario: intermediate is signed by two different roots (cross-signing)
	rootA := generateSelfSignedRoot(t, "Root A")
	rootB := generateSelfSignedRoot(t, "Root B")

	// Create intermediate signed by rootA
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate inter key: %v", err)
	}
	interSKI := make([]byte, 20)
	if _, err := rand.Read(interSKI); err != nil {
		t.Fatalf("generate inter SKI: %v", err)
	}

	// Sign by root A
	interTmplA := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Cross-Signed Inter", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          interSKI,
		AuthorityKeyId:        rootA.cert.SubjectKeyId,
	}
	derA, err := x509.CreateCertificate(rand.Reader, interTmplA, rootA.cert, &interKey.PublicKey, rootA.key)
	if err != nil {
		t.Fatalf("create inter cert A: %v", err)
	}
	parsedA, _ := x509.ParseCertificate(derA)
	hA := sha256.Sum256(derA)
	interA := &CertificateResult{
		CertHash: hA[:], DER: derA, Parsed: parsedA,
		SKI: parsedA.SubjectKeyId, AKI: parsedA.AuthorityKeyId,
	}

	// Sign same key by root B (cross-sign)
	interTmplB := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Cross-Signed Inter", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          interSKI,
		AuthorityKeyId:        rootB.cert.SubjectKeyId,
	}
	derB, err := x509.CreateCertificate(rand.Reader, interTmplB, rootB.cert, &interKey.PublicKey, rootB.key)
	if err != nil {
		t.Fatalf("create inter cert B: %v", err)
	}
	parsedB, _ := x509.ParseCertificate(derB)
	hB := sha256.Sum256(derB)
	interB := &CertificateResult{
		CertHash: hB[:], DER: derB, Parsed: parsedB,
		SKI: parsedB.SubjectKeyId, AKI: parsedB.AuthorityKeyId,
	}

	// Leaf signed by intermediate (using interKey which is the same for both cross-signed versions)
	leaf := generateLeafCert(t, "cross.example.com", &testCertBundle{cert: parsedA, key: interKey})

	repo := newSKILookupRepo()
	repo.registerCert(rootA)
	repo.registerCert(rootB)
	// Both cross-signed intermediates discoverable by their SKI
	repo.skiMap[hex.EncodeToString(interSKI)] = []*CertificateResult{interA, interB}
	// Both roots discoverable
	repo.registerCert(rootA)
	repo.registerCert(rootB)

	// Chain only contains leaf and interA
	chainCerts := []*CertificateResult{leaf.result, interA}

	graph := buildChainGraph(context.Background(), repo, chainCerts)
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}

	// Leaf should have at least one issuer
	if len(graph.Root.Issuers) < 1 {
		t.Fatal("expected at least 1 issuer for leaf in cross-signing scenario")
	}
}

func TestBuildChainGraph_EmptyChain(t *testing.T) {
	repo := newSKILookupRepo()
	graph := buildChainGraph(context.Background(), repo, nil)
	if graph != nil {
		t.Error("expected nil graph for empty chain")
	}

	graph = buildChainGraph(context.Background(), repo, []*CertificateResult{})
	if graph != nil {
		t.Error("expected nil graph for zero-length chain")
	}
}

func TestIsSignatureSelfSigned(t *testing.T) {
	root := generateSelfSignedRoot(t, "Self-Signed Test")
	if !isSignatureSelfSigned(root.result) {
		t.Error("expected self-signed root to be detected")
	}

	inter := generateSignedIntermediate(t, "Not Self Signed", root)
	if isSignatureSelfSigned(inter.result) {
		t.Error("intermediate should not be self-signed")
	}

	// Nil parsed should return false
	nilResult := &CertificateResult{}
	if isSignatureSelfSigned(nilResult) {
		t.Error("nil parsed cert should not be self-signed")
	}
}
