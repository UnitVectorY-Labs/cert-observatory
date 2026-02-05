package web

import (
	"context"
	"encoding/hex"
)

// maxGraphDepth limits the depth of the chain graph to prevent infinite recursion.
const maxGraphDepth = 10

// ChainGraphNode represents a single certificate in the trust path tree.
type ChainGraphNode struct {
	// HashHex is the hex-encoded SHA-256 hash of the certificate (empty if missing).
	HashHex string
	// SubjectCN is the common name extracted from the subject.
	SubjectCN string
	// SubjectDN is the full subject distinguished name.
	SubjectDN string
	// IssuerDN is the full issuer distinguished name.
	IssuerDN string
	// InChain indicates the certificate was provided in the TLS handshake.
	InChain bool
	// IsSelfSigned indicates the certificate's own public key validates its signature.
	IsSelfSigned bool
	// IsMissing indicates the issuer was identified but no matching certificate was found.
	IsMissing bool
	// CertIndex is the index into ChainGraphData.AllCerts (-1 if missing).
	CertIndex int
	// Issuers are the certificates whose public key signed this certificate.
	Issuers []*ChainGraphNode
}

// ChainGraphData contains the complete trust path graph and all certificate details.
type ChainGraphData struct {
	// Root is the tree starting from the leaf certificate.
	Root *ChainGraphNode
	// AllCerts contains all unique certificates for detail display below the graph.
	AllCerts []*CertViewData
}

// chainGraphBuilder builds the certificate trust path graph.
type chainGraphBuilder struct {
	repo       Repository
	ctx        context.Context
	chainSet   map[string]bool            // hashes of certs in the TLS chain
	certCache  map[string]*CertificateResult // hash -> cert, avoids re-fetching
	allCerts   []*CertViewData            // accumulated unique certs for detail display
	certIndex  map[string]int             // hash -> index in allCerts
}

// buildChainGraph constructs the certificate trust path tree for display.
// It starts from the leaf certificate and recursively finds valid issuers
// from the database, validating actual cryptographic signatures.
func buildChainGraph(ctx context.Context, repo Repository, chainCerts []*CertificateResult) *ChainGraphData {
	if len(chainCerts) == 0 {
		return nil
	}

	builder := &chainGraphBuilder{
		repo:      repo,
		ctx:       ctx,
		chainSet:  make(map[string]bool),
		certCache: make(map[string]*CertificateResult),
		allCerts:  nil,
		certIndex: make(map[string]int),
	}

	// Populate chain set and cert cache from the provided chain
	for _, cert := range chainCerts {
		hashHex := hex.EncodeToString(cert.CertHash)
		builder.chainSet[hashHex] = true
		builder.certCache[hashHex] = cert
	}

	// Build the tree starting from the leaf
	root := builder.buildNode(chainCerts[0], make(map[string]bool), 0)

	if root == nil {
		return nil
	}

	return &ChainGraphData{
		Root:     root,
		AllCerts: builder.allCerts,
	}
}

// buildNode recursively builds a ChainGraphNode for a certificate.
func (b *chainGraphBuilder) buildNode(cert *CertificateResult, visited map[string]bool, depth int) *ChainGraphNode {
	if cert == nil || depth > maxGraphDepth {
		return nil
	}

	hashHex := hex.EncodeToString(cert.CertHash)

	// Prevent infinite loops
	if visited[hashHex] {
		return nil
	}
	visited[hashHex] = true

	// Register this certificate for detail display
	certIdx := b.registerCert(cert)

	selfSigned := isSignatureSelfSigned(cert)

	node := &ChainGraphNode{
		HashHex:      hashHex,
		SubjectCN:    extractCN(certSubjectDN(cert)),
		SubjectDN:    certSubjectDN(cert),
		IssuerDN:     certIssuerDN(cert),
		InChain:      b.chainSet[hashHex],
		IsSelfSigned: selfSigned,
		CertIndex:    certIdx,
	}

	// Self-signed certificates are roots; don't look for issuers
	if selfSigned {
		return node
	}

	// Find valid issuers from the database
	issuers := b.findValidIssuers(cert)

	if len(issuers) == 0 {
		// No issuer found - create a missing placeholder
		missingNode := &ChainGraphNode{
			SubjectDN: certIssuerDN(cert),
			SubjectCN: extractCN(certIssuerDN(cert)),
			IssuerDN:  "",
			IsMissing: true,
			CertIndex: -1,
		}
		node.Issuers = []*ChainGraphNode{missingNode}
	} else {
		for _, issuer := range issuers {
			// Clone visited set for each branch to allow divergent paths
			branchVisited := make(map[string]bool, len(visited))
			for k, v := range visited {
				branchVisited[k] = v
			}
			issuerNode := b.buildNode(issuer, branchVisited, depth+1)
			if issuerNode != nil {
				node.Issuers = append(node.Issuers, issuerNode)
			}
		}
	}

	return node
}

// findValidIssuers finds certificates from the database whose public key
// validates the signature on the given certificate.
func (b *chainGraphBuilder) findValidIssuers(cert *CertificateResult) []*CertificateResult {
	if cert.Parsed == nil {
		return nil
	}

	// Look up candidates by AKI -> SKI match
	if len(cert.AKI) > 0 {
		candidates, err := b.repo.FindCertificatesBySKI(b.ctx, cert.AKI)
		if err != nil {
			return nil
		}

		var valid []*CertificateResult
		for _, candidate := range candidates {
			if candidate.Parsed == nil {
				continue
			}
			// Validate the actual cryptographic signature
			if err := candidate.Parsed.CheckSignature(
				cert.Parsed.SignatureAlgorithm,
				cert.Parsed.RawTBSCertificate,
				cert.Parsed.Signature,
			); err == nil {
				hashHex := hex.EncodeToString(candidate.CertHash)
				b.certCache[hashHex] = candidate
				valid = append(valid, candidate)
			}
		}
		return valid
	}

	return nil
}

// registerCert adds a certificate to the allCerts list if not already present
// and returns its index.
func (b *chainGraphBuilder) registerCert(cert *CertificateResult) int {
	hashHex := hex.EncodeToString(cert.CertHash)
	if idx, ok := b.certIndex[hashHex]; ok {
		return idx
	}

	viewData := certToViewData(cert)
	idx := len(b.allCerts)
	b.allCerts = append(b.allCerts, viewData)
	b.certIndex[hashHex] = idx
	return idx
}

// isSignatureSelfSigned checks if a certificate's own public key validates
// its signature, which is the cryptographic definition of self-signed.
func isSignatureSelfSigned(cert *CertificateResult) bool {
	if cert.Parsed == nil {
		return false
	}
	err := cert.Parsed.CheckSignature(
		cert.Parsed.SignatureAlgorithm,
		cert.Parsed.RawTBSCertificate,
		cert.Parsed.Signature,
	)
	return err == nil
}

// certSubjectDN extracts the subject DN from a CertificateResult.
func certSubjectDN(cert *CertificateResult) string {
	if cert.Parsed != nil {
		return cert.Parsed.Subject.String()
	}
	return cert.Subject
}

// certIssuerDN extracts the issuer DN from a CertificateResult.
func certIssuerDN(cert *CertificateResult) string {
	if cert.Parsed != nil {
		return cert.Parsed.Issuer.String()
	}
	return cert.Issuer
}
