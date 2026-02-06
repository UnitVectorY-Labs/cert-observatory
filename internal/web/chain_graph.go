package web

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
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
	// IsExpired indicates the certificate is expired as of graph build time.
	IsExpired bool
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
	// MermaidDiagram is the flowchart source rendered by Mermaid.
	MermaidDiagram string
	// MermaidNodeToCertIndex maps Mermaid node IDs to AllCerts indices.
	MermaidNodeToCertIndex map[string]int
	// Legend controls which dynamic legend items are displayed.
	Legend ChainGraphLegend
}

// ChainGraphLegend indicates which node-type legend items are present in the graph.
type ChainGraphLegend struct {
	HasServerCertificate bool
	HasIntermediateCA    bool
	HasRootCA            bool
	HasMissing           bool
	HasExpired           bool
}

// chainGraphBuilder builds the certificate trust path graph.
type chainGraphBuilder struct {
	repo      Repository
	ctx       context.Context
	chainSet  map[string]bool // hashes of certs in the TLS chain
	allCerts  []*CertViewData // accumulated unique certs for detail display
	certIndex map[string]int  // hash -> index in allCerts
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
		allCerts:  nil,
		certIndex: make(map[string]int),
	}

	// Populate chain set from the provided chain
	for _, cert := range chainCerts {
		hashHex := hex.EncodeToString(cert.CertHash)
		builder.chainSet[hashHex] = true
	}

	// Build the tree starting from the leaf
	root := builder.buildNode(chainCerts[0], make(map[string]bool), 0)

	if root == nil {
		return nil
	}

	diagram, nodeToCertIdx, legend := buildMermaidDiagram(root)

	return &ChainGraphData{
		Root:                   root,
		AllCerts:               builder.allCerts,
		MermaidDiagram:         diagram,
		MermaidNodeToCertIndex: nodeToCertIdx,
		Legend:                 legend,
	}
}

// mermaidGraphBuilder converts ChainGraphNode trees into Mermaid flowchart syntax.
type mermaidGraphBuilder struct {
	nextNodeID      int
	nextMissingID   int
	leafHash        string
	nodeIDByHash    map[string]string
	nodeToCertIndex map[string]int
	inChainNodeSet  map[string]bool
	inChainNodeIDs  []string
	classMembers    map[string][]string
	edges           map[string]bool
	lines           []string
	hasExpired      bool
}

func buildMermaidDiagram(root *ChainGraphNode) (string, map[string]int, ChainGraphLegend) {
	if root == nil {
		return "", nil, ChainGraphLegend{}
	}

	b := &mermaidGraphBuilder{
		leafHash:        root.HashHex,
		nodeIDByHash:    make(map[string]string),
		nodeToCertIndex: make(map[string]int),
		inChainNodeSet:  make(map[string]bool),
		classMembers:    make(map[string][]string),
		edges:           make(map[string]bool),
		lines:           []string{"flowchart TB"},
	}

	b.walk(root)

	if len(b.inChainNodeIDs) > 0 {
		b.lines = append(b.lines,
			`subgraph tlsChain[" "]`,
			"direction TB",
		)
		for _, nodeID := range b.inChainNodeIDs {
			b.lines = append(b.lines, nodeID)
		}
		b.lines = append(b.lines,
			"end",
			"style tlsChain fill:#0f172a,stroke:#64748b,stroke-width:1px,stroke-dasharray:4 3;",
		)
	}

	for _, className := range []string{"leaf", "intermediate", "root", "missing", "interactive"} {
		ids, ok := b.classMembers[className]
		if !ok || len(ids) == 0 {
			continue
		}
		b.lines = append(b.lines, fmt.Sprintf("class %s %s;", strings.Join(ids, ","), className))
	}

	b.lines = append(b.lines,
		"classDef leaf fill:#3d2a12,stroke:#f97316,stroke-width:2px,color:#f8fafc;",
		"classDef intermediate fill:#102a47,stroke:#60a5fa,stroke-width:2px,color:#f8fafc;",
		"classDef root fill:#123524,stroke:#22c55e,stroke-width:2px,color:#f8fafc;",
		"classDef missing fill:#3b1212,stroke:#ef4444,stroke-width:2px,stroke-dasharray:5 3,color:#f8fafc;",
		"classDef interactive cursor:pointer;",
	)

	legend := ChainGraphLegend{
		HasServerCertificate: len(b.classMembers["leaf"]) > 0,
		HasIntermediateCA:    len(b.classMembers["intermediate"]) > 0,
		HasRootCA:            len(b.classMembers["root"]) > 0,
		HasMissing:           len(b.classMembers["missing"]) > 0,
		HasExpired:           b.hasExpired,
	}

	return strings.Join(b.lines, "\n"), b.nodeToCertIndex, legend
}

func (b *mermaidGraphBuilder) addClassMember(className, nodeID string) {
	b.classMembers[className] = append(b.classMembers[className], nodeID)
}

func (b *mermaidGraphBuilder) addInChainNode(nodeID string) {
	if b.inChainNodeSet[nodeID] {
		return
	}
	b.inChainNodeSet[nodeID] = true
	b.inChainNodeIDs = append(b.inChainNodeIDs, nodeID)
}

func (b *mermaidGraphBuilder) classifyNode(node *ChainGraphNode) string {
	switch {
	case node.IsMissing:
		return "missing"
	case node.HashHex == b.leafHash:
		return "leaf"
	case node.IsSelfSigned:
		return "root"
	default:
		return "intermediate"
	}
}

func (b *mermaidGraphBuilder) walk(node *ChainGraphNode) string {
	if node == nil {
		return ""
	}

	nodeID := b.ensureNode(node)
	for _, issuer := range node.Issuers {
		childID := b.walk(issuer)
		if childID == "" {
			continue
		}
		edgeKey := nodeID + "->" + childID
		if b.edges[edgeKey] {
			continue
		}
		b.edges[edgeKey] = true
		b.lines = append(b.lines, fmt.Sprintf("%s --> %s", nodeID, childID))
	}

	return nodeID
}

func (b *mermaidGraphBuilder) ensureNode(node *ChainGraphNode) string {
	if node == nil {
		return ""
	}

	if !node.IsMissing && node.HashHex != "" {
		if existingID, ok := b.nodeIDByHash[node.HashHex]; ok {
			return existingID
		}
	}

	var nodeID string
	if node.IsMissing {
		nodeID = fmt.Sprintf("m%d", b.nextMissingID)
		b.nextMissingID++
	} else {
		nodeID = fmt.Sprintf("n%d", b.nextNodeID)
		b.nextNodeID++
		b.nodeIDByHash[node.HashHex] = nodeID
	}

	label := node.SubjectCN
	if label == "" {
		label = node.SubjectDN
	}
	if label == "" {
		label = "(unknown subject)"
	}
	if node.IsExpired {
		label = "⛔ " + label
		b.hasExpired = true
	}
	label = escapeMermaidLabel(label)
	b.lines = append(b.lines, fmt.Sprintf("%s[\"%s\"]", nodeID, label))

	className := b.classifyNode(node)
	b.addClassMember(className, nodeID)
	if node.InChain {
		b.addInChainNode(nodeID)
	}

	if node.CertIndex >= 0 {
		b.nodeToCertIndex[nodeID] = node.CertIndex
		b.addClassMember("interactive", nodeID)
		b.lines = append(b.lines, fmt.Sprintf("click %s selectTrustPathCertFromMermaid \"View certificate details\"", nodeID))
	}

	return nodeID
}

func escapeMermaidLabel(label string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		`"`, `\"`,
		"\n", " ",
	)
	return replacer.Replace(label)
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
		IsExpired:    isExpiredAt(cert, time.Now()),
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

func isExpiredAt(cert *CertificateResult, now time.Time) bool {
	if cert == nil {
		return false
	}
	if cert.Parsed != nil {
		return now.After(cert.Parsed.NotAfter)
	}
	if cert.NotAfter.IsZero() {
		return false
	}
	return now.After(cert.NotAfter)
}
