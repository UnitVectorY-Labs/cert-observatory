package web

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/certutil"
	"github.com/UnitVectorY-Labs/cert-observatory/internal/domain"
)

// IndexData is the view model for the index page.
type IndexData struct {
	Results    *ResultsViewData
	Error      *ErrorData
	ManualMode bool
}

// handleIndex serves the main page (GET only, read-only, never triggers crawl).
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, manualMode := r.URL.Query()["manual"]
	if err := s.templates.ExecuteTemplate(w, "index.html", &IndexData{ManualMode: manualMode}); err != nil {
		s.logger.Error("failed to render index", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// maxManualCerts is the maximum number of certificates that can be uploaded at once
// via the manual import feature.
const maxManualCerts = 5

// handleManualCert handles manual PEM certificate upload (POST only).
// This is a "secret" feature unlocked by visiting /?manual.
// Accepts 1 to maxManualCerts PEM CERTIFICATE blocks. Each certificate must be
// currently valid and independently trace to a trusted certificate already in
// the database, optionally using other uploaded certificates as intermediates.
func (s *Server) handleManualCert(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderManualError(w, r, "Invalid Request", "Could not parse form data.", http.StatusBadRequest)
		return
	}

	pemText := strings.TrimSpace(r.FormValue("pem"))
	if pemText == "" {
		s.renderManualError(w, r, "No Certificate", "Please paste at least one PEM-encoded certificate.", http.StatusBadRequest)
		return
	}

	// Decode all PEM blocks, accepting only CERTIFICATE blocks.
	var x509Certs []*x509.Certificate
	remaining := []byte(pemText)
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			s.renderManualError(w, r, "Invalid PEM", fmt.Sprintf("Only CERTIFICATE PEM blocks are accepted, got %q.", block.Type), http.StatusBadRequest)
			return
		}
		if len(x509Certs) >= maxManualCerts {
			s.renderManualError(w, r, "Too Many Certificates", fmt.Sprintf("A maximum of %d certificates can be uploaded at once.", maxManualCerts), http.StatusBadRequest)
			return
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			s.renderManualError(w, r, "Invalid Certificate", "Could not parse certificate: "+err.Error(), http.StatusBadRequest)
			return
		}
		x509Certs = append(x509Certs, parsed)
	}

	// Reject non-whitespace trailing data that could not be decoded as PEM.
	// This check only applies when at least one certificate was already parsed;
	// if no certs were found at all the "Invalid PEM" check below provides a
	// better error message.
	if len(x509Certs) > 0 && len(strings.TrimSpace(string(remaining))) > 0 {
		s.renderManualError(w, r, "Unexpected Data", "Only PEM CERTIFICATE blocks are allowed. Please remove any non-PEM trailing data.", http.StatusBadRequest)
		return
	}

	if len(x509Certs) == 0 {
		s.renderManualError(w, r, "Invalid PEM", "Could not decode any PEM data. Please provide valid PEM-encoded certificates.", http.StatusBadRequest)
		return
	}

	// Build CertificateResult objects and store every certificate in the database.
	uploaded := make([]*CertificateResult, len(x509Certs))
	uploadedBySKI := make(map[string][]*CertificateResult)
	for i, x509Cert := range x509Certs {
		certInfo := certutil.ParseX509Certificate(x509Cert)
		uploaded[i] = &CertificateResult{
			CertHash:  certInfo.CertHash,
			DER:       certInfo.DER,
			PEM:       certInfo.PEM(),
			Subject:   certInfo.Subject,
			Issuer:    certInfo.Issuer,
			NotBefore: certInfo.NotBefore,
			NotAfter:  certInfo.NotAfter,
			SKI:       certInfo.SKI,
			AKI:       certInfo.AKI,
			Parsed:    certInfo.Parsed,
			Position:  i + 1,
		}
		if len(uploaded[i].SKI) > 0 {
			uploadedBySKI[string(uploaded[i].SKI)] = append(uploadedBySKI[string(uploaded[i].SKI)], uploaded[i])
		}
	}

	now := time.Now()
	for i, cert := range uploaded {
		if err := s.validateManualCertificate(r.Context(), cert, uploadedBySKI, now, map[string]bool{}); err != nil {
			s.renderManualError(w, r, "Untrusted Certificate",
				fmt.Sprintf("Certificate %d (%s) is not acceptable for manual import: %v", i+1, certSubjectDN(cert), err),
				http.StatusBadRequest)
			return
		}
	}

	for _, cert := range uploaded {
		if err := s.repo.StoreCertificate(r.Context(), cert); err != nil {
			s.logger.Error("failed to store manual certificate", "error", err)
			s.renderManualError(w, r, "Storage Error", "Could not store the certificate.", http.StatusInternalServerError)
			return
		}
	}

	// ShowNonChainCerts is always true for manual mode — expanding the trust path
	// via the DB is the primary purpose of this feature.
	// ShowExpired is driven by the user's checkbox selection.
	filters := ChainGraphFilters{
		ShowNonChainCerts: true,
		ShowExpired:       r.FormValue("showExpired") == "true",
	}

	// Use the leaf (first) certificate's CN as the display name.
	leafInfo := certutil.ParseX509Certificate(x509Certs[0])
	subjectCN := extractCN(leafInfo.Subject)
	if subjectCN == "" {
		subjectCN = leafInfo.Subject
	}

	data := &ResultsViewData{
		Domain:   subjectCN,
		IsManual: true,
	}

	for _, cert := range uploaded {
		viewData := certToViewData(cert)
		// Assign an appropriate label based on the actual certificate type rather than
		// defaulting to "Server Certificate" (which is misleading for CA/intermediate certs).
		if viewData.IsSelfSigned {
			viewData.CertLabel = "Self Signed Certificate"
		} else if viewData.IsCA {
			viewData.CertLabel = "Intermediate CA"
		} else {
			viewData.CertLabel = "End-Entity Certificate"
		}
		data.Chain = append(data.Chain, viewData)
	}

	// Pass all uploaded certs so they are all marked "in chain" in the Mermaid diagram,
	// matching the grouping used when a server returns multiple certificates.
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, uploaded, filters)
	data.DownloadURL = buildManualDownloadURL(hex.EncodeToString(uploaded[0].CertHash), filters)

	s.renderManualResults(w, r, data)
}

func (s *Server) validateManualCertificate(ctx context.Context, cert *CertificateResult, uploadedBySKI map[string][]*CertificateResult, now time.Time, visiting map[string]bool) error {
	if cert == nil || cert.Parsed == nil {
		return fmt.Errorf("certificate could not be parsed")
	}
	if now.Before(cert.Parsed.NotBefore) {
		return fmt.Errorf("certificate is not valid until %s", cert.Parsed.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.Parsed.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.Parsed.NotAfter.Format(time.RFC3339))
	}

	hash := hex.EncodeToString(cert.CertHash)
	if visiting[hash] {
		return fmt.Errorf("issuer path contains a cycle")
	}

	lookupKey := cert.AKI
	if len(lookupKey) == 0 {
		if isSignatureSelfSigned(cert) {
			lookupKey = cert.SKI
		}
		if len(lookupKey) == 0 {
			return fmt.Errorf("certificate does not have an Authority Key Identifier (AKI) extension")
		}
	}

	visiting[hash] = true
	defer delete(visiting, hash)

	for _, candidate := range uploadedBySKI[string(lookupKey)] {
		if candidate == nil || candidate.Parsed == nil {
			continue
		}
		if string(candidate.CertHash) == string(cert.CertHash) {
			continue
		}
		if err := cert.Parsed.CheckSignatureFrom(candidate.Parsed); err != nil {
			continue
		}
		if err := s.validateManualCertificate(ctx, candidate, uploadedBySKI, now, visiting); err == nil {
			return nil
		}
	}

	dbCandidates, err := s.repo.FindCertificatesBySKI(ctx, lookupKey)
	if err != nil {
		return fmt.Errorf("look up issuer certificates: %w", err)
	}

	for _, candidate := range dbCandidates {
		if candidate == nil || candidate.Parsed == nil {
			continue
		}
		if err := cert.Parsed.CheckSignatureFrom(candidate.Parsed); err != nil {
			continue
		}
		if string(candidate.CertHash) == string(cert.CertHash) && isSignatureSelfSigned(candidate) {
			return nil
		}
		if err := s.validateManualCertificate(ctx, candidate, uploadedBySKI, now, visiting); err == nil {
			return nil
		}
	}

	return fmt.Errorf("no valid issuer path to a trusted root was found")
}

func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// handleInspect handles domain inspection requests (POST only, can trigger crawl).
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, "Invalid Request", "Could not parse form data.", http.StatusBadRequest)
		return
	}

	rawDomain := r.FormValue("domain")
	target, err := domain.NormalizeAndValidateTarget(rawDomain, true)
	if err != nil {
		s.renderError(w, r, "Invalid Domain", formatDomainError(err), http.StatusBadRequest)
		return
	}
	normalizedDomain := target.Domain
	port := target.Port

	// Parse filter options
	filters := parseChainGraphFilters(r)

	// Check for IP literals (SSRF prevention)
	if isIPLiteral(normalizedDomain) {
		s.renderError(w, r, "Invalid Domain", "IP addresses are not allowed. Please enter a domain name.", http.StatusBadRequest)
		return
	}

	// Check for reserved domains (RFC 2606, .local, .onion, etc.)
	if reservedInfo := domain.CheckReservedDomain(normalizedDomain); reservedInfo != nil {
		s.renderReservedDomainError(w, r, reservedInfo)
		return
	}

	// Check if we need to crawl or can use cached data
	canRefresh, _, err := s.repo.CanStandardRefreshForPort(r.Context(), normalizedDomain, port, s.config.StandardRefreshWindow)
	if err != nil {
		s.logger.Error("failed to check refresh eligibility", "domain", normalizedDomain, "error", err)
	}

	// Try to get existing data first
	domainResult, err := s.repo.GetDomainWithChainForPort(r.Context(), normalizedDomain, port)

	if err == nil && domainResult != nil && domainResult.HasChain && !canRefresh {
		// Use cached data
		s.renderCachedResults(w, r, domainResult, false, filters)
		return
	}

	// Need to crawl
	result, crawlErr := s.performCrawl(r.Context(), normalizedDomain, port, false)
	if crawlErr != nil {
		s.logger.Warn("crawl failed", "domain", normalizedDomain, "error", crawlErr)

		// If we have cached data, show it with an error notice
		if domainResult != nil && domainResult.HasChain {
			s.renderCachedResultsWithError(w, r, domainResult, crawlErr, filters)
			return
		}

		s.renderError(w, r, "Crawl Failed", formatCrawlError(crawlErr), http.StatusOK)
		return
	}

	// Render fresh results
	s.renderFreshResults(w, r, result, filters)
}

// handleRefresh handles force refresh requests (POST only, can trigger crawl).
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, "Invalid Request", "Could not parse form data.", http.StatusBadRequest)
		return
	}

	rawDomain := r.FormValue("domain")
	target, err := domain.NormalizeAndValidateTarget(rawDomain, true)
	if err != nil {
		s.renderError(w, r, "Invalid Domain", formatDomainError(err), http.StatusBadRequest)
		return
	}
	normalizedDomain := target.Domain
	port := target.Port

	// Use default filters for refresh (show everything)
	// Note: Force refresh intentionally shows all certificates to give users
	// the most complete view of the certificate chain when they explicitly
	// request a fresh crawl. Users can adjust filters on subsequent inspects.
	filters := ChainGraphFilters{
		ShowNonChainCerts: true,
		ShowExpired:       true,
	}

	// Check if forced refresh is allowed
	canForce, waitTime, err := s.repo.CanForcedRefreshForPort(r.Context(), normalizedDomain, port, s.config.ForcedRefreshWindow)
	if err != nil {
		s.logger.Error("failed to check forced refresh eligibility", "domain", normalizedDomain, "error", err)
		s.renderError(w, r, "Error", "Could not verify refresh eligibility.", http.StatusInternalServerError)
		return
	}

	if !canForce {
		s.renderError(w, r, "Refresh Not Available", fmt.Sprintf("Force refresh will be available in %s.", formatDuration(waitTime)), http.StatusTooManyRequests)
		return
	}

	// Perform forced crawl
	result, crawlErr := s.performCrawl(r.Context(), normalizedDomain, port, true)
	if crawlErr != nil {
		s.logger.Warn("forced crawl failed", "domain", normalizedDomain, "error", crawlErr)

		// Try to get cached data
		domainResult, _ := s.repo.GetDomainWithChainForPort(r.Context(), normalizedDomain, port)
		if domainResult != nil && domainResult.HasChain {
			s.renderCachedResultsWithError(w, r, domainResult, crawlErr, filters)
			return
		}

		s.renderError(w, r, "Crawl Failed", formatCrawlError(crawlErr), http.StatusOK)
		return
	}

	s.renderFreshResults(w, r, result, filters)
}

// handleCertDetails returns certificate details for a specific cert.
func (s *Server) handleCertDetails(w http.ResponseWriter, r *http.Request) {
	hashHex := r.PathValue("hash")
	if hashHex == "" {
		http.Error(w, "Missing certificate hash", http.StatusBadRequest)
		return
	}

	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		http.Error(w, "Invalid certificate hash", http.StatusBadRequest)
		return
	}

	cert, err := s.repo.GetCertificateByHash(r.Context(), hash)
	if err != nil {
		s.logger.Error("failed to get certificate", "hash", hashHex, "error", err)
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	viewData := certToViewData(cert)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "cert_details", viewData); err != nil {
		s.logger.Error("failed to render cert details", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// performCrawl executes a crawl with locking.
func (s *Server) performCrawl(ctx context.Context, domainName string, port int, forced bool) (*CrawlOutput, error) {
	lockID := generateLockID()
	lockTTL := s.config.CrawlTimeout + 10*time.Second

	// Try to acquire lock
	acquired, err := s.repo.AcquireLockForPort(ctx, domainName, port, lockID, lockTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		// Another crawl is in progress, wait a bit and try to get cached results
		time.Sleep(2 * time.Second)
		domainResult, err := s.repo.GetDomainWithChainForPort(ctx, domainName, port)
		if err == nil && domainResult != nil && domainResult.HasChain {
			// Return the cached data as if it was a fresh crawl
			return &CrawlOutput{
				Domain: domainName,
				Port:   port,
				Chain:  domainResult.Chain,
			}, nil
		}
		return nil, fmt.Errorf("another crawl in progress")
	}

	// Ensure lock is released
	defer func() {
		if err := s.repo.ReleaseLockForPort(ctx, domainName, port, lockID); err != nil {
			s.logger.Warn("failed to release lock", "domain", domainName, "error", err)
		}
	}()

	// Create context with timeout
	crawlCtx, cancel := context.WithTimeout(ctx, s.config.CrawlTimeout)
	defer cancel()

	// Perform crawl
	result, err := s.crawler.CrawlPort(crawlCtx, domainName, port)
	if err != nil {
		// Record failure
		s.repo.RecordCrawlResult(ctx, &CrawlResultInput{
			Domain:  domainName,
			Port:    port,
			Success: false,
			Forced:  forced,
		})
		return nil, err
	}

	// Record success
	if err := s.repo.RecordCrawlResult(ctx, &CrawlResultInput{
		Domain:  domainName,
		Port:    port,
		Success: true,
		Forced:  forced,
		Chain:   result.Chain,
	}); err != nil {
		s.logger.Error("failed to record crawl result", "domain", domainName, "error", err)
		// Don't fail the request, we still have the result
	}

	return result, nil
}

// ErrorData is the view model for error display.
type ErrorData struct {
	Title            string
	Message          string
	MessageHTML      string // HTML message (for RFC links, etc.)
	HasCachedResults bool
}

// renderError renders an error message.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, title, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	errData := &ErrorData{
		Title:   title,
		Message: message,
	}

	// For HTMX requests, just render the error fragment
	if isHTMXRequest(r) {
		if err := s.templates.ExecuteTemplate(w, "error", errData); err != nil {
			s.logger.Error("failed to render error template", "error", err)
			fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", title, message)
		}
		return
	}

	// For regular requests, render full page with error
	pageData := &IndexData{Error: errData}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render error page", "error", err)
		fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", title, message)
	}
}

// renderReservedDomainError renders an error for reserved domain names.
func (s *Server) renderReservedDomainError(w http.ResponseWriter, r *http.Request, info *domain.ReservedDomainInfo) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)

	// Build HTML message with RFC link
	messageHTML := info.Reason
	if info.RFCLink != "" {
		messageHTML += fmt.Sprintf(` See <a href="%s" target="_blank" rel="noopener noreferrer">the relevant RFC</a> for more information.`, info.RFCLink)
	}

	errData := &ErrorData{
		Title:       "Reserved Domain",
		Message:     info.Reason,
		MessageHTML: messageHTML,
	}

	// For HTMX requests, just render the error fragment
	if isHTMXRequest(r) {
		if err := s.templates.ExecuteTemplate(w, "error", errData); err != nil {
			s.logger.Error("failed to render error template", "error", err)
			fmt.Fprintf(w, "<div class=\"error-block\"><h4>Reserved Domain</h4><p>%s</p></div>", info.Reason)
		}
		return
	}

	// For regular requests, render full page with error
	pageData := &IndexData{Error: errData}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render error page", "error", err)
		fmt.Fprintf(w, "<div class=\"error-block\"><h4>Reserved Domain</h4><p>%s</p></div>", info.Reason)
	}
}

// renderManualError renders an error in the context of the manual upload page.
func (s *Server) renderManualError(w http.ResponseWriter, r *http.Request, title, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	errData := &ErrorData{
		Title:   title,
		Message: message,
	}

	if isHTMXRequest(r) {
		if err := s.templates.ExecuteTemplate(w, "error", errData); err != nil {
			s.logger.Error("failed to render error template", "error", err)
			fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", html.EscapeString(title), html.EscapeString(message))
		}
		return
	}

	pageData := &IndexData{Error: errData, ManualMode: true}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render error page", "error", err)
		fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", html.EscapeString(title), html.EscapeString(message))
	}
}
func (s *Server) renderCachedResults(w http.ResponseWriter, r *http.Request, result *DomainResult, lastCrawlFailed bool, filters ChainGraphFilters) {
	canForce, waitTime, _ := s.repo.CanForcedRefreshForPort(r.Context(), result.Domain, result.Port, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(result, true, canForce, waitTime, lastCrawlFailed)

	// Build the chain graph from the chain certificates
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, result.Chain, filters)
	data.DownloadURL = buildNormalDownloadURL(result.Domain, result.Port, filters)

	s.renderResults(w, r, data)
}

// renderCachedResultsWithError renders cached results with an error notice.
func (s *Server) renderCachedResultsWithError(w http.ResponseWriter, r *http.Request, result *DomainResult, crawlErr error, filters ChainGraphFilters) {
	s.renderCachedResults(w, r, result, true, filters)
}

// renderFreshResults renders fresh crawl results.
func (s *Server) renderFreshResults(w http.ResponseWriter, r *http.Request, result *CrawlOutput, filters ChainGraphFilters) {
	// Convert crawl output to domain result format
	domainResult := &DomainResult{
		Domain:    result.Domain,
		Port:      result.Port,
		HasChain:  len(result.Chain) > 0,
		Chain:     result.Chain,
		UpdatedAt: time.Now(),
	}

	canForce, waitTime, _ := s.repo.CanForcedRefreshForPort(r.Context(), result.Domain, result.Port, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(domainResult, false, canForce, waitTime, false)

	// Build the chain graph from the chain certificates
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, result.Chain, filters)
	data.DownloadURL = buildNormalDownloadURL(result.Domain, result.Port, filters)

	s.renderResults(w, r, data)
}

// renderResults renders results, either as a fragment for HTMX or as a full page for regular requests.
func (s *Server) renderResults(w http.ResponseWriter, r *http.Request, data *ResultsViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// If HTMX request, render just the results fragment
	if isHTMXRequest(r) {
		if err := s.templates.ExecuteTemplate(w, "results", data); err != nil {
			s.logger.Error("failed to render results", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Otherwise, render the full page with results
	pageData := &IndexData{Results: data}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render full page with results", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// renderManualResults renders manual import results, keeping ManualMode=true for full-page responses.
func (s *Server) renderManualResults(w http.ResponseWriter, r *http.Request, data *ResultsViewData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// If HTMX request, render just the results fragment
	if isHTMXRequest(r) {
		if err := s.templates.ExecuteTemplate(w, "results", data); err != nil {
			s.logger.Error("failed to render manual results", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// For full-page responses keep ManualMode=true so the PEM textarea is shown again
	pageData := &IndexData{Results: data, ManualMode: true}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render manual full page with results", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Helper functions

func parseChainGraphFilters(r *http.Request) ChainGraphFilters {
	// Default values: ShowNonChainCerts=true, ShowExpired=false
	// Checkboxes only send value when checked
	return ChainGraphFilters{
		ShowNonChainCerts: r.FormValue("showNonChainCerts") == "true",
		ShowExpired:       r.FormValue("showExpired") == "true",
	}
}

func generateLockID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// This should never happen with crypto/rand, but handle gracefully
		// Use a timestamp-based fallback
		b = []byte(fmt.Sprintf("%x", time.Now().UnixNano()))
	}
	return hex.EncodeToString(b)
}

func isIPLiteral(s string) bool {
	// Check for IPv4
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		allDigits := true
		for _, part := range parts {
			for _, c := range part {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
		}
		if allDigits {
			return true
		}
	}

	// Check for IPv6 (contains colons, but domain validation already rejects these)
	return strings.Contains(s, ":")
}

func formatDomainError(err error) string {
	switch err {
	case domain.ErrEmptyDomain:
		return "Please enter a domain name."
	case domain.ErrDomainTooLong:
		return "Domain name is too long (maximum 253 characters)."
	case domain.ErrDomainHasScheme:
		return "Please enter just the domain name without http:// or https://."
	case domain.ErrDomainHasPort:
		return "Please enter a valid domain name."
	case domain.ErrInvalidPort:
		return "Port must be a number between 1 and 65535."
	case domain.ErrDomainHasPath:
		return "Please enter just the domain name without any path."
	case domain.ErrDomainHasQuery:
		return "Please enter just the domain name without query parameters."
	case domain.ErrDomainInvalidChars:
		return "Domain contains invalid characters."
	default:
		return "Invalid domain name format."
	}
}

func formatCrawlError(err error) string {
	errStr := err.Error()
	if strings.Contains(errStr, "tcp connect") {
		return "Connection failed. The server may be unreachable."
	}
	if strings.Contains(errStr, "tls handshake") {
		return "TLS handshake failed. The server may not support TLS."
	}
	if strings.Contains(errStr, "no certificates") {
		return "No certificates were returned by the server."
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		return "Connection timed out."
	}
	return "Failed to retrieve certificate chain."
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	hours := int(d.Hours())
	if hours == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", hours)
}

// buildNormalDownloadURL constructs the server-side download URL for a domain.
func buildNormalDownloadURL(domainName string, port int, filters ChainGraphFilters) string {
	params := url.Values{}
	params.Set("domain", domainName)
	if port != 0 && port != 443 {
		params.Set("port", fmt.Sprintf("%d", port))
	}
	if filters.ShowNonChainCerts {
		params.Set("showNonChainCerts", "true")
	}
	if filters.ShowExpired {
		params.Set("showExpired", "true")
	}
	return "/download?" + params.Encode()
}

// buildManualDownloadURL constructs the server-side download URL for a manually imported cert.
func buildManualDownloadURL(leafHashHex string, filters ChainGraphFilters) string {
	params := url.Values{}
	params.Set("cert", leafHashHex)
	if filters.ShowExpired {
		params.Set("showExpired", "true")
	}
	return "/download?" + params.Encode()
}

// sanitizeDownloadFilename removes unsafe characters from a filename base.
func sanitizeDownloadFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	result := b.String()
	if result == "" {
		return "certificates"
	}
	return result
}

// handleDownload serves a PEM bundle of all certificates in the trust path graph.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	domainParam := r.URL.Query().Get("domain")
	certHashHex := r.URL.Query().Get("cert")

	var chainCerts []*CertificateResult
	var filters ChainGraphFilters
	var filenameBase string

	if domainParam != "" {
		target, err := domain.NormalizeAndValidateTarget(domainParam, false)
		if err != nil {
			http.Error(w, "Invalid domain", http.StatusBadRequest)
			return
		}
		if portParam := r.URL.Query().Get("port"); portParam != "" {
			target, err = domain.NormalizeAndValidateTarget(domainParam+":"+portParam, true)
			if err != nil {
				http.Error(w, "Invalid port", http.StatusBadRequest)
				return
			}
		}
		domainResult, err := s.repo.GetDomainWithChainForPort(r.Context(), target.Domain, target.Port)
		if err != nil || domainResult == nil || !domainResult.HasChain {
			http.Error(w, "Domain not found", http.StatusNotFound)
			return
		}
		chainCerts = domainResult.Chain
		filters = ChainGraphFilters{
			ShowNonChainCerts: r.URL.Query().Get("showNonChainCerts") == "true",
			ShowExpired:       r.URL.Query().Get("showExpired") == "true",
		}
		filenameBase = formatTarget(target.Domain, target.Port)
	} else if certHashHex != "" {
		hash, err := hex.DecodeString(certHashHex)
		if err != nil || len(hash) != 32 {
			http.Error(w, "Invalid cert hash", http.StatusBadRequest)
			return
		}
		cert, err := s.repo.GetCertificateByHash(r.Context(), hash)
		if err != nil {
			http.Error(w, "Certificate not found", http.StatusNotFound)
			return
		}
		chainCerts = []*CertificateResult{cert}
		filters = ChainGraphFilters{
			ShowNonChainCerts: true,
			ShowExpired:       r.URL.Query().Get("showExpired") == "true",
		}
		viewData := certToViewData(cert)
		filenameBase = viewData.SubjectCN
		if filenameBase == "" {
			filenameBase = "certificate"
		}
	} else {
		http.Error(w, "Missing domain or cert parameter", http.StatusBadRequest)
		return
	}

	graph := buildChainGraph(r.Context(), s.repo, chainCerts, filters)
	if graph == nil || len(graph.AllCerts) == 0 {
		http.Error(w, "No certificates found", http.StatusNotFound)
		return
	}

	var buf strings.Builder
	for _, cert := range graph.AllCerts {
		cn := cert.SubjectCN
		if cn == "" {
			cn = cert.SubjectDN
		}
		if cn == "" {
			cn = "(unknown)"
		}
		// Sanitize the CN so it cannot inject newlines into the PEM comment line.
		cn = strings.NewReplacer("\r", " ", "\n", " ").Replace(cn)
		buf.WriteString("# " + cn + "\n")
		buf.WriteString(strings.TrimSpace(cert.PEM) + "\n")
	}

	safeBase := sanitizeDownloadFilename(filenameBase)
	filename := safeBase + "-certificates.pem"

	w.Header().Set("Content-Type", "application/x-pem-file")
	// sanitizeDownloadFilename strips all characters that could break the quoted filename
	// parameter; the explicit quote escaping here adds a defense-in-depth layer.
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filename, `"`, `\"`)+`"`)
	fmt.Fprint(w, buf.String())
}
