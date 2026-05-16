package web

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
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

// handleManualCert handles manual PEM certificate upload (POST only).
// This is a "secret" feature unlocked by visiting /?manual.
func (s *Server) handleManualCert(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderManualError(w, r, "Invalid Request", "Could not parse form data.", http.StatusBadRequest)
		return
	}

	pemText := strings.TrimSpace(r.FormValue("pem"))
	if pemText == "" {
		s.renderManualError(w, r, "No Certificate", "Please paste a PEM-encoded certificate.", http.StatusBadRequest)
		return
	}

	// Decode the PEM block
	block, rest := pem.Decode([]byte(pemText))
	if block == nil {
		s.renderManualError(w, r, "Invalid PEM", "Could not decode PEM data. Please provide a valid PEM-encoded certificate.", http.StatusBadRequest)
		return
	}
	if block.Type != "CERTIFICATE" {
		s.renderManualError(w, r, "Invalid PEM", fmt.Sprintf("Expected a CERTIFICATE block, got %q.", block.Type), http.StatusBadRequest)
		return
	}
	// Only one certificate is allowed
	if extraBlock, _ := pem.Decode(rest); extraBlock != nil && extraBlock.Type == "CERTIFICATE" {
		s.renderManualError(w, r, "Multiple Certificates", "Only a single PEM certificate is allowed. Please provide exactly one certificate.", http.StatusBadRequest)
		return
	}

	// Parse the DER bytes
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.renderManualError(w, r, "Invalid Certificate", "Could not parse the certificate: "+err.Error(), http.StatusBadRequest)
		return
	}

	certInfo := certutil.ParseX509Certificate(x509Cert)

	// Build a CertificateResult from the parsed certificate
	uploaded := &CertificateResult{
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
		Position:  1,
	}

	// Validate: the certificate MUST be signed by a trusted cert already in the DB.
	// Self-signed certificates are not accepted unless they are already a trusted root in the DB
	// that signs themselves (which would be found as their own issuer, but self-signed uploads
	// are rejected per spec - "it MUST be valid" means issued by something trusted).
	if isSignatureSelfSigned(uploaded) {
		s.renderManualError(w, r, "Self-Signed Certificate", "Self-signed certificates cannot be uploaded via manual import. The certificate must be signed by a trusted certificate already in the database.", http.StatusBadRequest)
		return
	}

	// Look up valid issuers from the DB using AKI→SKI matching + signature verification
	if len(uploaded.AKI) == 0 {
		s.renderManualError(w, r, "Untrusted Certificate", "The certificate does not have an Authority Key Identifier (AKI) extension. Cannot verify its issuer.", http.StatusBadRequest)
		return
	}

	candidates, err := s.repo.FindCertificatesBySKI(r.Context(), uploaded.AKI)
	if err != nil {
		s.logger.Error("failed to look up issuer candidates", "error", err)
		s.renderManualError(w, r, "Database Error", "Could not look up issuer certificates.", http.StatusInternalServerError)
		return
	}

	trusted := false
	for _, candidate := range candidates {
		if candidate.Parsed == nil {
			continue
		}
		if err := candidate.Parsed.CheckSignature(
			x509Cert.SignatureAlgorithm,
			x509Cert.RawTBSCertificate,
			x509Cert.Signature,
		); err == nil {
			trusted = true
			break
		}
	}

	if !trusted {
		s.renderManualError(w, r, "Untrusted Certificate", "The certificate is not signed by any trusted certificate in the database. Only certificates with a valid chain of trust can be uploaded.", http.StatusBadRequest)
		return
	}

	// Store the certificate in the database
	if err := s.repo.StoreCertificate(r.Context(), uploaded); err != nil {
		s.logger.Error("failed to store manual certificate", "error", err)
		s.renderManualError(w, r, "Storage Error", "Could not store the certificate.", http.StatusInternalServerError)
		return
	}

	// Build and render the chain graph starting from the uploaded certificate
	filters := ChainGraphFilters{
		ShowNonChainCerts: true,
		ShowExpired:       true,
	}

	subjectCN := extractCN(certInfo.Subject)
	if subjectCN == "" {
		subjectCN = certInfo.Subject
	}

	data := &ResultsViewData{
		Domain:   subjectCN,
		IsManual: true,
	}
	data.Chain = []*CertViewData{certToViewData(uploaded)}
	assignChainLabelsAndColors(data.Chain)
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, []*CertificateResult{uploaded}, filters)

	s.renderResults(w, r, data)
}

// isHTMXRequest checks if the request is an HTMX request.
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
	normalizedDomain, err := domain.NormalizeAndValidate(rawDomain)
	if err != nil {
		s.renderError(w, r, "Invalid Domain", formatDomainError(err), http.StatusBadRequest)
		return
	}

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
	canRefresh, _, err := s.repo.CanStandardRefresh(r.Context(), normalizedDomain, s.config.StandardRefreshWindow)
	if err != nil {
		s.logger.Error("failed to check refresh eligibility", "domain", normalizedDomain, "error", err)
	}

	// Try to get existing data first
	domainResult, err := s.repo.GetDomainWithChain(r.Context(), normalizedDomain)

	if err == nil && domainResult != nil && domainResult.HasChain && !canRefresh {
		// Use cached data
		s.renderCachedResults(w, r, domainResult, false, filters)
		return
	}

	// Need to crawl
	result, crawlErr := s.performCrawl(r.Context(), normalizedDomain, false)
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
	normalizedDomain, err := domain.NormalizeAndValidate(rawDomain)
	if err != nil {
		s.renderError(w, r, "Invalid Domain", formatDomainError(err), http.StatusBadRequest)
		return
	}

	// Use default filters for refresh (show everything)
	// Note: Force refresh intentionally shows all certificates to give users
	// the most complete view of the certificate chain when they explicitly
	// request a fresh crawl. Users can adjust filters on subsequent inspects.
	filters := ChainGraphFilters{
		ShowNonChainCerts: true,
		ShowExpired:       true,
	}

	// Check if forced refresh is allowed
	canForce, waitTime, err := s.repo.CanForcedRefresh(r.Context(), normalizedDomain, s.config.ForcedRefreshWindow)
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
	result, crawlErr := s.performCrawl(r.Context(), normalizedDomain, true)
	if crawlErr != nil {
		s.logger.Warn("forced crawl failed", "domain", normalizedDomain, "error", crawlErr)

		// Try to get cached data
		domainResult, _ := s.repo.GetDomainWithChain(r.Context(), normalizedDomain)
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
func (s *Server) performCrawl(ctx context.Context, domainName string, forced bool) (*CrawlOutput, error) {
	lockID := generateLockID()
	lockTTL := s.config.CrawlTimeout + 10*time.Second

	// Try to acquire lock
	acquired, err := s.repo.AcquireLock(ctx, domainName, lockID, lockTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}

	if !acquired {
		// Another crawl is in progress, wait a bit and try to get cached results
		time.Sleep(2 * time.Second)
		domainResult, err := s.repo.GetDomainWithChain(ctx, domainName)
		if err == nil && domainResult != nil && domainResult.HasChain {
			// Return the cached data as if it was a fresh crawl
			return &CrawlOutput{
				Domain: domainName,
				Chain:  domainResult.Chain,
			}, nil
		}
		return nil, fmt.Errorf("another crawl in progress")
	}

	// Ensure lock is released
	defer func() {
		if err := s.repo.ReleaseLock(ctx, domainName, lockID); err != nil {
			s.logger.Warn("failed to release lock", "domain", domainName, "error", err)
		}
	}()

	// Create context with timeout
	crawlCtx, cancel := context.WithTimeout(ctx, s.config.CrawlTimeout)
	defer cancel()

	// Perform crawl
	result, err := s.crawler.Crawl(crawlCtx, domainName)
	if err != nil {
		// Record failure
		s.repo.RecordCrawlResult(ctx, &CrawlResultInput{
			Domain:  domainName,
			Success: false,
			Forced:  forced,
		})
		return nil, err
	}

	// Record success
	if err := s.repo.RecordCrawlResult(ctx, &CrawlResultInput{
		Domain:  domainName,
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
			fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", title, message)
		}
		return
	}

	pageData := &IndexData{Error: errData, ManualMode: true}
	if err := s.templates.ExecuteTemplate(w, "index.html", pageData); err != nil {
		s.logger.Error("failed to render error page", "error", err)
		fmt.Fprintf(w, "<div class=\"error-block\"><h4>%s</h4><p>%s</p></div>", title, message)
	}
}
func (s *Server) renderCachedResults(w http.ResponseWriter, r *http.Request, result *DomainResult, lastCrawlFailed bool, filters ChainGraphFilters) {
	canForce, waitTime, _ := s.repo.CanForcedRefresh(r.Context(), result.Domain, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(result, true, canForce, waitTime, lastCrawlFailed)

	// Build the chain graph from the chain certificates
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, result.Chain, filters)

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
		HasChain:  len(result.Chain) > 0,
		Chain:     result.Chain,
		UpdatedAt: time.Now(),
	}

	canForce, waitTime, _ := s.repo.CanForcedRefresh(r.Context(), result.Domain, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(domainResult, false, canForce, waitTime, false)

	// Build the chain graph from the chain certificates
	data.ChainGraph = buildChainGraph(r.Context(), s.repo, result.Chain, filters)

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
		return "Please enter just the domain name without a port number."
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
		return "TLS handshake failed. The server may not support TLS on port 443."
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
