package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/domain"
)

// IndexData is the view model for the index page.
type IndexData struct {
	Results *ResultsViewData
	Error   *ErrorData
}

// handleIndex serves the main page (GET only, read-only, never triggers crawl).
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "index.html", &IndexData{}); err != nil {
		s.logger.Error("failed to render index", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
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

	// Check for IP literals (SSRF prevention)
	if isIPLiteral(normalizedDomain) {
		s.renderError(w, r, "Invalid Domain", "IP addresses are not allowed. Please enter a domain name.", http.StatusBadRequest)
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
		s.renderCachedResults(w, r, domainResult, false)
		return
	}

	// Need to crawl
	result, crawlErr := s.performCrawl(r.Context(), normalizedDomain, false)
	if crawlErr != nil {
		s.logger.Warn("crawl failed", "domain", normalizedDomain, "error", crawlErr)

		// If we have cached data, show it with an error notice
		if domainResult != nil && domainResult.HasChain {
			s.renderCachedResultsWithError(w, r, domainResult, crawlErr)
			return
		}

		s.renderError(w, r, "Crawl Failed", formatCrawlError(crawlErr), http.StatusOK)
		return
	}

	// Render fresh results
	s.renderFreshResults(w, r, result)
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
			s.renderCachedResultsWithError(w, r, domainResult, crawlErr)
			return
		}

		s.renderError(w, r, "Crawl Failed", formatCrawlError(crawlErr), http.StatusOK)
		return
	}

	s.renderFreshResults(w, r, result)
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

// renderCachedResults renders cached results.
func (s *Server) renderCachedResults(w http.ResponseWriter, r *http.Request, result *DomainResult, lastCrawlFailed bool) {
	canForce, waitTime, _ := s.repo.CanForcedRefresh(r.Context(), result.Domain, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(result, true, canForce, waitTime, lastCrawlFailed)

	s.renderResults(w, r, data)
}

// renderCachedResultsWithError renders cached results with an error notice.
func (s *Server) renderCachedResultsWithError(w http.ResponseWriter, r *http.Request, result *DomainResult, crawlErr error) {
	s.renderCachedResults(w, r, result, true)
}

// renderFreshResults renders fresh crawl results.
func (s *Server) renderFreshResults(w http.ResponseWriter, r *http.Request, result *CrawlOutput) {
	// Convert crawl output to domain result format
	domainResult := &DomainResult{
		Domain:    result.Domain,
		HasChain:  len(result.Chain) > 0,
		Chain:     result.Chain,
		UpdatedAt: time.Now(),
	}

	canForce, waitTime, _ := s.repo.CanForcedRefresh(r.Context(), result.Domain, s.config.ForcedRefreshWindow)

	data := buildResultsViewData(domainResult, false, canForce, waitTime, false)

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
