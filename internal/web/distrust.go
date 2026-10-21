package web

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

// annotateDistrust uses one stored snapshot per rendered result. No network
// requests are made, and a platform warning never hides an observed path.
func (s *Server) annotateDistrust(ctx context.Context, data *ResultsViewData) {
	snapshot, err := s.repo.DistrustSnapshot(ctx)
	if err != nil {
		s.logger.Error("failed to load CA distrust data", "error", err)
		data.DistrustSources = []string{"CA distrust data unavailable; status is unknown."}
		return
	}
	now := time.Now()
	for _, name := range []string{distrust.OneCRL, distrust.CCADB} {
		label := map[string]string{distrust.OneCRL: "Mozilla OneCRL", distrust.CCADB: "CCADB root-store actions"}[name]
		message := label + ": not collected; status is unknown."
		for _, state := range snapshot.Sources {
			if state.Source != name {
				continue
			}
			if state.LastSuccessfulAt != nil {
				message = fmt.Sprintf("%s: last successful refresh %s (%d rules).", label, state.LastSuccessfulAt.UTC().Format(time.RFC3339), state.ActiveRules)
				if state.Stale(now) {
					message += " Data is stale or the latest refresh failed."
				}
			}
		}
		data.DistrustSources = append(data.DistrustSources, message)
	}
	annotate := func(view *CertViewData) {
		view.DistrustRules = nil
		block, _ := pem.Decode([]byte(view.PEM))
		if block == nil {
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}
		for _, rule := range snapshot.Rules {
			if rule.Matches(cert, now) {
				view.DistrustRules = append(view.DistrustRules, rule)
			}
		}
	}
	for _, cert := range data.Chain {
		annotate(cert)
	}
	if graph := data.ChainGraph; graph != nil {
		warnings := map[string]bool{}
		for _, cert := range graph.AllCerts {
			annotate(cert)
			warnings[cert.HashHex] = len(cert.DistrustRules) > 0
		}
		for _, node := range collectUniqueCertNodes(graph.Root) {
			node.HasDistrust = warnings[node.HashHex]
		}
		graph.MermaidDiagram, graph.MermaidNodeToCertIndex, graph.Legend = buildMermaidDiagram(graph.Root)
	}
}

// These helpers also handle references already stored before this UI update.
func distrustTitle(rule distrust.Rule) string {
	if rule.Source == distrust.OneCRL {
		return "Distrusted by Mozilla"
	}
	return rule.Label()
}

func oneCRLRecordURL(rule distrust.Rule) string {
	return distrust.OneCRLURL + "/" + url.PathEscape(rule.SourceRecordID)
}

func distrustReferenceURL(rule distrust.Rule) string {
	reference := strings.TrimSpace(rule.ReferenceURL)
	if reference == "" {
		return ""
	}
	if rule.Source == distrust.OneCRL && strings.Trim(reference, "0123456789") == "" {
		return "https://bugzilla.mozilla.org/show_bug.cgi?id=" + reference
	}
	parsed, err := url.Parse(reference)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
		return ""
	}
	return reference
}
