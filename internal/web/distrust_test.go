package web

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/UnitVectorY-Labs/cert-observatory/internal/distrust"
)

func TestDistrustRendering(t *testing.T) {
	// Use a locally generated CA, never a network certificate.
	generated, _ := generateTestCA(t)
	der := generated.Raw
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(der)
	cert := &CertificateResult{CertHash: hash[:], DER: der, Parsed: parsed, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Subject: parsed.Subject.String(), Issuer: parsed.Issuer.String(), NotBefore: parsed.NotBefore, NotAfter: parsed.NotAfter}
	now := time.Now().UTC()
	old := now.Add(-4 * time.Hour)
	rule := distrust.Rule{Source: distrust.OneCRL, SourceRecordID: "blocked", Platform: "mozilla", Status: "blocked", MatchType: "certificate_sha256", CertificateSHA256: hash[:], Reason: "<script>unsafe</script>", ReferenceURL: "javascript:alert(1)", FirstSeenAt: now, LastSeenAt: now}
	repo := &mockRepository{distrustSnapshot: &distrust.Snapshot{Rules: []distrust.Rule{rule}, Sources: []distrust.SourceState{{Source: distrust.OneCRL, LastSuccessfulAt: &old, ActiveRules: 1}}}}
	cfg := DefaultConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := New(cfg, repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := &ResultsViewData{Chain: []*CertViewData{certToViewData(cert)}, ChainGraph: buildChainGraph(context.Background(), repo, []*CertificateResult{cert}, ChainGraphFilters{})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("HX-Request", "true")
	out := httptest.NewRecorder()
	server.renderResults(out, req, data)
	body := out.Body.String()
	for _, want := range []string{"Blocked by Mozilla", "CA platform distrust action", "Data is stale", "not collected", "Leaf certificates are not checked.", "&lt;script&gt;unsafe&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "<script>unsafe") || strings.Contains(body, `href="javascript:`) {
		t.Fatal("unescaped upstream data")
	}
	if !data.ChainGraph.Legend.HasDistrust || !strings.Contains(data.ChainGraph.MermaidDiagram, "⚠") {
		t.Fatal("graph lacks distrust marker")
	}
	// A newly withdrawn rule clears the marker without changing/re-crawling the chain.
	repo.distrustSnapshot.Rules[0].WithdrawnAt = &now
	server.annotateDistrust(context.Background(), data)
	if len(data.Chain[0].DistrustRules) != 0 || data.ChainGraph.Legend.HasDistrust {
		t.Fatal("withdrawn warning remains")
	}
	repo.distrustError = errors.New("database unavailable")
	data = &ResultsViewData{}
	server.annotateDistrust(context.Background(), data)
	if len(data.DistrustSources) != 1 || !strings.Contains(data.DistrustSources[0], "unavailable") {
		t.Fatal("missing unknown state")
	}
}
