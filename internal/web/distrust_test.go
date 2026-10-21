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
	for _, want := range []string{"Distrusted by Mozilla", "Distrusted Certificate", "distrust-callout", "View OneCRL record", "Last confirmed in source:", "Data is stale", "not collected", "Leaf certificates are not checked.", "&lt;script&gt;unsafe&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "<script>unsafe") || strings.Contains(body, `href="javascript:`) {
		t.Fatal("unescaped upstream data")
	}
	if !data.ChainGraph.Legend.HasDistrust || !strings.Contains(data.ChainGraph.MermaidDiagram, "⚠ Distrusted") {
		t.Fatal("graph lacks distrust marker")
	}
	// Render a stored numeric bug reference as a usable external link.
	repo.distrustSnapshot.Rules[0].ReferenceURL = "2083382"
	out = httptest.NewRecorder()
	server.renderResults(out, req, data)
	for _, want := range []string{`href="https://bugzilla.mozilla.org/show_bug.cgi?id=2083382"`, `href="` + distrust.OneCRLURL + `/blocked"`, "Related Mozilla issue", "May require access"} {
		if !strings.Contains(out.Body.String(), want) {
			t.Errorf("missing rendered reference %q", want)
		}
	}
	// Expiration and distrust remain independent graph indicators.
	data.ChainGraph.Root.IsExpired = true
	server.annotateDistrust(context.Background(), data)
	diagram := data.ChainGraph.MermaidDiagram
	if !strings.Contains(diagram, "⛔ ⚠ Distrusted") || !data.ChainGraph.Legend.HasExpired || !data.ChainGraph.Legend.HasDistrust {
		t.Fatal("expiration and distrust indicators must coexist")
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

func TestDistrustReferenceLinks(t *testing.T) {
	for _, tc := range []struct{ name, source, reference, want string }{
		{"numeric bug", distrust.OneCRL, " 2083382 ", "https://bugzilla.mozilla.org/show_bug.cgi?id=2083382"},
		{"issue URL", distrust.OneCRL, "https://bugzilla.mozilla.org/show_bug.cgi?id=2083382", "https://bugzilla.mozilla.org/show_bug.cgi?id=2083382"},
		{"empty", distrust.OneCRL, "", ""},
		{"unsafe", distrust.OneCRL, "javascript:alert(1)", ""},
		{"relative", distrust.OneCRL, "/2083382", ""},
		{"invalid URL", distrust.OneCRL, "https://%", ""},
		{"credentials", distrust.OneCRL, "https://user:password@example.com", ""},
		{"ccadb numeric", distrust.CCADB, "123", ""},
		{"ccadb source", distrust.CCADB, "https://www.ccadb.org/resources", "https://www.ccadb.org/resources"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := distrustReferenceURL(distrust.Rule{Source: tc.source, ReferenceURL: tc.reference})
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := oneCRLRecordURL(distrust.Rule{SourceRecordID: "example/id"}); got != distrust.OneCRLURL+"/example%2Fid" {
		t.Fatal(got)
	}
}
