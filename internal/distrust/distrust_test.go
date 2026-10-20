package distrust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertificate() *x509.Certificate {
	return &x509.Certificate{IsCA: true, Raw: []byte("certificate"), RawIssuer: []byte{0x30, 0}, RawSubject: []byte{0x30, 0}, RawSubjectPublicKeyInfo: []byte("DER SPKI"), SerialNumber: big.NewInt(128)}
}
func TestRuleMatching(t *testing.T) {
	c := testCertificate()
	fp := sha256.Sum256(c.Raw)
	key := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	rules := []Rule{
		{MatchType: "certificate_sha256", CertificateSHA256: fp[:]},
		{MatchType: "issuer_serial", IssuerNameDER: c.RawIssuer, SerialNumber: c.SerialNumber.Bytes()},
		{MatchType: "subject_public_key_hash", SubjectNameDER: c.RawSubject, PublicKeyHash: key[:]},
	}
	now := time.Now()
	for _, r := range rules {
		t.Run(r.MatchType, func(t *testing.T) {
			if !r.Matches(c, now) {
				t.Fatal("expected CA match")
			}
			leaf := *c
			leaf.IsCA = false
			if r.Matches(&leaf, now) {
				t.Fatal("leaf must not match")
			}
			other := *c
			other.Raw = []byte("another cert")
			other.RawIssuer = []byte("different issuer")
			other.RawSubject = []byte("different subject")
			if r.Matches(&other, now) {
				t.Fatal("unrelated certificate matched")
			}
			r.WithdrawnAt = &now
			if r.Matches(c, now) {
				t.Fatal("withdrawn rule matched")
			}
			r.WithdrawnAt = nil
			future := now.Add(time.Hour)
			r.EffectiveAt = &future
			if r.Matches(c, now) {
				t.Fatal("future rule matched")
			}
		})
	}
	// Reissued/cross-signed certificates with the same subject and SPKI share a
	// subject/key block, but an issuer/serial rule must not spread to another issuer.
	reissued := *c
	reissued.Raw = []byte("reissued")
	reissued.RawIssuer = []byte("another issuer")
	reissued.SerialNumber = big.NewInt(300)
	if !rules[2].Matches(&reissued, now) || rules[0].Matches(&reissued, now) || rules[1].Matches(&reissued, now) {
		t.Fatal("incorrect cross-sign matching")
	}
	reissued.RawSubjectPublicKeyInfo = []byte("different key")
	if rules[2].Matches(&reissued, now) {
		t.Fatal("different key matched")
	}
}

func oneCRLFixture(t *testing.T, enabled bool) []byte {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString
	b, err := json.Marshal(map[string]any{"data": []any{map[string]any{"id": "issuer-rule", "enabled": enabled, "issuerName": b64([]byte{0x30, 0}), "serialNumber": b64([]byte{0, 128}), "details": map[string]any{"bug": "https://example.test/incident"}}, map[string]any{"id": "key-rule", "enabled": enabled, "subject": b64([]byte{0x30, 0}), "pubKeyHash": b64(make([]byte, 32))}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestParseOneCRL(t *testing.T) {
	rules, err := ParseOneCRL(oneCRLFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || len(rules[0].SerialNumber) != 1 || rules[0].SerialNumber[0] != 128 || rules[1].MatchType != "subject_public_key_hash" {
		t.Fatalf("incorrect rules: %+v", rules)
	}
	if !rules[0].Matches(testCertificate(), time.Now()) {
		t.Fatal("normalized serial did not match")
	}
	rules, err = ParseOneCRL(oneCRLFixture(t, false))
	if err != nil || len(rules) != 0 {
		t.Fatalf("disabled rules: %v %v", rules, err)
	}
	for _, bad := range []string{`{}`, `{"data":[]}`, `{"data":[{"id":"x","enabled":true,"issuerName":"!","serialNumber":"AA=="}]}`, `{"data":[{"id":"x","issuerName":"MAA=","serialNumber":"AQ=="}]}`, string(oneCRLFixture(t, true)) + "garbage"} {
		if _, err = ParseOneCRL([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed snapshot %s", bad)
		}
	}
}

const csvHeader = "Salesforce Record ID,Certificate Record Type,SHA-256 Fingerprint,Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n"

func TestParseCCADB(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	input := csvHeader + "root,Root Certificate," + fp + ",Blocked,Not Included,Disabled,Removed\n" + "intermediate,Intermediate Certificate," + fp + ",Blocked,Not Trusted,Trusted,Not Trusted\n"
	rules, err := ParseCCADB([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Platform != "apple" || rules[1].Status != "disabled" || rules[2].Status != "removed" {
		t.Fatalf("unexpected actions %+v", rules)
	}
	if rules[0].Label() != "Blocked by Apple" || rules[2].Label() != "Removed from Mozilla root store" {
		t.Fatal("incorrect labels")
	}
	noActions := csvHeader + "root,Root Certificate," + fp + ",Not Trusted,Not Included,NotBefore,Included\n"
	if r, e := ParseCCADB([]byte(noActions)); e != nil || len(r) != 0 {
		t.Fatalf("non-block action imported: %v %v", r, e)
	}
	for _, bad := range []string{csvHeader, "<html>error</html>", strings.Replace(input, fp, "invalid", 1), input + "incomplete,row\n", input + "root,Root Certificate," + fp + ",Blocked,Blocked,Blocked,Blocked\n", strings.Replace(input, "Disabled", "NewUnrecognizedStatus", 1)} {
		if _, e := ParseCCADB([]byte(bad)); e == nil {
			t.Fatalf("accepted invalid CSV: %s", bad)
		}
	}
}

func TestSourceFreshness(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Hour)
	old := now.Add(-3 * time.Hour)
	for _, tc := range []struct {
		s    SourceState
		want bool
	}{
		{SourceState{Source: OneCRL}, true},
		{SourceState{Source: OneCRL, LastSuccessfulAt: &recent}, false},
		{SourceState{Source: OneCRL, LastSuccessfulAt: &old}, true},
		{SourceState{Source: CCADB, LastSuccessfulAt: &old}, false},
		{SourceState{Source: CCADB, LastSuccessfulAt: &recent, LastError: "failed"}, true},
	} {
		if got := tc.s.Stale(now); got != tc.want {
			t.Errorf("Stale(%+v)=%v", tc.s, got)
		}
	}
}
