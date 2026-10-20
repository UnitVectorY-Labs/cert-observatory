package distrust

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

const maxFeedBytes = 32 << 20

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Fetch reads a complete bounded snapshot. Pagination is rejected rather than
// accidentally withdrawing records missing from a partial response.
func Fetch(ctx context.Context, client HTTPClient, source string) ([]Rule, error) {
	var url string
	switch source {
	case OneCRL:
		url = OneCRLURL
	case CCADB:
		url = CCADBURL
	default:
		return nil, fmt.Errorf("unknown source %q", source)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if resp.Header.Get("Next-Page") != "" {
		return nil, fmt.Errorf("paginated feed is unsupported")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFeedBytes {
		return nil, fmt.Errorf("feed exceeds %d bytes", maxFeedBytes)
	}
	if source == OneCRL {
		return ParseOneCRL(b)
	}
	return ParseCCADB(b)
}

func ParseOneCRL(b []byte) ([]Rule, error) {
	var feed struct {
		Data []struct {
			ID      string                    `json:"id"`
			Enabled *bool                     `json:"enabled"`
			Issuer  string                    `json:"issuerName"`
			Serial  string                    `json:"serialNumber"`
			Subject string                    `json:"subject"`
			Key     string                    `json:"pubKeyHash"`
			Details struct{ Bug, Why string } `json:"details"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &feed); err != nil {
		return nil, err
	}
	if len(feed.Data) == 0 {
		return nil, fmt.Errorf("empty or missing OneCRL data")
	}
	var rules []Rule
	seen := map[string]bool{}
	for _, v := range feed.Data {
		if v.ID == "" || seen[v.ID] || v.Enabled == nil {
			return nil, fmt.Errorf("missing or duplicate OneCRL ID or enabled field")
		}
		seen[v.ID] = true
		r := Rule{Source: OneCRL, SourceRecordID: v.ID, Platform: "mozilla", Status: "blocked", Reason: v.Details.Why, ReferenceURL: v.Details.Bug}
		decode := func(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }
		var err error
		switch {
		case v.Issuer != "" && v.Serial != "" && v.Subject == "" && v.Key == "":
			r.MatchType = "issuer_serial"
			r.IssuerNameDER, err = decode(v.Issuer)
			if err != nil {
				return nil, err
			}
			serial, e := decode(v.Serial)
			if e != nil {
				return nil, e
			}
			r.SerialNumber = new(big.Int).SetBytes(serial).Bytes()
		case v.Subject != "" && v.Key != "" && v.Issuer == "" && v.Serial == "":
			r.MatchType = "subject_public_key_hash"
			r.SubjectNameDER, err = decode(v.Subject)
			if err != nil {
				return nil, err
			}
			r.PublicKeyHash, err = decode(v.Key)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported OneCRL rule %s", v.ID)
		}
		name := r.IssuerNameDER
		if r.MatchType == "subject_public_key_hash" {
			name = r.SubjectNameDER
		}
		var dn asn1.RawValue
		if rest, e := asn1.Unmarshal(name, &dn); e != nil || len(rest) != 0 || dn.Tag != asn1.TagSequence || dn.Class != asn1.ClassUniversal {
			return nil, fmt.Errorf("invalid OneCRL distinguished name")
		}
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if *v.Enabled {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func ParseCCADB(b []byte) ([]Rule, error) {
	reader := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, []byte{0xef, 0xbb, 0xbf})))
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	fields := map[string]int{}
	for i, h := range header {
		if _, ok := fields[h]; ok {
			return nil, fmt.Errorf("duplicate CCADB header %s", h)
		}
		fields[h] = i
	}
	required := []string{"Salesforce Record ID", "Certificate Record Type", "SHA-256 Fingerprint", "Apple Status", "Chrome Status", "Microsoft Status", "Mozilla Status"}
	for _, k := range required {
		if _, ok := fields[k]; !ok {
			return nil, fmt.Errorf("missing CCADB column %s", k)
		}
	}
	var rules []Rule
	seen := map[string]bool{}
	records := 0
	for {
		row, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		records++
		get := func(k string) string { return strings.TrimSpace(row[fields[k]]) }
		id := get("Salesforce Record ID")
		if id == "" || seen[id] {
			return nil, fmt.Errorf("missing or duplicate CCADB ID")
		}
		seen[id] = true
		fingerprint, e := hex.DecodeString(strings.ReplaceAll(get("SHA-256 Fingerprint"), ":", ""))
		if e != nil || len(fingerprint) != 32 {
			return nil, fmt.Errorf("invalid CCADB fingerprint for %s", id)
		}
		kind := get("Certificate Record Type")
		if kind != "Root Certificate" && kind != "Intermediate Certificate" {
			return nil, fmt.Errorf("unknown CCADB record type %q", kind)
		}
		// Intermediate statuses may be derived from their parent's trust. Only root
		// store actions are imported here; intermediate blocks come from OneCRL.
		if kind != "Root Certificate" {
			continue
		}
		for _, p := range []struct{ column, platform string }{{"Apple Status", "apple"}, {"Chrome Status", "chrome"}, {"Microsoft Status", "microsoft"}, {"Mozilla Status", "mozilla"}} {
			status := strings.ToLower(get(p.column))
			switch status {
			case "", "blocked", "disabled", "removed", "not included", "included", "not trusted", "trusted", "notbefore", "pending", "not yet included", "obsolete":
			default:
				return nil, fmt.Errorf("unknown CCADB %s value %q", p.column, get(p.column))
			}
			switch status {
			case "blocked", "disabled", "removed":
			default:
				continue
			}
			r := Rule{Source: CCADB, SourceRecordID: id, Platform: p.platform, Status: status, MatchType: "certificate_sha256", CertificateSHA256: fingerprint, ReferenceURL: "https://www.ccadb.org/resources"}
			if e := r.Validate(); e != nil {
				return nil, e
			}
			rules = append(rules, r)
		}
	}
	if records == 0 {
		return nil, fmt.Errorf("empty CCADB catalog")
	}
	return rules, nil
}
