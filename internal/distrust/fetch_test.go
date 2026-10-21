package distrust

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type mockHTTP func(*http.Request) (*http.Response, error)

func (f mockHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestFetchRejectsIncompleteResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body, next string
		code             int
	}{
		{"HTTP failure", "", "", 503},
		{"paginated", string(oneCRLFixture(t, true)), "https://example.test/page2", 200},
		{"truncated", `{"data":[`, "", 200},
		{"too large", strings.Repeat(" ", maxFeedBytes+1), "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := mockHTTP(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != OneCRLURL {
					t.Fatal("unexpected URL")
				}
				return &http.Response{StatusCode: tc.code, Header: http.Header{"Next-Page": []string{tc.next}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if _, err := Fetch(context.Background(), client, OneCRL); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
	client := mockHTTP(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	if _, err := Fetch(context.Background(), client, OneCRL); err == nil {
		t.Fatal("expected transport error")
	}
}
