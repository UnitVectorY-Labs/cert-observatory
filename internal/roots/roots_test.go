package roots

import (
	"testing"
)

func TestGetSources(t *testing.T) {
	sources, err := GetSources()
	if err != nil {
		t.Fatalf("GetSources() error = %v", err)
	}

	if len(sources) == 0 {
		t.Error("GetSources() returned empty sources")
	}

	// Verify each source has name and URL
	for i, source := range sources {
		if source.Name == "" {
			t.Errorf("source[%d].Name is empty", i)
		}
		if source.URL == "" {
			t.Errorf("source[%d].URL is empty", i)
		}
	}

	// Verify expected sources are present
	expectedNames := map[string]bool{
		"apple":     false,
		"google":    false,
		"microsoft": false,
		"mozilla":   false,
	}

	for _, source := range sources {
		if _, ok := expectedNames[source.Name]; ok {
			expectedNames[source.Name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("expected source %q not found", name)
		}
	}
}
