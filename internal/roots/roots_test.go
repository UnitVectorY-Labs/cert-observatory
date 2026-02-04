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
}
