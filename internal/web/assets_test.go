package web

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestBuildAssetVersions(t *testing.T) {
	staticFiles := fstest.MapFS{
		"static/css/style.css": {Data: []byte("body { color: red; }")},
		"static/js/script.js":  {Data: []byte("console.log('hello')")},
	}

	versions, err := buildAssetVersions(staticFiles, versionedAssetPaths)
	if err != nil {
		t.Fatalf("buildAssetVersions failed: %v", err)
	}

	if len(versions) != len(versionedAssetPaths) {
		t.Fatalf("expected %d versions, got %d", len(versionedAssetPaths), len(versions))
	}

	for _, path := range versionedAssetPaths {
		version := versions[path]
		if len(version) != assetVersionLength {
			t.Fatalf("version for %s has length %d, expected %d", path, len(version), assetVersionLength)
		}
		if strings.ContainsAny(version, "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("version for %s is not lowercase hex: %s", path, version)
		}
	}
}

func TestAssetURL(t *testing.T) {
	versions := map[string]string{
		"/static/css/style.css": "abc123def456",
	}

	got := assetURL("/static/css/style.css", versions)
	if got != "/static/css/style.css?v=abc123def456" {
		t.Fatalf("unexpected URL with version: %s", got)
	}

	got = assetURL("/static/js/htmx.min.js", versions)
	if got != "/static/js/htmx.min.js" {
		t.Fatalf("unexpected URL without version: %s", got)
	}
}
