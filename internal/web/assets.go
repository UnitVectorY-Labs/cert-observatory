package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
)

const assetVersionLength = 12

var versionedAssetPaths = []string{
	"/static/css/style.css",
	"/static/js/htmx.min.js",
	"/static/js/script.js",
	"/static/js/mermaid-11.12.2.min.js",
	"/static/vendor/uvy-design/uvy-tokens.css",
	"/static/vendor/uvy-design/uvy-elements.css",
	"/static/vendor/uvy-design/uvy-theme.js",
}

func buildAssetVersions(staticFiles fs.FS, assetPaths []string) (map[string]string, error) {
	versions := make(map[string]string, len(assetPaths))

	for _, path := range assetPaths {
		assetBytes, err := fs.ReadFile(staticFiles, strings.TrimPrefix(path, "/"))
		if err != nil {
			return nil, fmt.Errorf("read asset %q: %w", path, err)
		}

		sum := sha256.Sum256(assetBytes)
		fullHash := hex.EncodeToString(sum[:])
		versions[path] = fullHash[:assetVersionLength]
	}

	return versions, nil
}

func assetURL(path string, versions map[string]string) string {
	version, ok := versions[path]
	if !ok {
		return path
	}

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	return path + separator + "v=" + version
}
