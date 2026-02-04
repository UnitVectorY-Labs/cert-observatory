// Package roots provides embedded root certificate sources configuration.
package roots

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed roots.yaml
var rootsYAML []byte

// Source represents a root certificate source.
type Source struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

// Config represents the root sources configuration.
type Config struct {
	Sources []Source `yaml:"sources"`
}

// GetSources returns the configured root certificate sources from the embedded YAML file.
func GetSources() ([]Source, error) {
	var config Config
	if err := yaml.Unmarshal(rootsYAML, &config); err != nil {
		return nil, err
	}
	return config.Sources, nil
}
