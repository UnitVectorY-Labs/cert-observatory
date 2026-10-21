package main

import (
	"strings"
	"testing"
)

func TestDistrustFlagEnvironmentPrecedence(t *testing.T) {
	t.Setenv("CERT_OBS_DISTRUST_SOURCE", "invalid-env")
	t.Setenv("CERT_OBS_DISTRUST_TIMEOUT", "invalid-duration")
	c := rootCmd()
	c.SetArgs([]string{"ingest-distrust", "--source=invalid-flag", "--timeout=1s"})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "source must be") {
		t.Fatalf("flags did not override environment: %v", err)
	}
	c = rootCmd()
	c.SetArgs([]string{"ingest-distrust", "--source=all"})
	if err := c.Execute(); err == nil || !strings.Contains(err.Error(), "CERT_OBS_DISTRUST_TIMEOUT") {
		t.Fatalf("invalid environment duration not reported: %v", err)
	}
}
