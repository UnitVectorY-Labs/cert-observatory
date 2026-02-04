package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAddCert_MissingPEMFile(t *testing.T) {
	cfg := DefaultAddCertConfig()
	cfg.Stderr = &bytes.Buffer{}

	err := AddCert(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for empty PEM file path")
	}
}

func TestAddCert_NonexistentFile(t *testing.T) {
	cfg := DefaultAddCertConfig()
	cfg.PEMFile = "/nonexistent/path/to/file.pem"
	cfg.Stderr = &bytes.Buffer{}

	err := AddCert(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestAddCert_EmptyFile(t *testing.T) {
	// Create a temporary empty file
	tmpDir := t.TempDir()
	pemFile := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(pemFile, []byte(""), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	cfg := DefaultAddCertConfig()
	cfg.PEMFile = pemFile
	cfg.Stderr = &bytes.Buffer{}

	err := AddCert(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for empty PEM file")
	}
}

func TestAddCert_InvalidPEM(t *testing.T) {
	// Create a file with invalid content
	tmpDir := t.TempDir()
	pemFile := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(pemFile, []byte("not a valid PEM file"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	cfg := DefaultAddCertConfig()
	cfg.PEMFile = pemFile
	cfg.Stderr = &bytes.Buffer{}

	err := AddCert(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for invalid PEM content")
	}
}

func TestDefaultAddCertConfig(t *testing.T) {
	cfg := DefaultAddCertConfig()
	if cfg.Stderr == nil {
		t.Error("Stderr should not be nil")
	}
}
