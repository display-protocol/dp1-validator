package config

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestPathAndDir_underHome(t *testing.T) {
	setupTestHome(t)

	dir, err := Dir(false)
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(os.Getenv("HOME"), ".dp1")
	if dir != wantDir {
		t.Fatalf("Dir: got %q want %q", dir, wantDir)
	}

	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(wantDir, "config.yaml"); p != want {
		t.Fatalf("Path: got %q want %q", p, want)
	}
}

func TestLoad_missingFile_defaults(t *testing.T) {
	setupTestHome(t)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Feed.URL != "https://feed.feralfile.com" {
		t.Fatalf("Feed.URL: %q", cfg.Feed.URL)
	}
	if cfg.Defaults.OutputFormat != "human" {
		t.Fatalf("Defaults.OutputFormat: %q", cfg.Defaults.OutputFormat)
	}
}

func TestLoad_mergesEmptyOptionalFields(t *testing.T) {
	setupTestHome(t)

	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "signing:\n  private_key: \"abc123\"\nfeed:\n  url: \"\"\ndefaults:\n  output_format: \"\"\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Signing.PrivateKey != "abc123" {
		t.Fatalf("private key not kept: %q", cfg.Signing.PrivateKey)
	}
	if cfg.Feed.URL != "https://feed.feralfile.com" {
		t.Fatalf("Feed.URL not merged: %q", cfg.Feed.URL)
	}
	if cfg.Defaults.OutputFormat != "human" {
		t.Fatalf("OutputFormat not merged: %q", cfg.Defaults.OutputFormat)
	}
}

func TestSave_roundTrip(t *testing.T) {
	setupTestHome(t)

	cfg := Config{
		Signing: SigningCfg{PrivateKey: "deadbeef", PublicKey: "00"},
		Feed:    FeedCfg{URL: "https://example.com/feed"},
		Defaults: DefaultsCfg{
			OutputFormat: "json",
		},
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Signing.PrivateKey != cfg.Signing.PrivateKey ||
		got.Feed.URL != cfg.Feed.URL ||
		got.Defaults.OutputFormat != cfg.Defaults.OutputFormat {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, cfg)
	}
}

func TestLoadCached_invalidatesAfterSave(t *testing.T) {
	setupTestHome(t)

	InvalidateCache()
	first, err := LoadCached()
	if err != nil {
		t.Fatal(err)
	}
	if first.Feed.URL == "" {
		t.Fatal("expected default feed url")
	}

	second, err := LoadCached()
	if err != nil {
		t.Fatal(err)
	}
	if second.Feed.URL != first.Feed.URL {
		t.Fatal("cache should return same snapshot")
	}

	first.Feed.URL = "https://changed.example"
	if err := Save(first); err != nil {
		t.Fatal(err)
	}

	third, err := LoadCached()
	if err != nil {
		t.Fatal(err)
	}
	if third.Feed.URL != "https://changed.example" {
		t.Fatalf("after Save, cache should reload: got %q", third.Feed.URL)
	}
}
