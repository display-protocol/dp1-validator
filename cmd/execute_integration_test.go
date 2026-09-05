package cmd_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	dp1 "github.com/display-protocol/dp1-go"

	"github.com/display-protocol/dp1-cli/cmd"
)

func TestExecute_initWritesDefaultConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	defer resetCLIState(t)
	root := cmd.Root
	root.SetArgs([]string{"init"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".dp1", "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatal(err)
	}
}

func TestExecute_configPath_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	defer resetCLIState(t)
	root := cmd.Root
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--json", "config", "path"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("stdout %q: %v", buf.String(), err)
	}
	if got.Path == "" {
		t.Fatal("empty path")
	}
}

func TestExecute_configShow_JSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	defer resetCLIState(t)
	root := cmd.Root
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--json", "config", "show"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var got struct {
		OK   bool `json:"ok"`
		Feed struct {
			URL string `json:"url"`
		} `json:"feed"`
		Defaults struct {
			OutputFormat string `json:"output_format"`
		} `json:"defaults"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("stdout %q: %v", buf.String(), err)
	}
	if !got.OK {
		t.Fatalf("ok: %v", got.OK)
	}
	if got.Feed.URL != "https://feed.feralfile.com" {
		t.Fatalf("feed.url: %q", got.Feed.URL)
	}
	if got.Defaults.OutputFormat != "human" {
		t.Fatalf("defaults.output_format: %q", got.Defaults.OutputFormat)
	}
}

func TestExecute_versionJSONShape(t *testing.T) {
	defer resetCLIState(t)
	root := cmd.Root
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--json", "version"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("%s: %v", buf.String(), err)
	}
	for _, k := range []string{"dp1_cli", "dp1_go", "go"} {
		if env[k] == "" {
			t.Fatalf("missing key %q in %#v", k, env)
		}
	}
}

func TestExecute_playlistValidate_unsignedAllowedWithFlag(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"dpVersion":"1.1.0","title":"x","items":[{"source":"https://example.invalid/i.json"}]}`)
	path := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--json", "playlist", "validate", path, "--allow-unsigned"})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	stdout := captureStdout(t, func() {
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	var env struct {
		OK            bool   `json:"ok"`
		UnsignedDraft bool   `json:"unsignedDraft"`
		Message       string `json:"message"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	if !env.OK || !env.UnsignedDraft || env.Message == "" {
		t.Fatalf("got %#v, want ok with unsignedDraft", env)
	}
}

func TestExecute_playlistValidate_unsignedFailsSchema(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"dpVersion":"1.1.0","title":"x","items":[{"source":"https://example.invalid/i.json"}]}`)
	path := filepath.Join(dir, "unsigned.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"playlist", "validate", path})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestExecute_playlistSignProducesValidSignedDoc(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"dpVersion":"1.1.0","title":"sign-e2e","items":[{"source":"https://example.invalid/i.json"}]}`)
	inPath := filepath.Join(dir, "in.json")
	outPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(inPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(priv)

	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"playlist", "sign", inPath, "--private-key", keyHex, "-o", outPath})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	signed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dp1.ParseAndValidatePlaylist(signed); err != nil {
		t.Fatalf("signed doc invalid: %v", err)
	}

	root.SetArgs([]string{"playlist", "verify", outPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify signed: %v", err)
	}
}

func TestExecute_channelSign_defaultPublisherRoleProducesValidDoc(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{
  "id": "11111111-1111-4111-8111-111111111111",
  "slug": "fixture-channel",
  "title": "Fixture",
  "version": "0.1.0",
  "created": "2026-05-01T12:00:00Z",
  "playlists": ["https://example.invalid/playlist.json"]
}`)
	inPath := filepath.Join(dir, "in.json")
	outPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(inPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(priv)

	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	// No --role: default publisher must pass channels schema (dp1-go v0.4.0+).
	root.SetArgs([]string{"channel", "sign", inPath, "--private-key", keyHex, "-o", outPath})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	signed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dp1.ParseAndValidateChannel(signed); err != nil {
		t.Fatalf("signed channel invalid (default publisher role): %v", err)
	}

	var env struct {
		Sigs []struct {
			Role string `json:"role"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Sigs) != 1 || env.Sigs[0].Role != "publisher" {
		t.Fatalf("signatures: got %#v, want one entry with role publisher", env.Sigs)
	}
}

func TestExecute_playlistSign_missingFileErrors(t *testing.T) {
	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"playlist", "sign", filepath.Join(t.TempDir(), "nope.json")})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error")
	}
}

func TestExecute_playlistSign_missingPrivateKeyErrors(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"dpVersion":"1.1.0","title":"x","items":[{"source":"https://example.invalid/i.json"}]}`)
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())
	t.Setenv("DP1_PRIVATE_KEY", "")
	defer resetCLIState(t)

	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"playlist", "sign", path})
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})
	if err := root.Execute(); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestExecute_playlistPublish_postsToFeed(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type: %q", r.Header.Get("Content-Type"))
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dp1.ParseAndValidatePlaylist(b); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"feed-ok"}`))
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	raw := []byte(`{"dpVersion":"1.1.0","title":"pub-e2e","items":[{"source":"https://example.invalid/i.json"}]}`)
	inPath := filepath.Join(dir, "in.json")
	outPath := filepath.Join(dir, "out.json")
	if err := os.WriteFile(inPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(priv)

	t.Setenv("HOME", t.TempDir())
	defer resetCLIState(t)
	root := cmd.Root
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	t.Cleanup(func() {
		root.SetArgs(nil)
		resetCLIState(t)
	})

	root.SetArgs([]string{"playlist", "sign", inPath, "--private-key", keyHex, "-o", outPath})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	root.SetOut(io.Discard)
	root.SetArgs([]string{"--json", "playlist", "publish", outPath, "--feed-url", srv.URL})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/playlists" {
		t.Fatalf("request path: %s", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("unexpected Authorization: %q", gotAuth)
	}
}
