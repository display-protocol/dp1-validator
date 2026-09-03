package feed

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/display-protocol/dp1-cli/internal/config"
)

func TestResolveBaseURL_order(t *testing.T) {
	t.Setenv(EnvURL, "")

	_, err := ResolveBaseURL("", config.FeedCfg{})
	if err == nil {
		t.Fatal("expected error when URL missing")
	}

	base, err := ResolveBaseURL("", config.FeedCfg{URL: "https://example.com/v "})
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://example.com/v" {
		t.Fatalf("base URL: %q", base)
	}

	base, err = ResolveBaseURL("https://flag.example", config.FeedCfg{URL: "https://cfg.example"})
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://flag.example" {
		t.Fatalf("flag URL should win: %q", base)
	}

	t.Setenv(EnvURL, "https://env.example")
	base, err = ResolveBaseURL("", config.FeedCfg{URL: "https://cfg.example"})
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://env.example" {
		t.Fatalf("env URL should beat config: %q", base)
	}
}

func TestClient_Create_success(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/playlists" {
			t.Fatalf("path %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		auth = r.Header.Get("Authorization")
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != `{"ok":true}` {
			t.Fatalf("body %s", b)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"u1"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient()
	st, body, err := c.Create(context.Background(), srv.URL, Playlist, []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if st != http.StatusCreated {
		t.Fatalf("status %d", st)
	}
	if auth != "" {
		t.Fatalf("unexpected Authorization header: %q", auth)
	}
	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil || doc["id"] != "u1" {
		t.Fatalf("body: %s", body)
	}
}

func TestClient_Create_errorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"validation_error","message":"nope"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewClient()
	st, body, err := c.Create(context.Background(), srv.URL, PlaylistGroup, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if st != http.StatusBadRequest {
		t.Fatalf("status %d", st)
	}
	e := ErrorFromResponse(st, body)
	var ae *APIError
	if !errors.As(e, &ae) {
		t.Fatalf("want *APIError, got %T", e)
	}
	if ae.Code != "validation_error" || ae.Message != "nope" {
		t.Fatalf("%#v", ae)
	}
}
