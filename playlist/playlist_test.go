package playlist

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Test constants for valid UUIDs
const (
	testPlaylistID = "385f79b6-a45f-4c1c-8080-e93a192adccc"
	testItemID1    = "285f79b6-a45f-4c1c-8080-e93a192adccc"
	testItemID2    = "185f79b6-a45f-4c1c-8080-e93a192adccc"
)

func stringPtr(s string) *string {
	return &s
}

// Test data for playlist validation
var validPlaylistJSON = `{
  "dpVersion": "1.0.0",
  "id": "` + testPlaylistID + `",
  "slug": "test-playlist",
  "title": "Test Playlist",
  "created": "2025-06-03T17:01:00Z",
  "defaults": {
    "display": {
      "scaling": "fit",
      "background": "#000000"
    },
    "license": "open",
    "duration": 300
  },
  "items": [
    {
      "id": "` + testItemID1 + `",
      "source": "https://example.com/artwork1.html",
      "repro": {
        		"assetsSHA256": [
          "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
          "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
        ]
      }
    },
    {
      "id": "` + testItemID2 + `",
      "source": "https://example.com/artwork2.html"
    }
  ],
  "signature": "ed25519:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}`

func TestParsePlaylist(t *testing.T) {
	// Test data with valid JSON
	validPlaylist := `{
  "dpVersion": "1.0.0",
  "id": "` + testPlaylistID + `",
  "slug": "summer-mix-01", 
  "title": "Summer Mix 01",
  "created": "2025-06-03T17:01:00Z",
  "items": [
    {
      "id": "` + testItemID1 + `",
      "slug": "payphone-v2",
      "title": "Payphone",
      "source": "https://cdn.feralfile.com/payphone/index.html",
      "duration": 300,
      "license": "open"
    },
    {
      "id": "` + testItemID2 + `",
      "title": "Another Artwork",
      "source": "https://example.com/art.html",
      "duration": 180
    }
  ],
  "signature": "ed25519:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}`

	tests := []struct {
		name        string
		input       string
		expectError bool
		checkID     string
	}{
		{
			name:        "Valid JSON playlist",
			input:       validPlaylist,
			expectError: false,
			checkID:     testPlaylistID,
		},
		{
			name:        "Valid base64 encoded JSON",
			input:       base64.StdEncoding.EncodeToString([]byte(validPlaylist)),
			expectError: false,
			checkID:     testPlaylistID,
		},
		{
			name:        "Invalid JSON",
			input:       `{"invalid": json}`,
			expectError: true,
		},
		{
			name:        "Invalid base64",
			input:       "invalid-base64-data!@#",
			expectError: true,
		},
		{
			name:        "Empty input",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			playlist, _, err := ParsePlaylist(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if playlist == nil {
				t.Errorf("Expected non-nil playlist")
				return
			}

			if tt.checkID != "" && playlist.ID != tt.checkID {
				t.Errorf("Expected ID %s, got %s", tt.checkID, playlist.ID)
			}
		})
	}
}

func TestParsePlaylistWithURL(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(validPlaylistJSON))
		if err != nil {
			t.Errorf("Unexpected error writing to response writer: %v", err)
		}
	}))
	defer server.Close()

	// Test with URL
	playlist, _, err := ParsePlaylist(server.URL)
	if err != nil {
		t.Errorf("Unexpected error parsing from URL: %v", err)
		return
	}

	if playlist.ID != testPlaylistID {
		t.Errorf("Expected correct ID from URL request")
	}
}

func TestParsePlaylistHTTPError(t *testing.T) {
	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Test with URL that returns 404
	_, _, err := ParsePlaylist(server.URL)
	if err == nil {
		t.Errorf("Expected error for 404 response")
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"https://example.com", true},
		{"http://localhost:8080", true},
		{"ftp://files.example.com", true},
		{"not-a-url", false},
		{"", false},
		{"just-text", false},
		{"/local/path", false},
		{"mailto:test@example.com", false}, // This doesn't have a proper host part for URL parsing
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isURL(tt.input)
			if result != tt.expected {
				t.Errorf("isURL(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCanonicalizePlaylist(t *testing.T) {
	// Create test playlist
	signature := "ed25519:0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	playlist := &Playlist{
		DPVersion: "1.0.0",
		ID:        testPlaylistID,
		Title:     "Test Playlist",
		Created:   "2025-06-03T17:01:00Z",
		Items: []PlaylistItem{
			{
				ID:     testItemID1,
				Source: "https://example.com",
			},
		},
		Signature: &signature,
	}

	canonical, err := CanonicalizePlaylist(playlist, false)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Check that result is valid JSON
	var obj map[string]any
	if err := json.Unmarshal(canonical, &obj); err != nil {
		t.Errorf("Canonical output is not valid JSON: %v", err)
	}

	// Test that canonicalization is deterministic
	canonical2, err := CanonicalizePlaylist(playlist, false)
	if err != nil {
		t.Errorf("Unexpected error on second canonicalization: %v", err)
		return
	}

	if !reflect.DeepEqual(canonical, canonical2) {
		t.Errorf("Canonicalization is not deterministic")
	}

	// Check that canonical form ends with LF terminator
	if len(canonical) == 0 || canonical[len(canonical)-1] != '\n' {
		t.Errorf("Canonical form should end with LF terminator")
	}

	// Check that signable canonical form doesn't have signature
	canonical3, err := CanonicalizePlaylist(playlist, true)
	if err != nil {
		t.Errorf("Unexpected error on third canonicalization: %v", err)
		return
	}

	// Unmarshal the signable canonical form
	var signableObj map[string]any
	if err := json.Unmarshal(canonical3, &signableObj); err != nil {
		t.Errorf("Unexpected error on json unmarshal third canonicalization: %v", err)
		return
	}

	// Check if signature has been removed
	sig, ok := signableObj["signature"].(string)
	if ok && len(sig) > 0 {
		t.Error("Signature canonical form should have signature removed")
	}
}

func TestValidatePlaylistStructure(t *testing.T) {
	validUUID := testPlaylistID
	validItemUUID := testItemID1

	tests := []struct {
		name        string
		playlist    *Playlist
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid playlist with all required fields",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: false,
		},
		{
			name: "Valid playlist with optional fields",
			playlist: &Playlist{
				DPVersion: "2.1.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Display: &Display{
						Scaling:    "fit",
						Background: "#000000",
					},
					License:  "open",
					Duration: 300,
				},
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Title:    "Test Item",
						Source:   "https://example.com",
						Duration: 180,
						License:  "token",
						Ref:      "https://example.com/ref",
					},
				},
				Signature: stringPtr("ed25519:1234567890abcdef"),
			},
			expectError: false,
		},
		{
			name: "Missing dpVersion",
			playlist: &Playlist{
				ID:      validUUID,
				Slug:    "test-playlist",
				Created: "2025-06-03T17:01:00Z",
				Title:   "Test Playlist",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: dpversion",
		},
		{
			name: "Missing ID",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: id",
		},
		{
			name: "Missing title",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: title",
		},
		{
			name: "Missing created",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: created",
		},
		{
			name: "Invalid created timestamp",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "not-a-timestamp",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid created timestamp format",
		},
		{
			name: "No items",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items:     []PlaylistItem{},
			},
			expectError: true,
			errorMsg:    "playlist must contain at least one item",
		},
		{
			name: "Too many items",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items:     make([]PlaylistItem, 1025), // Exceeds max of 1024
			},
			expectError: true,
			errorMsg:    "validation error for field items: max",
		},
		{
			name: "Item missing ID",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: id",
		},
		{
			name: "Item missing source",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: source",
		},
		{
			name: "Invalid UUID format for playlist",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        "invalid-uuid",
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid UUID format for field: id",
		},
		{
			name: "Invalid UUID format for item",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: "invalid-item-uuid", Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid UUID format for field: id",
		},
		{
			name: "Invalid semver",
			playlist: &Playlist{
				DPVersion: "invalid-version",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid semantic version format for dpVersion: invalid-version",
		},
		{
			name: "Invalid URL for item source",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "not-a-url", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid URL format for field source: not-a-url",
		},
		{
			name: "Invalid URL for item ref",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Ref: "not-a-url", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid URL format for field ref: not-a-url",
		},
		{
			name: "Title too long",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     strings.Repeat("a", 257), // Exceeds max of 256
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field title: max",
		},
		{
			name: "Item title too long",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Title: strings.Repeat("a", 257), Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field title: max",
		},
		{
			name: "Invalid slug format",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "invalid slug with spaces",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field slug: alphanum",
		},
		{
			name: "Slug too long",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      strings.Repeat("a", 65), // Exceeds max of 64
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field slug: max",
		},
		{
			name: "Invalid signature format",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
				Signature: stringPtr("invalid-signature"),
			},
			expectError: true,
			errorMsg:    "field signature must start with: ed25519:",
		},
		{
			name: "Invalid defaults license",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					License: "invalid-license",
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid value for field license, must be one of: open token subscription",
		},
		{
			name: "Invalid defaults duration",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Duration: -1, // Must be at least 1
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "field duration must have minimum value/length of 1",
		},
		{
			name: "Valid playlist with display block",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Display: &Display{
						Scaling:    "fit",
						Margin:     "10px",
						Background: "#000000",
						AutoPlay:   true,
						Loop:       false,
					},
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid display scaling",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Display: &Display{
						Scaling: "invalid-scaling",
					},
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "invalid value for field scaling, must be one of: fit fill stretch auto",
		},
		{
			name: "Invalid display margin",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Display: &Display{
						Margin: "invalid-margin",
					},
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field margin: margin",
		},
		{
			name: "Invalid display background",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Defaults: &Defaults{
					Display: &Display{
						Background: "invalid-color",
					},
				},
				Items: []PlaylistItem{
					{ID: validItemUUID, Source: "https://example.com", Duration: 300, License: "open"},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field background: background",
		},
		{
			name: "Valid playlist with repro block",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							Seed:         "abcdef1234567890",
							AssetsSHA256: []string{"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
							FrameHash: &FrameHash{
								SHA256: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
								PHash:  "0xabcdef1234567890",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid repro seed format",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							Seed: "invalid-seed",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field seed must be hexadecimal: invalid-seed",
		},
		{
			name: "Invalid repro asset hash length",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							AssetsSHA256: []string{"short"},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field assetssha256[0] must be exactly 66 characters long",
		},
		{
			name: "Invalid repro asset hash format",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							AssetsSHA256: []string{"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789g"}, // Invalid hex
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field assetssha256[0] must be hexadecimal: 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789g",
		},
		{
			name: "Missing repro frame hash SHA256",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							FrameHash: &FrameHash{
								// SHA256 is missing
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: sha256",
		},
		{
			name: "Invalid repro frame hash length",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							FrameHash: &FrameHash{
								SHA256: "short",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field sha256 must be exactly 66 characters long",
		},
		{
			name: "Invalid repro p-hash length",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Repro: &ReproBlock{
							FrameHash: &FrameHash{
								SHA256: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
								PHash:  "short",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field phash must be exactly 18 characters long",
		},
		{
			name: "Valid playlist with provenance block",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain:    "evm",
								Standard: "erc721",
								Address:  "123456789012345678901234567890123456789012345678",
								TokenID:  "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678",
								URI:      "https://example.com/metadata",
								MetaHash: "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Invalid provenance type",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "invalid-type",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid value for field type, must be one of: onChain seriesRegistry offChainURI",
		},
		{
			name: "Missing provenance contract chain",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type:     "onChain",
							Contract: &Contract{
								// Chain is missing
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "missing required field: chain",
		},
		{
			name: "Invalid provenance contract chain",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain: "invalid-chain",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid value for field chain, must be one of: evm tezos bitmark other",
		},
		{
			name: "Invalid provenance contract standard",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain:    "evm",
								Standard: "invalid-standard",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid value for field standard, must be one of: erc1155 erc721 fa2 other",
		},
		{
			name: "Invalid provenance contract address length",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain:   "evm",
								Address: strings.Repeat("a", 49), // Exceeds max of 48
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "validation error for field address: max",
		},
		{
			name: "Invalid provenance contract URI",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain: "evm",
								URI:   "not-a-url",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "invalid URL format for field uri: not-a-url",
		},
		{
			name: "Invalid provenance contract meta hash",
			playlist: &Playlist{
				DPVersion: "1.0.0",
				ID:        validUUID,
				Slug:      "test-playlist",
				Title:     "Test Playlist",
				Created:   "2025-06-03T17:01:00Z",
				Items: []PlaylistItem{
					{
						ID:       validItemUUID,
						Source:   "https://example.com",
						Duration: 300,
						License:  "open",
						Provenance: &Provenance{
							Type: "onChain",
							Contract: &Contract{
								Chain:    "evm",
								MetaHash: "invalid-hash",
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "field metahash must be exactly 66 characters long",
		},
		{
			name:        "Nil playlist",
			playlist:    nil,
			expectError: true,
			errorMsg:    "playlist cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePlaylistStructure(tt.playlist)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestHasSignature(t *testing.T) {
	tests := []struct {
		name     string
		playlist *Playlist
		expected bool
	}{
		{
			name: "With signature",
			playlist: &Playlist{
				Signature: stringPtr("ed25519:abcdef123456"),
			},
			expected: true,
		},
		{
			name: "Without signature",
			playlist: &Playlist{
				Signature: stringPtr(""),
			},
			expected: false,
		},
		{
			name:     "Nil signature field",
			playlist: &Playlist{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasSignature(tt.playlist)
			if result != tt.expected {
				t.Errorf("HasSignature() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestExtractAssetHashes(t *testing.T) {
	tests := []struct {
		name     string
		playlist *Playlist
		expected []string
	}{
		{
			name: "Multiple items with hashes",
			playlist: &Playlist{
				Items: []PlaylistItem{
					{
						Repro: &ReproBlock{
							AssetsSHA256: []string{"hash1", "hash2"},
						},
					},
					{
						Repro: &ReproBlock{
							AssetsSHA256: []string{"hash3"},
						},
					},
				},
			},
			expected: []string{"hash1", "hash2", "hash3"},
		},
		{
			name: "No repro blocks",
			playlist: &Playlist{
				Items: []PlaylistItem{
					{ID: testItemID1},
					{ID: testItemID2},
				},
			},
			expected: nil,
		},
		{
			name: "Mixed items",
			playlist: &Playlist{
				Items: []PlaylistItem{
					{ID: testItemID1}, // No repro
					{
						Repro: &ReproBlock{
							AssetsSHA256: []string{"hash1"},
						},
					},
					{
						Repro: &ReproBlock{}, // Empty assets
					},
				},
			},
			expected: []string{"hash1"},
		},
		{
			name:     "Empty playlist",
			playlist: &Playlist{Items: []PlaylistItem{}},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractAssetHashes(tt.playlist)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ExtractAssetHashes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMarginValueMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedString string
		expectError    bool
		errorContains  string
	}{
		// Valid string inputs
		{
			name:           "String with px units",
			input:          `"10px"`,
			expectedString: "10px",
			expectError:    false,
		},
		{
			name:           "String with percentage",
			input:          `"5%"`,
			expectedString: "5%",
			expectError:    false,
		},
		{
			name:           "String with vw units",
			input:          `"2.5vw"`,
			expectedString: "2.5vw",
			expectError:    false,
		},
		{
			name:           "String with vh units",
			input:          `"100vh"`,
			expectedString: "100vh",
			expectError:    false,
		},
		{
			name:           "String with decimal px",
			input:          `"10.5px"`,
			expectedString: "10.5px",
			expectError:    false,
		},
		{
			name:           "Zero with units",
			input:          `"0px"`,
			expectedString: "0px",
			expectError:    false,
		},
		// Valid number inputs (should be converted to px)
		{
			name:           "Integer number",
			input:          `15`,
			expectedString: "15px",
			expectError:    false,
		},
		{
			name:           "Decimal number",
			input:          `10.5`,
			expectedString: "11px", // Rounded to nearest integer
			expectError:    false,
		},
		{
			name:           "Zero number",
			input:          `0`,
			expectedString: "0px",
			expectError:    false,
		},
		{
			name:           "Large number",
			input:          `999`,
			expectedString: "999px",
			expectError:    false,
		},
		// Invalid JSON inputs (should fail during unmarshaling)
		{
			name:          "Invalid JSON",
			input:         `invalid`,
			expectError:   true,
			errorContains: "invalid character",
		},
		{
			name:          "Boolean value",
			input:         `true`,
			expectError:   true,
			errorContains: "margin must be a string or number",
		},
		{
			name:        "Null value",
			input:       `null`,
			expectError: false, // null should be handled gracefully
		},
		{
			name:          "Array value",
			input:         `[10]`,
			expectError:   true,
			errorContains: "margin must be a string or number",
		},
		{
			name:          "Object value",
			input:         `{"value": 10}`,
			expectError:   true,
			errorContains: "margin must be a string or number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test unmarshaling
			var margin Margin
			err := json.Unmarshal([]byte(tt.input), &margin)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check the string representation
			if margin.String() != tt.expectedString {
				t.Errorf("Expected string %q, got %q", tt.expectedString, margin.String())
			}

			// Test marshaling back to JSON
			marshaled, err := json.Marshal(margin)
			if err != nil {
				t.Errorf("Failed to marshal: %v", err)
				return
			}

			// The marshaled result should be a JSON string
			expectedJSON := fmt.Sprintf(`"%s"`, tt.expectedString)
			if string(marshaled) != expectedJSON {
				t.Errorf("Expected marshaled JSON %q, got %q", expectedJSON, string(marshaled))
			}

			// Test round-trip: unmarshal -> marshal -> unmarshal
			var margin2 Margin
			err = json.Unmarshal(marshaled, &margin2)
			if err != nil {
				t.Errorf("Failed to unmarshal marshaled result: %v", err)
				return
			}

			if margin2.String() != margin.String() {
				t.Errorf("Round-trip failed: original %q, round-trip %q", margin.String(), margin2.String())
			}
		})
	}
}

// Benchmark tests
func BenchmarkParsePlaylist(b *testing.B) {
	for range b.N {
		_, _, _ = ParsePlaylist(validPlaylistJSON)
	}
}

func BenchmarkCanonicalizePlaylist(b *testing.B) {
	playlist := &Playlist{
		DPVersion: "1.0.0",
		ID:        testPlaylistID,
		Created:   "2025-06-03T17:01:00Z",
		Items: []PlaylistItem{
			{ID: testItemID1, Source: "https://example.com"},
		},
	}

	b.ResetTimer()
	for range b.N {
		_, _ = CanonicalizePlaylist(playlist, false)
	}
}
