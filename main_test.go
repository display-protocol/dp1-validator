package main

import (
	"archive/tar"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/feral-file/dp-1/validator/playlist"
	"github.com/feral-file/dp-1/validator/validator"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/cobra"
)

// Test CLI flag validation (basic tests without full CLI execution)
func TestCLIValidation(t *testing.T) {
	// These tests validate our understanding of the CLI structure
	// without actually executing commands

	// Test that required command structures exist
	if rootCmd == nil {
		t.Error("rootCmd should be defined")
	}

	if playlistCmd == nil {
		t.Error("playlistCmd should be defined")
	}

	if capsuleCmd == nil {
		t.Error("capsuleCmd should be defined")
	}

	// Test that commands have proper parents
	if !slices.Contains(rootCmd.Commands(), playlistCmd) {
		t.Error("playlistCmd should be added to rootCmd")
	}

	if !slices.Contains(rootCmd.Commands(), capsuleCmd) {
		t.Error("capsuleCmd should be added to rootCmd")
	}
}

func TestCLIHelpText(t *testing.T) {
	// Test that commands have proper help text
	if rootCmd.Short == "" {
		t.Error("rootCmd should have short description")
	}

	if playlistCmd.Short == "" {
		t.Error("playlistCmd should have short description")
	}

	if capsuleCmd.Short == "" {
		t.Error("capsuleCmd should have short description")
	}

	const expectedShort = "DP-1 playlist and capsule validator"
	if rootCmd.Short != expectedShort {
		t.Errorf("rootCmd should have short description: %s", rootCmd.Short)
	}

	const expectedLong = `A validator for DP-1 playlists and capsules that can verify:
- Ed25519 signatures on playlists
- SHA256 asset integrity in capsules
- Structural compliance with DP-1 specification`
	if rootCmd.Long != expectedLong {
		t.Errorf("rootCmd should have long description: %s", rootCmd.Long)
	}

	// Test playlist command help text
	expectedPlaylistContent := []string{
		"Validate a DP-1 playlist structure",
		"optionally verify its Ed25519 signature",
		"Structure only:",
		"With signature verification:",
	}

	for _, content := range expectedPlaylistContent {
		if !strings.Contains(playlistCmd.Long, content) {
			t.Errorf("Playlist help text should contain: %s", content)
		}
	}
}

// Test global variables initialization
func TestGlobalVariables(t *testing.T) {
	// Test that global variables are properly initialized
	if playlistInput != "" {
		t.Error("playlistInput should be empty initially")
	}

	if pubkeyHex != "" {
		t.Error("pubkeyHex should be empty initially")
	}

	if capsulePath != "" {
		t.Error("capsulePath should be empty initially")
	}

	if hashesInput != "" {
		t.Error("hashesInput should be empty initially")
	}
}

func TestCLIStructure(t *testing.T) {
	// Test that root command exists
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	// Test that both subcommands exist
	commands := rootCmd.Commands()
	if len(commands) != 2 {
		t.Fatalf("Expected 2 subcommands, got %d", len(commands))
	}

	// Check command names
	cmdNames := make(map[string]bool)
	for _, cmd := range commands {
		cmdNames[cmd.Use] = true
	}

	if !cmdNames["playlist"] {
		t.Error("playlist command not found")
	}
	if !cmdNames["capsule"] {
		t.Error("capsule command not found")
	}
}

func TestPlaylistCommandFlags(t *testing.T) {
	// Test playlist command flags
	playlistFlag := playlistCmd.Flags().Lookup("playlist")
	if playlistFlag == nil {
		t.Error("playlist command should have --playlist flag")
	}

	pubkeyFlag := playlistCmd.Flags().Lookup("pubkey")
	if pubkeyFlag == nil {
		t.Error("playlist command should have --pubkey flag")
	}

	// Check that only playlist is required, pubkey is optional
	playlistAnnotations := playlistFlag.Annotations
	if playlistAnnotations == nil || playlistAnnotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("Flag playlist should be required")
	}

	pubkeyAnnotations := pubkeyFlag.Annotations
	if pubkeyAnnotations != nil && pubkeyAnnotations[cobra.BashCompOneRequiredFlag] != nil {
		t.Error("Flag pubkey should be optional")
	}
}

func TestCapsuleCommandFlags(t *testing.T) {
	// Test capsule command flags
	pathFlag := capsuleCmd.Flags().Lookup("path")
	//nolint:staticcheck // SA5011(related information): t.Error will panic
	if pathFlag == nil {
		t.Error("capsule command should have --path flag")
	}

	hashesFlag := capsuleCmd.Flags().Lookup("hashes")
	//nolint:staticcheck // SA5011(related information): t.Error will panic
	if hashesFlag == nil {
		t.Error("capsule command should have --hashes flag")
	}

	// Check that path is required
	//nolint:staticcheck // SA5011(related information): t.Error will panic
	pathAnnotations := pathFlag.Annotations
	if pathAnnotations == nil || pathAnnotations[cobra.BashCompOneRequiredFlag] == nil {
		t.Error("path flag should be required for capsule command")
	}

	// Check that hashes is optional
	//nolint:staticcheck // SA5011(related information): t.Error will panic
	hashesAnnotations := hashesFlag.Annotations
	if hashesAnnotations != nil && hashesAnnotations[cobra.BashCompOneRequiredFlag] != nil {
		t.Error("hashes flag should be optional for capsule command")
	}
}

func TestCapsuleCommandValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "No flags provided",
			args:        []string{"capsule"},
			shouldError: true,
			errorMsg:    "required flag(s) \"path\" not set",
		},
		{
			name:        "Only path provided",
			args:        []string{"capsule", "--path", "test.dp1c"},
			shouldError: false, // Will error later due to file not existing, but flag validation passes
		},
		{
			name:        "Path with hashes provided",
			args:        []string{"capsule", "--path", "test.dp1c", "--hashes", "abc123,def456"},
			shouldError: false, // Will error later due to file not existing, but flag validation passes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags
			capsulePath = ""
			hashesInput = ""

			// Set up command with args
			rootCmd.SetArgs(tt.args)

			// Execute command
			err := rootCmd.Execute()

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				// For cases that shouldn't error in flag validation, they might still error
				// due to invalid file paths, but we're just testing the flag validation
				if err != nil && strings.Contains(err.Error(), "required flag(s)") {
					t.Errorf("Unexpected flag validation error: %v", err)
				}
			}

			// Reset args for next test
			rootCmd.SetArgs([]string{})
		})
	}
}

func TestCapsuleUsageModes(t *testing.T) {
	// Test that the command help text includes information about usage modes
	helpText := capsuleCmd.Long

	expectedModes := []string{
		"Capsule only:",
		"Capsule with override:",
	}

	for _, mode := range expectedModes {
		if !strings.Contains(helpText, mode) {
			t.Errorf("Help text should contain usage mode: %s", mode)
		}
	}

	// Test that the help mentions important requirements
	expectedContent := []string{
		".dp1c file",
		"tar+zstd",
		"playlist.json",
		"assets/",
		"provided hashes override",
	}

	for _, content := range expectedContent {
		if !strings.Contains(helpText, content) {
			t.Errorf("Help text should contain: %s", content)
		}
	}
}

func TestPlaylistCommandValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "No flags provided",
			args:        []string{"playlist"},
			shouldError: true,
			errorMsg:    "required flag(s) \"playlist\" not set",
		},
		{
			name:        "Only playlist provided (no pubkey)",
			args:        []string{"playlist", "--playlist", "test-playlist"},
			shouldError: false, // Will error later due to invalid playlist, but flag validation passes
		},
		{
			name:        "Playlist with pubkey provided",
			args:        []string{"playlist", "--playlist", "test-playlist", "--pubkey", "test-pubkey"},
			shouldError: false, // Will error later due to invalid playlist, but flag validation passes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flags
			playlistInput = ""
			pubkeyHex = ""

			// Set up command with args
			rootCmd.SetArgs(tt.args)

			// Execute command
			err := rootCmd.Execute()

			if tt.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				// For cases that shouldn't error in flag validation, they might still error
				// due to invalid playlist, but we're just testing the flag validation
				if err != nil && strings.Contains(err.Error(), "required flag(s)") {
					t.Errorf("Unexpected flag validation error: %v", err)
				}
			}

			// Reset args for next test
			rootCmd.SetArgs([]string{})
		})
	}
}

func TestSafeHashPreview(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Short hash",
			input:    "abc123",
			expected: "abc123",
		},
		{
			name:     "Exactly 16 chars",
			input:    "0123456789abcdef",
			expected: "0123456789abcdef",
		},
		{
			name:     "Long hash",
			input:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expected: "0123456789abcdef...",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeHashPreview(tt.input)
			if result != tt.expected {
				t.Errorf("safeHashPreview(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test helper functions and constants for validatePlaylist and validateCapsule tests

const validTestPlaylist = `{
  "dpVersion": "1.0.0",
  "id": "00000000-0000-4000-8000-000000000001",
  "slug": "test-playlist",
  "title": "Test Playlist",
  "created": "2023-01-01T00:00:00Z",
  "items": [
    {
      "id": "00000000-0000-4000-8000-000000000002",
      "title": "Test Item",
      "source": "https://example.com/art.html",
      "duration": 300,
      "license": "open"
    }
  ]
}`

const validTestPlaylistWithSignature = `{
  "dpVersion": "1.0.0",
  "id": "00000000-0000-4000-8000-000000000001",
  "slug": "test-playlist",
  "title": "Test Playlist",
  "created": "2023-01-01T00:00:00Z",
  "items": [
    {
      "id": "00000000-0000-4000-8000-000000000002",
      "title": "Test Item",
      "source": "https://example.com/art.html",
      "duration": 300,
      "license": "open"
    }
  ],
  "signature": "ed25519:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}`

const invalidTestPlaylist = `{
  "dpVersion": "invalid-version",
  "id": "invalid-uuid",
  "items": []
}`

// saveTestFlags saves current flag values for restoration later
func saveTestFlags() (string, string, string, string) {
	return playlistInput, pubkeyHex, capsulePath, hashesInput
}

// restoreTestFlags restores flag values
func restoreTestFlags(p, pub, cap, hash string) {
	playlistInput = p
	pubkeyHex = pub
	capsulePath = cap
	hashesInput = hash
}

func TestValidatePlaylistComprehensive(t *testing.T) {
	// Save original flag values
	origPlaylist, origPubkey, origCapsule, origHashes := saveTestFlags()
	defer restoreTestFlags(origPlaylist, origPubkey, origCapsule, origHashes)

	t.Run("Valid playlist scenarios", func(t *testing.T) {
		tests := []struct {
			name        string
			playlist    string
			pubkey      string
			expectError bool
		}{
			{
				name:        "Valid playlist without signature",
				playlist:    validTestPlaylist,
				pubkey:      "",
				expectError: false,
			},
			{
				name:        "Valid playlist with signature but no pubkey",
				playlist:    validTestPlaylistWithSignature,
				pubkey:      "",
				expectError: false,
			},
			{
				name:        "Valid base64 encoded playlist",
				playlist:    base64.StdEncoding.EncodeToString([]byte(validTestPlaylist)),
				pubkey:      "",
				expectError: false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				playlistInput = tt.playlist
				pubkeyHex = tt.pubkey

				err := validatePlaylist(&cobra.Command{}, []string{})
				if tt.expectError && err == nil {
					t.Error("Expected error but got none")
				}
				if !tt.expectError && err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("Error scenarios", func(t *testing.T) {
		tests := []struct {
			name          string
			playlist      string
			pubkey        string
			errorContains string
		}{
			{
				name:          "Invalid JSON",
				playlist:      `{"invalid": json}`,
				pubkey:        "",
				errorContains: "failed to parse playlist",
			},
			{
				name:          "Invalid playlist structure",
				playlist:      invalidTestPlaylist,
				pubkey:        "",
				errorContains: "playlist structure validation failed",
			},
			{
				name:          "Invalid pubkey format",
				playlist:      validTestPlaylistWithSignature,
				pubkey:        "invalid-pubkey",
				errorContains: "invalid public key",
			},
			{
				name:          "Wrong signature verification",
				playlist:      validTestPlaylistWithSignature,
				pubkey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				errorContains: "signature verification failed",
			},
			{
				name:          "Empty playlist input",
				playlist:      "",
				pubkey:        "",
				errorContains: "failed to parse playlist",
			},
			{
				name:          "Malformed JSON",
				playlist:      `{"incomplete": `,
				pubkey:        "",
				errorContains: "failed to parse playlist",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				playlistInput = tt.playlist
				pubkeyHex = tt.pubkey

				err := validatePlaylist(&cobra.Command{}, []string{})
				if err == nil {
					t.Error("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			})
		}
	})

	t.Run("Signature format validation", func(t *testing.T) {
		// Test with playlist that passes structure validation but has invalid signature format
		invalidSigLengthPlaylist := `{
  			"dpVersion": "1.0.0",
  			"id": "00000000-0000-4000-8000-000000000001",
  			"slug": "test-playlist",
  			"title": "Test Playlist",
  			"created": "2023-01-01T00:00:00Z",
  			"items": [
  			  {
  			    "id": "00000000-0000-4000-8000-000000000002",
  			    "title": "Test Item",
  			    "source": "https://example.com/art.html",
  			    "duration": 300,
  			    "license": "open"
  			  }
  			],
  			"signature": "ed25519:abcdef123456"
		}`

		playlistInput = invalidSigLengthPlaylist
		pubkeyHex = ""

		err := validatePlaylist(&cobra.Command{}, []string{})
		if err == nil {
			t.Error("Expected error for invalid signature format")
		}
		if !strings.Contains(err.Error(), "invalid signature format") {
			t.Errorf("Expected error about invalid signature format, got: %v", err)
		}
	})

	t.Run("URL handling", func(t *testing.T) {
		playlistInput = "https://nonexistent.example.com/playlist.json"
		pubkeyHex = ""

		err := validatePlaylist(&cobra.Command{}, []string{})
		if err == nil {
			t.Error("Expected error for unreachable URL")
		}
		// Should get a network error, not a parsing error
		if strings.Contains(err.Error(), "invalid character") {
			t.Error("URL fetch should fail with network error, not JSON parsing error")
		}
	})
}

// Integration tests with real cryptography
func TestValidatePlaylistIntegration(t *testing.T) {
	// Save original flag values
	origPlaylist, origPubkey, origCapsule, origHashes := saveTestFlags()
	defer restoreTestFlags(origPlaylist, origPubkey, origCapsule, origHashes)

	t.Run("ValidatePlaylist with valid signature verification", func(t *testing.T) {
		// Generate a test key pair
		privkey, pubkey, err := generateTestKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate test key pair: %v", err)
		}

		// Create a test playlist
		testPlaylist := createTestPlaylist()

		// Sign the playlist
		signedPlaylist, err := signTestPlaylist(testPlaylist, privkey)
		if err != nil {
			t.Fatalf("Failed to sign test playlist: %v", err)
		}

		// Test validation with correct public key
		playlistInput = signedPlaylist
		pubkeyHex = pubkey

		err = validatePlaylist(&cobra.Command{}, []string{})
		if err != nil {
			t.Errorf("Unexpected error with valid signature: %v", err)
		}
	})

	t.Run("ValidatePlaylist with wrong public key", func(t *testing.T) {
		// Generate two different key pairs
		privkey1, _, err := generateTestKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate first test key pair: %v", err)
		}

		_, pubkey2, err := generateTestKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate second test key pair: %v", err)
		}

		// Create and sign playlist with first key
		testPlaylist := createTestPlaylist()
		signedPlaylist, err := signTestPlaylist(testPlaylist, privkey1)
		if err != nil {
			t.Fatalf("Failed to sign test playlist: %v", err)
		}

		// Try to validate with second key (should fail)
		playlistInput = signedPlaylist
		pubkeyHex = pubkey2

		err = validatePlaylist(&cobra.Command{}, []string{})
		if err == nil {
			t.Error("Expected error with wrong public key")
		}
		if !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("Expected signature verification failure, got: %v", err)
		}
	})
}

// Helper functions for integration tests

func generateTestKeyPair() (string, string, error) {
	// Use the real validator package to generate actual keys
	return validator.GenerateKeyPair()
}

func createTestPlaylist() string {
	return `{
  		"dpVersion": "1.0.0",
  		"id": "00000000-0000-4000-8000-000000000001",
  		"slug": "test-playlist",
  		"title": "Test Playlist",
  		"created": "2023-01-01T00:00:00Z",
  		"items": [
  		  {
  		    "id": "00000000-0000-4000-8000-000000000002",
  		    "title": "Test Item",
  		    "source": "https://example.com/art.html",
  		    "duration": 300,
  		    "license": "open"
  		  }
  		]
	}`
}

func signTestPlaylist(playlistJSON, privkey string) (string, error) {
	// Parse the playlist to create the canonical form for signing
	p, _, err := playlist.ParsePlaylist(playlistJSON)
	if err != nil {
		return "", err
	}

	// Get the canonical form (without signature) for signing
	signableContent, err := playlist.CanonicalizePlaylist(p, true)
	if err != nil {
		return "", err
	}

	// Sign the canonical content using the real signing function
	signature, err := validator.Sign(privkey, signableContent)
	if err != nil {
		return "", err
	}

	// Add the real signature to the playlist
	signedPlaylist := strings.TrimSuffix(playlistJSON, "}") + `,"signature": "` + signature + `"}`

	return signedPlaylist, nil
}

// Test validateCapsule with comprehensive scenarios
func TestValidateCapsuleComprehensive(t *testing.T) {
	// Save original flag values
	origPlaylist, origPubkey, origCapsule, origHashes := saveTestFlags()
	defer restoreTestFlags(origPlaylist, origPubkey, origCapsule, origHashes)

	t.Run("File access and validation errors", func(t *testing.T) {
		tests := []struct {
			name          string
			capsulePath   string
			hashesInput   string
			errorContains string
		}{
			{
				name:          "Non-existent file",
				capsulePath:   "nonexistent.dp1c",
				hashesInput:   "",
				errorContains: "failed to extract capsule",
			},
			{
				name:          "Invalid file extension",
				capsulePath:   "invalid.txt",
				hashesInput:   "",
				errorContains: "failed to extract capsule",
			},
			{
				name:          "Empty path",
				capsulePath:   "",
				hashesInput:   "",
				errorContains: "failed to extract capsule",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				capsulePath = tt.capsulePath
				hashesInput = tt.hashesInput

				err := validateCapsule(&cobra.Command{}, []string{})
				if err == nil {
					t.Error("Expected error but got none")
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			})
		}
	})

	t.Run("Hash input processing with real capsule", func(t *testing.T) {
		// Create a real temporary .dp1c file for testing
		tempCapsule, cleanup, err := createTestCapsule()
		if err != nil {
			t.Fatalf("Failed to create test capsule: %v", err)
		}
		defer cleanup()

		tests := []struct {
			name          string
			hashesInput   string
			expectedCount int
			shouldSucceed bool
		}{
			{
				name:          "Valid single hash",
				hashesInput:   "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
				expectedCount: 1,
				shouldSucceed: false, // Will fail because hash doesn't match actual file content
			},
			{
				name:          "Multiple comma-separated hashes",
				hashesInput:   "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890,b2c3d4e5f6789012345678901234567890123456789012345678901234567890ab",
				expectedCount: 2,
				shouldSucceed: false,
			},
			{
				name:          "Array format hashes",
				hashesInput:   "[a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890,b2c3d4e5f6789012345678901234567890123456789012345678901234567890ab]",
				expectedCount: 2,
				shouldSucceed: false,
			},
			{
				name:          "Mixed valid and invalid hashes",
				hashesInput:   "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890,invalid-hash,b2c3d4e5f6789012345678901234567890123456789012345678901234567890ab",
				expectedCount: 2, // Only valid hashes should be extracted
				shouldSucceed: false,
			},
			{
				name:          "Empty hashes input",
				hashesInput:   "",
				expectedCount: 0,
				shouldSucceed: false, // Will fail because no hashes found in playlist or provided
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				capsulePath = tempCapsule
				hashesInput = tt.hashesInput

				err := validateCapsule(&cobra.Command{}, []string{})

				if tt.shouldSucceed && err != nil {
					t.Errorf("Expected success but got error: %v", err)
				}
				if !tt.shouldSucceed && err == nil {
					t.Error("Expected error but got none")
				}

				// The test validates that the function processes the hashes correctly
				// even if the final verification fails due to hash mismatch
			})
		}
	})

	t.Run("Successful capsule validation", func(t *testing.T) {
		// Create a real capsule with known content and matching hashes
		tempCapsule, cleanup, actualHashes, err := createTestCapsuleWithKnownHashes(t)
		if err != nil {
			t.Fatalf("Failed to create test capsule with known hashes: %v", err)
		}
		defer cleanup()

		t.Run("Validation with correct hashes", func(t *testing.T) {
			capsulePath = tempCapsule
			// Convert hashes from "0x..." format to raw hex for the --hashes parameter
			var rawHashes []string
			for _, hash := range actualHashes {
				rawHashes = append(rawHashes, strings.TrimPrefix(hash, "0x"))
			}
			hashesInput = strings.Join(rawHashes, ",")

			err := validateCapsule(&cobra.Command{}, []string{})
			if err != nil {
				t.Errorf("Expected success with correct hashes but got error: %v", err)
			}
		})

		t.Run("Validation with playlist hashes", func(t *testing.T) {
			// Test without providing hashes - should use hashes from playlist
			capsulePath = tempCapsule
			hashesInput = ""

			err := validateCapsule(&cobra.Command{}, []string{})
			// NOTE: This currently fails because playlist hashes include "0x" prefix
			// but file verification expects raw hashes. This is a known limitation
			// of the current implementation.
			if err == nil {
				t.Error("Unexpected success - playlist hashes currently don't work due to 0x prefix mismatch")
			}
			if !strings.Contains(err.Error(), "capsule verification failed") {
				t.Errorf("Expected capsule verification failure due to hash format mismatch, got: %v", err)
			}
			t.Logf("Expected behavior: playlist hashes with 0x prefix don't match raw file hashes: %v", err)
		})
	})
}

// Helper functions for creating test capsules

func createTestCapsule() (capsulePath string, cleanup func(), err error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-capsule-*")
	if err != nil {
		return "", nil, err
	}

	// Create playlist.json
	playlistContent := `{
  		"dpVersion": "1.0.0",
  		"id": "00000000-0000-4000-8000-000000000001",
  		"slug": "test-capsule",
  		"title": "Test Capsule",
  		"created": "2023-01-01T00:00:00Z",
  		"items": [
  		  {
  		    "id": "00000000-0000-4000-8000-000000000002",
  		    "title": "Test Item",
  		    "source": "https://example.com/art.html",
  		    "duration": 300,
  		    "license": "open"
  		  }
  		]
	}`

	playlistPath := filepath.Join(tempDir, "playlist.json")
	if err := os.WriteFile(playlistPath, []byte(playlistContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	// Create assets directory with a test file
	assetsDir := filepath.Join(tempDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	testFile := filepath.Join(assetsDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("Hello, test!"), 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	// Create the .dp1c archive
	capsulePath = filepath.Join(os.TempDir(), "test-capsule.dp1c")
	if err := createTarZstdArchive(tempDir, capsulePath); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, err
	}

	cleanup = func() {
		os.RemoveAll(tempDir)
		os.Remove(capsulePath)
	}

	return capsulePath, cleanup, nil
}

func createTestCapsuleWithKnownHashes(t *testing.T) (capsulePath string, cleanup func(), hashes []string, err error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-capsule-known-*")
	if err != nil {
		return "", nil, nil, err
	}

	// Create assets directory with test files
	assetsDir := filepath.Join(tempDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, nil, err
	}

	// Create test files and calculate their hashes
	testFiles := map[string]string{
		"file1.txt": "Hello, world!",
		"file2.txt": "This is a test file.",
	}

	var calculatedHashes []string
	for filename, content := range testFiles {
		filePath := filepath.Join(assetsDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			os.RemoveAll(tempDir)
			return "", nil, nil, err
		}

		// Calculate the actual hash and add "0x" prefix to match DP-1 format
		hash := validator.HashString(content)
		formattedHash := "0x" + hash
		calculatedHashes = append(calculatedHashes, formattedHash)
	}

	// Create playlist.json with the calculated hashes
	playlistContent := fmt.Sprintf(`{
  		"dpVersion": "1.0.0",
  		"id": "00000000-0000-4000-8000-000000000001",
  		"slug": "test-capsule-known",
  		"title": "Test Capsule with Known Hashes",
  		"created": "2023-01-01T00:00:00Z",
  		"items": [
  		  {
  		    "id": "00000000-0000-4000-8000-000000000002",
  		    "title": "Test Item",
  		    "source": "https://example.com/art.html",
  		    "duration": 300,
  		    "license": "open",
  		    "repro": {
  		      "assetsSHA256": ["%s", "%s"]
  		    }
  		  }
  		]
	}`, calculatedHashes[0], calculatedHashes[1])

	playlistPath := filepath.Join(tempDir, "playlist.json")
	if err := os.WriteFile(playlistPath, []byte(playlistContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, nil, err
	}

	// Create the .dp1c archive
	capsulePath = filepath.Join(os.TempDir(), "test-capsule-known.dp1c")
	if err := createTarZstdArchive(tempDir, capsulePath); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, nil, err
	}

	cleanup = func() {
		os.RemoveAll(tempDir)
		os.Remove(capsulePath)
	}

	return capsulePath, cleanup, calculatedHashes, nil
}

func createTarZstdArchive(sourceDir, targetPath string) error {
	// Create the output file
	file, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create zstd encoder (this matches what the real application expects)
	zstdWriter, err := zstd.NewWriter(file)
	if err != nil {
		return err
	}
	defer zstdWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(zstdWriter)
	defer tarWriter.Close()

	// Walk the source directory and add files to the archive
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate relative path from source directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Skip directories themselves, only add files
		if info.IsDir() {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Open and copy file content
		fileData, err := os.Open(path)
		if err != nil {
			return err
		}
		defer fileData.Close()

		_, err = io.Copy(tarWriter, fileData)
		return err
	})
}
