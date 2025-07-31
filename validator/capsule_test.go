package validator

import (
	"archive/tar"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// createTestCapsule creates a test .dp1c file with the given content
func createTestCapsule(t *testing.T, playlistData map[string]interface{}, assets map[string]string) string {
	t.Helper()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-capsule-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	// Create capsule content directory
	capsuleDir := filepath.Join(tempDir, "capsule")
	if err := os.MkdirAll(capsuleDir, 0750); err != nil {
		t.Fatalf("Failed to create capsule dir: %v", err)
	}

	// Write playlist.json
	playlistJSON, err := json.MarshalIndent(playlistData, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal playlist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
		t.Fatalf("Failed to write playlist.json: %v", err)
	}

	// Create assets directory (now required)
	assetsDir := filepath.Join(capsuleDir, "assets")
	if err := os.MkdirAll(assetsDir, 0750); err != nil {
		t.Fatalf("Failed to create assets dir: %v", err)
	}

	// Write asset files
	for filename, content := range assets {
		if err := os.WriteFile(filepath.Join(assetsDir, filename), []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write asset %s: %v", filename, err)
		}
	}

	// Create .dp1c archive
	capsulePath := filepath.Join(tempDir, "test.dp1c")
	if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
		t.Fatalf("Failed to create .dp1c archive: %v", err)
	}

	return capsulePath
}

// createTarZstdArchive creates a tar+zstd archive from a directory
func createTarZstdArchive(sourceDir, archivePath string) error {
	// Create archive file
	//nolint:gosec // G304: Ignore for testing
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Create zstd encoder
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		return err
	}
	defer func() { _ = encoder.Close() }()

	// Create tar writer
	tarWriter := tar.NewWriter(encoder)
	defer func() { _ = tarWriter.Close() }()

	// Walk the source directory
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
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

		// Write file content if it's a regular file
		if info.Mode().IsRegular() {
			//nolint:gosec // G304: Ignore for testing
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = file.Close() }()

			_, err = io.Copy(tarWriter, file)
			return err
		}

		return nil
	})
}

// createMaliciousCapsule creates a capsule with a malicious file path for testing path traversal attacks
func createMaliciousCapsule(t *testing.T, maliciousPath, content string) string {
	t.Helper()

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-malicious-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

	// Create capsule content directory
	capsuleDir := filepath.Join(tempDir, "capsule")
	if err := os.MkdirAll(capsuleDir, 0750); err != nil {
		t.Fatalf("Failed to create capsule dir: %v", err)
	}

	// Write playlist.json
	validPlaylist := map[string]any{
		"dpVersion": "1.0.0",
		"id":        "385f79b6-a45f-4c1c-8080-e93a192adccc",
		"slug":      "test-playlist",
		"created":   "2025-01-01T00:00:00Z",
		"title":     "Test Playlist",
		"items":     []any{},
	}
	playlistJSON, err := json.MarshalIndent(validPlaylist, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal playlist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
		t.Fatalf("Failed to write playlist.json: %v", err)
	}

	// Create assets directory
	assetsDir := filepath.Join(capsuleDir, "assets")
	if err := os.MkdirAll(assetsDir, 0750); err != nil {
		t.Fatalf("Failed to create assets dir: %v", err)
	}

	// Create .dp1c archive with malicious path
	capsulePath := filepath.Join(tempDir, "test.dp1c")
	if err := createMaliciousArchive(capsuleDir, capsulePath, maliciousPath, content); err != nil {
		t.Fatalf("Failed to create malicious .dp1c archive: %v", err)
	}

	return capsulePath
}

// createMaliciousArchive creates a tar+zstd archive with a malicious file path
func createMaliciousArchive(sourceDir, archivePath, maliciousPath, content string) error {
	// Create archive file
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Create zstd encoder
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		return err
	}
	defer func() { _ = encoder.Close() }()

	// Create tar writer
	tarWriter := tar.NewWriter(encoder)
	defer func() { _ = tarWriter.Close() }()

	// Add playlist.json
	playlistPath := filepath.Join(sourceDir, "playlist.json")
	playlistInfo, err := os.Stat(playlistPath)
	if err != nil {
		return err
	}

	playlistHeader, err := tar.FileInfoHeader(playlistInfo, "")
	if err != nil {
		return err
	}
	playlistHeader.Name = "playlist.json"

	if err := tarWriter.WriteHeader(playlistHeader); err != nil {
		return err
	}

	playlistFile, err := os.Open(playlistPath)
	if err != nil {
		return err
	}
	defer func() { _ = playlistFile.Close() }()

	if _, err := io.Copy(tarWriter, playlistFile); err != nil {
		return err
	}

	// Add assets directory
	assetsHeader := &tar.Header{
		Name:     "assets",
		Typeflag: tar.TypeDir,
		Mode:     0750,
	}
	if err := tarWriter.WriteHeader(assetsHeader); err != nil {
		return err
	}

	// Add malicious file with the specified path
	maliciousHeader := &tar.Header{
		Name:     maliciousPath,
		Typeflag: tar.TypeReg,
		Mode:     0600,
		Size:     int64(len(content)),
	}
	if err := tarWriter.WriteHeader(maliciousHeader); err != nil {
		return err
	}

	if _, err := tarWriter.Write([]byte(content)); err != nil {
		return err
	}

	return nil
}

// createLargeFileArchive creates a tar+zstd archive with a file that has a large size in the header
func createLargeFileArchive(sourceDir, archivePath string) error {
	// Create archive file
	file, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Create zstd encoder
	encoder, err := zstd.NewWriter(file)
	if err != nil {
		return err
	}
	defer func() { _ = encoder.Close() }()

	// Create tar writer
	tarWriter := tar.NewWriter(encoder)
	defer func() { _ = tarWriter.Close() }()

	// Add playlist.json
	playlistPath := filepath.Join(sourceDir, "playlist.json")
	playlistInfo, err := os.Stat(playlistPath)
	if err != nil {
		return err
	}

	playlistHeader, err := tar.FileInfoHeader(playlistInfo, "")
	if err != nil {
		return err
	}
	playlistHeader.Name = "playlist.json"

	if err := tarWriter.WriteHeader(playlistHeader); err != nil {
		return err
	}

	playlistFile, err := os.Open(playlistPath)
	if err != nil {
		return err
	}
	defer func() { _ = playlistFile.Close() }()

	if _, err := io.Copy(tarWriter, playlistFile); err != nil {
		return err
	}

	// Add assets directory
	assetsHeader := &tar.Header{
		Name:     "assets",
		Typeflag: tar.TypeDir,
		Mode:     0750,
	}
	if err := tarWriter.WriteHeader(assetsHeader); err != nil {
		return err
	}

	// Add small file with exaggerated size in header
	smallFilePath := filepath.Join(sourceDir, "assets", "small.txt")
	smallFileInfo, err := os.Stat(smallFilePath)
	if err != nil {
		return err
	}

	smallFileHeader, err := tar.FileInfoHeader(smallFileInfo, "")
	if err != nil {
		return err
	}
	smallFileHeader.Name = "assets/small.txt"
	// Set a size that exceeds the 1GB limit (1GB + 1 byte)
	smallFileHeader.Size = 1024*1024*1024 + 1

	if err := tarWriter.WriteHeader(smallFileHeader); err != nil {
		return err
	}

	smallFile, err := os.Open(smallFilePath)
	if err != nil {
		return err
	}
	defer func() { _ = smallFile.Close() }()

	if _, err := io.Copy(tarWriter, smallFile); err != nil {
		return err
	}

	return nil
}

func TestExtractCapsule(t *testing.T) {
	// Valid playlist for testing (using proper UUIDs from playlist package)
	validPlaylist := map[string]any{
		"dpVersion": "1.0.0",
		"id":        "385f79b6-a45f-4c1c-8080-e93a192adccc", // Use valid UUID
		"slug":      "test-playlist",
		"created":   "2025-01-01T00:00:00Z",
		"title":     "Test Playlist",
		"items": []any{
			map[string]any{
				"id":       "285f79b6-a45f-4c1c-8080-e93a192adccc", // Use valid UUID
				"source":   "https://example.com/test.html",
				"duration": 300,
				"license":  "open",
				"repro": map[string]any{
					"assetsSHA256": []any{
						"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						"0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
					},
				},
			},
		},
	}

	assets := map[string]string{
		"test1.txt": "Hello World",
		"test2.txt": "Test Content",
	}

	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid capsule",
			setupFile: func(t *testing.T) string {
				return createTestCapsule(t, validPlaylist, assets)
			},
			expectError: false,
		},
		{
			name: "Invalid file extension",
			setupFile: func(t *testing.T) string {
				capsulePath := createTestCapsule(t, validPlaylist, assets)
				// Rename to invalid extension
				invalidPath := strings.TrimSuffix(capsulePath, ".dp1c") + ".zip"
				_ = os.Rename(capsulePath, invalidPath)
				return invalidPath
			},
			expectError: true,
			errorMsg:    "file must have .dp1c extension",
		},
		{
			name: "Non-existent file",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/path/test.dp1c"
			},
			expectError: true,
			errorMsg:    "cannot access capsule file",
		},
		{
			name: "Missing assets directory",
			setupFile: func(t *testing.T) string {
				// Create a capsule without assets directory
				tempDir, err := os.MkdirTemp("", "test-no-assets-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Write only playlist.json (no assets directory)
				playlistJSON, err := json.MarshalIndent(validPlaylist, "", "  ")
				if err != nil {
					t.Fatalf("Failed to marshal playlist: %v", err)
				}
				if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
					t.Fatalf("Failed to write playlist.json: %v", err)
				}

				// Create .dp1c archive without assets
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "assets/ directory not found in capsule root - it is required",
		},
		{
			name: "Corrupted archive - invalid zstd data",
			setupFile: func(t *testing.T) string {
				// Create a file with invalid zstd data
				tempDir, err := os.MkdirTemp("", "test-corrupted-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := os.WriteFile(capsulePath, []byte("invalid zstd data"), 0600); err != nil {
					t.Fatalf("Failed to write corrupted file: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "failed to read tar header",
		},
		{
			name: "Corrupted archive - invalid tar data",
			setupFile: func(t *testing.T) string {
				// Create a file with valid zstd but invalid tar data
				tempDir, err := os.MkdirTemp("", "test-corrupted-tar-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				capsulePath := filepath.Join(tempDir, "test.dp1c")
				file, err := os.Create(capsulePath)
				if err != nil {
					t.Fatalf("Failed to create file: %v", err)
				}
				defer file.Close()

				encoder, err := zstd.NewWriter(file)
				if err != nil {
					t.Fatalf("Failed to create zstd encoder: %v", err)
				}
				defer encoder.Close()

				// Write invalid tar data
				_, err = encoder.Write([]byte("invalid tar data"))
				if err != nil {
					t.Fatalf("Failed to write invalid tar data: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "failed to read tar header",
		},
		{
			name: "Missing playlist.json",
			setupFile: func(t *testing.T) string {
				// Create a capsule without playlist.json
				tempDir, err := os.MkdirTemp("", "test-no-playlist-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Create assets directory only
				assetsDir := filepath.Join(capsuleDir, "assets")
				if err := os.MkdirAll(assetsDir, 0750); err != nil {
					t.Fatalf("Failed to create assets dir: %v", err)
				}

				// Create .dp1c archive without playlist.json
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "playlist.json not found in capsule root",
		},
		{
			name: "Invalid playlist.json - malformed JSON",
			setupFile: func(t *testing.T) string {
				// Create a capsule with malformed JSON
				tempDir, err := os.MkdirTemp("", "test-malformed-json-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Write malformed JSON
				malformedJSON := `{"dpVersion": "1.0.0", "id": "invalid-uuid", "items": [}`
				if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), []byte(malformedJSON), 0600); err != nil {
					t.Fatalf("Failed to write malformed playlist.json: %v", err)
				}

				// Create assets directory
				assetsDir := filepath.Join(capsuleDir, "assets")
				if err := os.MkdirAll(assetsDir, 0750); err != nil {
					t.Fatalf("Failed to create assets dir: %v", err)
				}

				// Create .dp1c archive
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "failed to parse playlist.json",
		},
		{
			name: "Invalid playlist structure",
			setupFile: func(t *testing.T) string {
				// Create a capsule with invalid playlist structure
				invalidPlaylist := map[string]any{
					"dpVersion": "1.0.0",
					// Missing required fields like id, slug, etc.
					"title": "Test Playlist",
				}

				return createTestCapsule(t, invalidPlaylist, assets)
			},
			expectError: true,
			errorMsg:    "invalid playlist structure",
		},
		{
			name: "Path traversal attack - absolute path",
			setupFile: func(t *testing.T) string {
				return createMaliciousCapsule(t, "/etc/passwd", "malicious content")
			},
			expectError: true,
			errorMsg:    "absolute paths not allowed",
		},
		{
			name: "Path traversal attack - directory traversal",
			setupFile: func(t *testing.T) string {
				return createMaliciousCapsule(t, "../../../etc/passwd", "malicious content")
			},
			expectError: true,
			errorMsg:    "path contains directory traversal",
		},
		{
			name: "Path traversal attack - leading separator",
			setupFile: func(t *testing.T) string {
				return createMaliciousCapsule(t, "/malicious.txt", "malicious content")
			},
			expectError: true,
			errorMsg:    "absolute paths not allowed",
		},
		{
			name: "Empty archive entry name",
			setupFile: func(t *testing.T) string {
				return createMaliciousCapsule(t, "", "malicious content")
			},
			expectError: true,
			errorMsg:    "empty entry name",
		},
		{
			name: "Total extraction size limit exceeded",
			setupFile: func(t *testing.T) string {
				// Create a capsule with a file that has a large size in the header
				tempDir, err := os.MkdirTemp("", "test-total-size-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Write playlist.json
				playlistJSON, err := json.MarshalIndent(validPlaylist, "", "  ")
				if err != nil {
					t.Fatalf("Failed to marshal playlist: %v", err)
				}
				if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
					t.Fatalf("Failed to write playlist.json: %v", err)
				}

				// Create assets directory
				assetsDir := filepath.Join(capsuleDir, "assets")
				if err := os.MkdirAll(assetsDir, 0750); err != nil {
					t.Fatalf("Failed to create assets dir: %v", err)
				}

				// Create a small file
				smallFilePath := filepath.Join(assetsDir, "small.txt")
				if err := os.WriteFile(smallFilePath, []byte("small content"), 0600); err != nil {
					t.Fatalf("Failed to write small file: %v", err)
				}

				// Create .dp1c archive with modified tar header
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createLargeFileArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "exceeds maximum size limit",
		},
		{
			name: "Assets directory is a file instead of directory",
			setupFile: func(t *testing.T) string {
				// Create a capsule where assets is a file instead of directory
				tempDir, err := os.MkdirTemp("", "test-assets-file-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Write playlist.json
				playlistJSON, err := json.MarshalIndent(validPlaylist, "", "  ")
				if err != nil {
					t.Fatalf("Failed to marshal playlist: %v", err)
				}
				if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
					t.Fatalf("Failed to write playlist.json: %v", err)
				}

				// Create assets as a file instead of directory
				assetsPath := filepath.Join(capsuleDir, "assets")
				if err := os.WriteFile(assetsPath, []byte("not a directory"), 0600); err != nil {
					t.Fatalf("Failed to write assets file: %v", err)
				}

				// Create .dp1c archive
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "assets/ exists but is not a directory",
		},
		{
			name: "Suspicious compression ratio",
			setupFile: func(t *testing.T) string {
				// Create a capsule with a file that has a large size in the header
				tempDir, err := os.MkdirTemp("", "test-compression-ratio-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Write playlist.json
				playlistJSON, err := json.MarshalIndent(validPlaylist, "", "  ")
				if err != nil {
					t.Fatalf("Failed to marshal playlist: %v", err)
				}
				if err := os.WriteFile(filepath.Join(capsuleDir, "playlist.json"), playlistJSON, 0600); err != nil {
					t.Fatalf("Failed to write playlist.json: %v", err)
				}

				// Create assets directory
				assetsDir := filepath.Join(capsuleDir, "assets")
				if err := os.MkdirAll(assetsDir, 0750); err != nil {
					t.Fatalf("Failed to create assets dir: %v", err)
				}

				// Create a small file
				smallFilePath := filepath.Join(assetsDir, "small.txt")
				if err := os.WriteFile(smallFilePath, []byte("small content"), 0600); err != nil {
					t.Fatalf("Failed to write small file: %v", err)
				}

				// Create .dp1c archive with modified tar header
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createLargeFileArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "exceeds maximum size limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capsulePath := tt.setupFile(t)

			info, err := ExtractCapsule(capsulePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if info == nil {
				t.Error("Expected CapsuleInfo but got nil")
				return
			}

			// Verify extraction
			if info.ExtractPath == "" {
				t.Error("ExtractPath should not be empty")
			}

			if info.PlaylistPath == "" {
				t.Error("PlaylistPath should not be empty")
			}

			if info.Playlist == nil {
				t.Error("Playlist should not be nil")
			}

			// Verify playlist content
			if info.Playlist.DPVersion != "1.0.0" {
				t.Errorf("Expected dpVersion 1.0.0, got %v", info.Playlist.DPVersion)
			}

			// Cleanup
			_ = CleanupCapsule(info)
		})
	}
}

func TestCleanupCapsule(t *testing.T) {
	// Test cleanup with valid info
	tempDir, err := os.MkdirTemp("", "test-cleanup-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	info := &CapsuleInfo{
		ExtractPath: tempDir,
	}

	// Verify directory exists
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("Temp dir should exist: %v", err)
	}

	// Cleanup
	err = CleanupCapsule(info)
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Verify directory is removed
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Error("Temp dir should be removed after cleanup")
	}

	// Test cleanup with nil info
	err = CleanupCapsule(nil)
	if err != nil {
		t.Errorf("Cleanup with nil info should not error: %v", err)
	}

	// Test cleanup with empty extract path
	info = &CapsuleInfo{
		ExtractPath: "",
	}
	err = CleanupCapsule(info)
	if err != nil {
		t.Errorf("Cleanup with empty extract path should not error: %v", err)
	}

	// Test cleanup with non-existent directory
	info = &CapsuleInfo{
		ExtractPath: "/nonexistent/directory",
	}
	err = CleanupCapsule(info)
	if err != nil {
		t.Errorf("Cleanup with non-existent directory should not error: %v", err)
	}
}

func TestExtractCapsuleEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setupFile   func(t *testing.T) string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Empty file",
			setupFile: func(t *testing.T) string {
				// Create an empty .dp1c file
				tempDir, err := os.MkdirTemp("", "test-empty-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := os.WriteFile(capsulePath, []byte{}, 0600); err != nil {
					t.Fatalf("Failed to write empty file: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "playlist.json not found in capsule root",
		},
		{
			name: "Directory instead of file",
			setupFile: func(t *testing.T) string {
				// Create a directory with .dp1c name
				tempDir, err := os.MkdirTemp("", "test-dir-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := os.MkdirAll(capsulePath, 0750); err != nil {
					t.Fatalf("Failed to create directory: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "archive path must be a regular file",
		},
		{
			name: "Symbolic link to valid file",
			setupFile: func(t *testing.T) string {
				// Create a symbolic link to a valid file
				tempDir, err := os.MkdirTemp("", "test-symlink-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create a valid capsule first
				validPlaylist := map[string]any{
					"dpVersion": "1.0.0",
					"id":        "385f79b6-a45f-4c1c-8080-e93a192adccc",
					"slug":      "test-playlist",
					"created":   "2025-01-01T00:00:00Z",
					"title":     "Test Playlist",
					"items": []any{
						map[string]any{
							"id":       "285f79b6-a45f-4c1c-8080-e93a192adccc",
							"source":   "https://example.com/test.html",
							"duration": 300,
							"license":  "open",
							"repro": map[string]any{
								"assetsSHA256": []any{
									"0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
								},
							},
						},
					},
				}
				assets := map[string]string{
					"test.txt": "Hello World",
				}
				validCapsulePath := createTestCapsule(t, validPlaylist, assets)

				// Create symbolic link
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := os.Symlink(validCapsulePath, capsulePath); err != nil {
					t.Fatalf("Failed to create symlink: %v", err)
				}

				return capsulePath
			},
			expectError: false, // Symlinks to valid files should work
		},
		{
			name: "Archive with only directories (no files)",
			setupFile: func(t *testing.T) string {
				// Create a capsule with only directories
				tempDir, err := os.MkdirTemp("", "test-dirs-only-*")
				if err != nil {
					t.Fatalf("Failed to create temp dir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(tempDir) })

				// Create capsule content directory
				capsuleDir := filepath.Join(tempDir, "capsule")
				if err := os.MkdirAll(capsuleDir, 0750); err != nil {
					t.Fatalf("Failed to create capsule dir: %v", err)
				}

				// Create assets directory only (no files)
				assetsDir := filepath.Join(capsuleDir, "assets")
				if err := os.MkdirAll(assetsDir, 0750); err != nil {
					t.Fatalf("Failed to create assets dir: %v", err)
				}

				// Create .dp1c archive
				capsulePath := filepath.Join(tempDir, "test.dp1c")
				if err := createTarZstdArchive(capsuleDir, capsulePath); err != nil {
					t.Fatalf("Failed to create .dp1c archive: %v", err)
				}

				return capsulePath
			},
			expectError: true,
			errorMsg:    "playlist.json not found in capsule root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capsulePath := tt.setupFile(t)

			info, err := ExtractCapsule(capsulePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if info == nil {
				t.Error("Expected CapsuleInfo but got nil")
				return
			}

			// Cleanup
			_ = CleanupCapsule(info)
		})
	}
}
