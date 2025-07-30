package playlist

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gowebpki/jcs"
)

// Global validator instance
var validate *validator.Validate

// Custom validator
var marginValidator = func(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(px|%|vw|vh)$`).MatchString(value)
}
var backgroundValidator = func(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return regexp.MustCompile(`^(#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})|transparent)$`).MatchString(value)
}

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("margin", marginValidator)
	_ = validate.RegisterValidation("background", backgroundValidator)
}

// PlaylistItem represents a single item in a DP-1 playlist
type PlaylistItem struct {
	ID         string         `json:"id" validate:"required,uuid4"`
	Title      string         `json:"title,omitempty" validate:"omitempty,max=256"`
	Source     string         `json:"source" validate:"required,url"`
	Duration   int            `json:"duration,omitempty" validate:"required,min=1"`
	License    string         `json:"license,omitempty" validate:"required,oneof=open token subscription"`
	Ref        string         `json:"ref,omitempty" validate:"omitempty,url"`
	Override   map[string]any `json:"override,omitempty"`
	Display    *Display       `json:"display,omitempty" validate:"omitempty"`
	Repro      *ReproBlock    `json:"repro,omitempty" validate:"omitempty"`
	Provenance *Provenance    `json:"provenance,omitempty" validate:"omitempty"`
}

// Mouse represents the mouse interaction
type Mouse struct {
	Click  bool `json:"click" validate:"omitempty"`
	Drag   bool `json:"drag" validate:"omitempty"`
	Scroll bool `json:"scroll" validate:"omitempty"`
	Hover  bool `json:"hover" validate:"omitempty"`
}

// Interaction represents the interaction of a playlist item
type Interaction struct {
	Keyboard []string `json:"keyboard" validate:"omitempty"`
	Mouse    *Mouse   `json:"mouse" validate:"omitempty"`
}

type Margin string

// UnmarshalJSON implements custom JSON unmarshaling for MarginValue
func (m *Margin) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*m = Margin(str)
		return nil
	}

	// If string fails, try to unmarshal as number
	var num float64
	if err := json.Unmarshal(data, &num); err != nil {
		return fmt.Errorf("margin must be a string or number: %w", err)
	}

	// Convert number to string with "px" units, rounding to nearest integer
	*m = Margin(fmt.Sprintf("%.0fpx", math.Round(num)))
	return nil
}

// String returns the string representation of the margin value
func (m Margin) String() string {
	return string(m)
}

// Display represents the display properties of a playlist item
type Display struct {
	Scaling     string       `json:"scaling" validate:"omitempty,oneof=fit fill stretch auto"`
	Margin      Margin       `json:"margin" validate:"omitempty,margin"`
	Background  string       `json:"background" validate:"omitempty,background"`
	AutoPlay    bool         `json:"autoPlay" validate:"omitempty"`
	Loop        bool         `json:"loop" validate:"omitempty"`
	Interaction *Interaction `json:"interaction,omitempty"`
}

// FrameHash represents the hash of a frame
type FrameHash struct {
	SHA256 string `json:"sha256" validate:"required,len=66,startswith=0x,hexadecimal"`
	PHash  string `json:"phash" validate:"omitempty,len=18,startswith=0x,hexadecimal"`
}

// ReproBlock represents reproduction verification data
type ReproBlock struct {
	EngineVersion map[string]string `json:"engineVersion,omitempty"`
	Seed          string            `json:"seed,omitempty" validate:"omitempty,hexadecimal"`
	AssetsSHA256  []string          `json:"assetsSHA256,omitempty" validate:"omitempty,dive,len=66,startswith=0x,hexadecimal"`
	FrameHash     *FrameHash        `json:"frameHash,omitempty"`
}

// Contract represents the contract information
type Contract struct {
	Chain    string `json:"chain" validate:"required,oneof=evm tezos bitmark other"`
	Standard string `json:"standard" validate:"omitempty,oneof=erc1155 erc721 fa2 other"`
	Address  string `json:"address" validate:"omitempty,max=48"`
	SeriesID string `json:"seriesId" validate:"omitempty,max=128"`
	TokenID  string `json:"tokenId" validate:"omitempty,max=128"`
	URI      string `json:"uri" validate:"omitempty,url"`
	MetaHash string `json:"metaHash" validate:"omitempty,len=66,startswith=0x,hexadecimal"`
}

// Dependency represents the dependency information
type Dependency struct {
	Chain    string `json:"chain" validate:"omitempty,oneof=evm tezos bitmark other"`
	Standard string `json:"standard" validate:"omitempty,oneof=erc1155 erc721 fa2 other"`
	URI      string `json:"uri" validate:"omitempty,url"`
}

// Provenance represents provenance information
type Provenance struct {
	Type         string       `json:"type" validate:"required,oneof=onChain seriesRegistry offChainURI"`
	Contract     *Contract    `json:"contract,omitempty" validate:"omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty" validate:"omitempty,max=1024,dive"`
}

// Defaults represents the default values for a playlist
type Defaults struct {
	Display  *Display `json:"display,omitempty" validate:"omitempty"`
	License  string   `json:"license,omitempty" validate:"omitempty,oneof=open token subscription"`
	Duration int      `json:"duration,omitempty" validate:"omitempty,min=1"`
}

// Playlist represents a DP-1 playlist
type Playlist struct {
	DPVersion string         `json:"dpVersion" validate:"required,semver"`
	ID        string         `json:"id" validate:"required,uuid4"`
	Slug      string         `json:"slug,omitempty" validate:"required,max=64,alphanum|contains=-|contains=_"`
	Title     string         `json:"title,omitempty" validate:"required,max=256"`
	Created   string         `json:"created" validate:"required,datetime=2006-01-02T15:04:05Z"`
	Defaults  *Defaults      `json:"defaults,omitempty" validate:"omitempty"`
	Items     []PlaylistItem `json:"items" validate:"required,min=1,max=1024,dive"`
	Signature *string        `json:"signature,omitempty" validate:"omitempty,startswith=ed25519:"`
}

// ParsePlaylist parses a playlist from either a URL or base64 encoded payload
func ParsePlaylist(input string) (*Playlist, []byte, error) {
	var rawData []byte
	var err error

	// Auto-detect if input is URL or base64
	if isURL(input) {
		rawData, err = fetchFromURL(input)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch playlist from URL: %w", err)
		}
	} else {
		// Try to decode as base64
		rawData, err = base64.StdEncoding.DecodeString(input)
		if err != nil {
			// If base64 decoding fails, treat as raw JSON
			rawData = []byte(input)
		}
	}

	var playlist Playlist
	if err := json.Unmarshal(rawData, &playlist); err != nil {
		return nil, nil, fmt.Errorf("failed to parse playlist JSON: %w", err)
	}

	return &playlist, rawData, nil
}

// isURL checks if the input string is a valid URL
func isURL(input string) bool {
	u, err := url.Parse(input)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// fetchFromURL fetches content from a URL with proper timeout and headers
func fetchFromURL(urlStr string) ([]byte, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "DP-1-Validator/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

// CanonicalizePlaylist converts a playlist to canonical JSON form
// This removes unnecessary whitespace and ensures consistent field ordering
func CanonicalizePlaylist(playlist *Playlist, signable bool) ([]byte, error) {
	if signable {
		playlist.Signature = nil
	}

	// Marshal to JSON first
	rawJson, err := json.Marshal(playlist)
	if err != nil {
		return nil, err
	}

	// Transform to canonical JSON
	canonical, err := jcs.Transform(rawJson)
	if err != nil {
		return nil, err
	}

	// Add LF terminator if not already present
	if len(canonical) > 0 && canonical[len(canonical)-1] != '\n' {
		canonical = append(canonical, '\n')
	}

	return canonical, nil
}

// ValidatePlaylistStructure validates the playlist structure using the validator library
func ValidatePlaylistStructure(playlist *Playlist) error {
	if playlist == nil {
		return fmt.Errorf("playlist cannot be nil")
	}

	// Use the validator library to validate the struct
	if err := validate.Struct(playlist); err != nil {
		// Convert validation errors to more user-friendly messages
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, fieldError := range validationErrors {
				switch fieldError.Tag() {
				case "required":
					return fmt.Errorf("missing required field: %s", strings.ToLower(fieldError.Field()))
				case "uuid4":
					return fmt.Errorf("invalid UUID format for field: %s", strings.ToLower(fieldError.Field()))
				case "semver":
					return fmt.Errorf("invalid semantic version format for dpVersion: %s", fieldError.Value())
				case "datetime":
					return fmt.Errorf("invalid created timestamp format, expected RFC3339: %s", fieldError.Value())
				case "min":
					if fieldError.Field() == "Items" {
						return fmt.Errorf("playlist must contain at least one item")
					}
					return fmt.Errorf("field %s must have minimum value/length of %s", strings.ToLower(fieldError.Field()), fieldError.Param())
				case "url":
					return fmt.Errorf("invalid URL format for field %s: %s", strings.ToLower(fieldError.Field()), fieldError.Value())
				case "oneof":
					return fmt.Errorf("invalid value for field %s, must be one of: %s", strings.ToLower(fieldError.Field()), fieldError.Param())
				case "hexadecimal":
					return fmt.Errorf("field %s must be hexadecimal: %s", strings.ToLower(fieldError.Field()), fieldError.Value())
				case "len":
					return fmt.Errorf("field %s must be exactly %s characters long", strings.ToLower(fieldError.Field()), fieldError.Param())
				case "startswith":
					return fmt.Errorf("field %s must start with: %s", strings.ToLower(fieldError.Field()), fieldError.Param())
				case "dive":
					// Handle array/slice validation errors
					return fmt.Errorf("validation error in %s array", strings.ToLower(fieldError.Field()))
				default:
					return fmt.Errorf("validation error for field %s: %s", strings.ToLower(fieldError.Field()), fieldError.Tag())
				}
			}
		}
		return fmt.Errorf("validation failed: %w", err)
	}

	return nil
}

// HasSignature checks if the playlist contains a signature
func HasSignature(playlist *Playlist) bool {
	return playlist.Signature != nil && *playlist.Signature != ""
}

// ExtractAssetHashes extracts SHA256 hashes from the repro block of all playlist items
func ExtractAssetHashes(playlist *Playlist) []string {
	var allHashes []string

	for _, item := range playlist.Items {
		if item.Repro != nil && len(item.Repro.AssetsSHA256) > 0 {
			allHashes = append(allHashes, item.Repro.AssetsSHA256...)
		}
	}

	return allHashes
}
