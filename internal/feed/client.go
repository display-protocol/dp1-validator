package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/display-protocol/dp1-cli/internal/config"
)

// Well-known environment variable for the feed base URL (an optional flag overrides it).
const (
	EnvURL = "DP1_FEED_URL"
)

// Resource is a POST /api/v1/{resource} create target.
type Resource string

const (
	Playlist      Resource = "playlists"
	PlaylistGroup Resource = "playlist-groups"
	Channel       Resource = "channels"
)

// ResolveBaseURL returns the feed base URL using:
// non-empty flag → env → config (feed package does not apply URL defaults; use config.Load after merge).
func ResolveBaseURL(urlFlag string, feedCfg config.FeedCfg) (baseURL string, err error) {
	base := firstNonEmpty(
		strings.TrimSpace(urlFlag),
		strings.TrimSpace(os.Getenv(EnvURL)),
		strings.TrimSpace(feedCfg.URL),
	)
	if base == "" {
		return "", fmt.Errorf("feed URL missing: use --feed-url, %s, or config key feed.url", EnvURL)
	}
	base = strings.TrimSpace(base)
	base = strings.TrimRight(base, "/")
	return base, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Client POSTs DP-1 documents to a feed server.
type Client struct {
	HTTP *http.Client
}

// NewClient returns a client with a bounded request timeout.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 60 * time.Second},
	}
}

// Create POSTs document to /api/v1/{resource}.
func (c *Client) Create(ctx context.Context, baseURL string, res Resource, document []byte) (statusCode int, respBody []byte, err error) {
	if c == nil || c.HTTP == nil {
		c = NewClient()
	}
	u := baseURL + "/api/v1/" + string(res)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(document))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dp1-cli/1.0")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("POST %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// APIError is a feed error body or non-success HTTP status.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RawBody    string
}

func (e *APIError) Error() string {
	if e == nil {
		return "feed error"
	}
	if e.Code != "" && e.Message != "" {
		return fmt.Sprintf("feed HTTP %d: %s — %s", e.StatusCode, e.Code, e.Message)
	}
	if e.RawBody != "" {
		return fmt.Sprintf("feed HTTP %d: %s", e.StatusCode, strings.TrimSpace(e.RawBody))
	}
	return fmt.Sprintf("feed HTTP %d", e.StatusCode)
}

// ErrorFromResponse builds an APIError from a non-2xx response.
func ErrorFromResponse(statusCode int, body []byte) error {
	raw := string(body)
	var dec struct {
		Err string `json:"error"`
		Msg string `json:"message"`
	}
	if json.Unmarshal(body, &dec) == nil && (dec.Err != "" || dec.Msg != "") {
		return &APIError{StatusCode: statusCode, Code: dec.Err, Message: dec.Msg, RawBody: raw}
	}
	return &APIError{StatusCode: statusCode, RawBody: raw}
}
