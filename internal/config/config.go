package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config persists CLI preferences under ~/.dp1/config.yaml .
type Config struct {
	Signing  SigningCfg  `yaml:"signing"`
	Feed     FeedCfg     `yaml:"feed"`
	Defaults DefaultsCfg `yaml:"defaults"`
}

type SigningCfg struct {
	PrivateKey string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	PublicKey  string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
}

type FeedCfg struct {
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
}

type DefaultsCfg struct {
	OutputFormat string `yaml:"output_format,omitempty" json:"output_format,omitempty"`
}

var cached struct {
	cfg Config
	ok  bool
	mu  sync.Mutex
}

// Dir returns ~/.dp1 (created if missing when ensure is true).
func Dir(ensure bool) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".dp1")
	if ensure {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	return dir, nil
}

// Path resolves ~/.dp1/config.yaml .
func Path() (string, error) {
	dir, err := Dir(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

func defaultConfig() Config {
	return Config{
		Feed: FeedCfg{
			URL: "https://feed.feralfile.com",
		},
		Defaults: DefaultsCfg{
			OutputFormat: "human",
		},
	}
}

// Load reads the config file, or returns defaults if missing.
func Load() (Config, error) {
	path, err := Path()
	if err != nil {
		return Config{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultConfig(), nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config yaml: %w", err)
	}
	return mergedDefaults(cfg), nil
}

func mergedDefaults(c Config) Config {
	d := defaultConfig()
	if c.Feed.URL == "" {
		c.Feed.URL = d.Feed.URL
	}
	if c.Defaults.OutputFormat == "" {
		c.Defaults.OutputFormat = d.Defaults.OutputFormat
	}
	return c
}

// Save writes cfg to ~/.dp1/config.yaml (creates parent dir).
func Save(cfg Config) error {
	dir, err := Dir(true)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "config.yaml")
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	InvalidateCache()
	return nil
}

// InvalidateCache clears any in-memory config snapshot after Save().
func InvalidateCache() {
	cached.mu.Lock()
	defer cached.mu.Unlock()
	cached.ok = false
}

// LoadCached returns the cached config after the first Load, until InvalidateCache().
func LoadCached() (Config, error) {
	cached.mu.Lock()
	defer cached.mu.Unlock()
	if cached.ok {
		return cached.cfg, nil
	}
	cfg, err := Load()
	if err != nil {
		return Config{}, err
	}
	cached.cfg = cfg
	cached.ok = true
	return cfg, nil
}
