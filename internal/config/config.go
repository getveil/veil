package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// ProjectConfig holds the parsed contents of .veil/config.yaml.
type ProjectConfig struct {
	Scoping   map[string][]string `yaml:"scoping"`
	Ignore    []string            `yaml:"ignore"`
	SkipHosts []string            `yaml:"skip_hosts"`
}

// validTopLevelKeys is the set of allowed top-level keys in config.yaml.
var validTopLevelKeys = map[string]bool{
	"scoping":    true,
	"ignore":     true,
	"skip_hosts": true,
}

// ConfigFile returns the path to the project config file.
func ConfigFile(root string) string {
	return filepath.Join(ProjectStateDir(root), "config.yaml")
}

// Load reads and validates .veil/config.yaml at the given path.
// If the file does not exist, it returns a zero-value ProjectConfig (not an error).
// An empty file or comments-only file is valid.
func Load(path string) (*ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &ProjectConfig{}, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	// Empty or whitespace-only file.
	if len(strings.TrimSpace(string(data))) == 0 {
		return &ProjectConfig{}, nil
	}

	// First pass: check for unknown keys using a raw map.
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	// raw can be nil for comments-only YAML.
	if raw == nil {
		return &ProjectConfig{}, nil
	}
	for key := range raw {
		if !validTopLevelKeys[key] {
			return nil, fmt.Errorf("config: unknown key %q in %s (valid keys: scoping, ignore, skip_hosts)", key, path)
		}
	}

	// Second pass: unmarshal into typed struct.
	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	// Validate ignore patterns.
	for _, pattern := range cfg.Ignore {
		if filepath.IsAbs(pattern) {
			return nil, fmt.Errorf("config: ignore pattern %q is absolute (must be relative to project root)", pattern)
		}
		if !doublestar.ValidatePattern(pattern) {
			return nil, fmt.Errorf("config: ignore pattern %q has invalid glob syntax", pattern)
		}
	}

	// Normalise nil maps/slices to empty.
	if cfg.Scoping == nil {
		cfg.Scoping = map[string][]string{}
	}
	if cfg.Ignore == nil {
		cfg.Ignore = []string{}
	}
	if cfg.SkipHosts == nil {
		cfg.SkipHosts = []string{}
	}

	return &cfg, nil
}
