// Package config holds Phage's runtime configuration and its defaults. Config
// is loaded once at startup (see internal/agent/app) and treated as immutable
// thereafter.
package config

import "github.com/AzozzALFiras/Phage/internal/policy/mode"

// Config is the full daemon configuration.
type Config struct {
	Mode        mode.Mode
	StatePath   string // where the learned baseline is persisted
	LogLevel    string
	LearnWindow string // minimum learning duration before Alert/Enforce is advised
}

// Default returns a safe starting configuration: learn-only, local state, a
// week of learning before the baseline should be trusted.
func Default() Config {
	return Config{
		Mode:        mode.Learn,
		StatePath:   "/var/lib/phage/baseline.json",
		LogLevel:    "info",
		LearnWindow: "168h",
	}
}
