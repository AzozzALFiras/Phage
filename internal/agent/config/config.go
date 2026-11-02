// Package config holds Phage's runtime configuration and its defaults. Config
// is loaded once at startup (see internal/agent/app) and treated as immutable
// thereafter. It can come from a YAML file (see configs/phage.example.yaml),
// from defaults, or a mix — the daemon overlays explicit command-line flags on
// top so an operator can tune one knob without editing a file.
package config

import (
	"bytes"
	"fmt"
	"os"

	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"gopkg.in/yaml.v3"
)

// Thresholds map an anomaly score (0.0 normal .. 1.0 certainly anomalous) to a
// response intent. Tuning aggressiveness lives here, as data, not in code.
type Thresholds struct {
	Notify  float64 // at/above this score, raise an alert
	Contain float64 // at/above this score, contain (enforce mode only)
}

// Config is the full daemon configuration.
type Config struct {
	Mode        mode.Mode
	StatePath   string // where the learned baseline is persisted
	AuditPath   string // append-only action trail; empty disables auditing
	ControlPath string // Unix socket for the phage CLI; empty disables it
	LogLevel    string
	LearnWindow string // minimum learning duration before Alert/Enforce is advised
	Thresholds  Thresholds
	Protect     bool // arm eBPF-LSM tamper-resistance (deny signals to the agent); opt-in, needs BPF LSM
}

// Default returns a safe starting configuration: learn-only, local state, a
// week of learning before the baseline should be trusted, and conservative
// response thresholds.
func Default() Config {
	return Config{
		Mode:        mode.Learn,
		StatePath:   "/var/lib/phage/baseline.json",
		AuditPath:   "",
		ControlPath: "/run/phage.sock",
		LogLevel:    "info",
		LearnWindow: "168h",
		Thresholds:  Thresholds{Notify: 0.4, Contain: 0.8},
	}
}

// fileConfig mirrors the YAML on disk. Every field is a pointer so Load can tell
// "absent, keep the default" from "present and set to the zero value" — which
// matters for a threshold an operator deliberately sets to 0.
type fileConfig struct {
	Mode        *string `yaml:"mode"`
	StatePath   *string `yaml:"state_path"`
	AuditPath   *string `yaml:"audit_path"`
	ControlPath *string `yaml:"control_path"`
	LogLevel    *string `yaml:"log_level"`
	LearnWindow *string `yaml:"learn_window"`
	Thresholds  *struct {
		Notify  *float64 `yaml:"notify"`
		Contain *float64 `yaml:"contain"`
	} `yaml:"thresholds"`
}

// Load reads a YAML config file, overlays it on Default(), and validates the
// result. Fields absent from the file keep their default. A malformed file or
// an invalid combination (see Validate) is an error, never a silent fallback —
// a security daemon must not start with a config the operator did not mean.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var fc fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown keys: a typo'd threshold must fail loudly
	if err := dec.Decode(&fc); err != nil {
		return Config{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg := Default()
	if fc.Mode != nil {
		m, err := mode.Parse(*fc.Mode)
		if err != nil {
			return Config{}, fmt.Errorf("config %q: %w", path, err)
		}
		cfg.Mode = m
	}
	setString(&cfg.StatePath, fc.StatePath)
	setString(&cfg.AuditPath, fc.AuditPath)
	setString(&cfg.ControlPath, fc.ControlPath)
	setString(&cfg.LogLevel, fc.LogLevel)
	setString(&cfg.LearnWindow, fc.LearnWindow)
	if fc.Thresholds != nil {
		if fc.Thresholds.Notify != nil {
			cfg.Thresholds.Notify = *fc.Thresholds.Notify
		}
		if fc.Thresholds.Contain != nil {
			cfg.Thresholds.Contain = *fc.Thresholds.Contain
		}
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects a configuration that cannot behave sanely. It is the one
// gate every config passes through, whether it came from a file or flags.
func (c Config) Validate() error {
	n, co := c.Thresholds.Notify, c.Thresholds.Contain
	if n < 0 || n > 1 {
		return fmt.Errorf("notify threshold %.2f out of range [0,1]", n)
	}
	if co < 0 || co > 1 {
		return fmt.Errorf("contain threshold %.2f out of range [0,1]", co)
	}
	if n > co {
		return fmt.Errorf("notify threshold %.2f must not exceed contain threshold %.2f", n, co)
	}
	return nil
}

func setString(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}
