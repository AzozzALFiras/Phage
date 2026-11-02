package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/policy/mode"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "phage.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadOverlaysDefaults(t *testing.T) {
	// Only some fields are set; the rest must keep their defaults.
	p := writeTemp(t, `
mode: enforce
thresholds:
  notify: 0.5
  contain: 0.9
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != mode.Enforce {
		t.Errorf("Mode = %v, want enforce", cfg.Mode)
	}
	if cfg.Thresholds.Notify != 0.5 || cfg.Thresholds.Contain != 0.9 {
		t.Errorf("thresholds = %+v, want {0.5 0.9}", cfg.Thresholds)
	}
	// Untouched field keeps the default.
	if cfg.ControlPath != Default().ControlPath {
		t.Errorf("ControlPath = %q, want default %q", cfg.ControlPath, Default().ControlPath)
	}
}

func TestLoadRejectsInvertedThresholds(t *testing.T) {
	// notify above contain is nonsensical: a score could demand containment
	// without ever crossing the alert line. Must fail loudly, not silently run.
	p := writeTemp(t, "thresholds:\n  notify: 0.9\n  contain: 0.4\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when notify > contain")
	}
}

func TestLoadRejectsOutOfRange(t *testing.T) {
	p := writeTemp(t, "thresholds:\n  contain: 1.7\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when a threshold is out of [0,1]")
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	// A typo like "treshold" must not be silently ignored on a security daemon.
	p := writeTemp(t, "treshold: 0.5\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error on an unknown config key")
	}
}

func TestLoadRejectsBadMode(t *testing.T) {
	p := writeTemp(t, "mode: paranoid\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected error on an unknown mode")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for a missing file")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	// The committed example must always be a valid, loadable config.
	if _, err := Load("../../../configs/phage.example.yaml"); err != nil {
		t.Fatalf("configs/phage.example.yaml does not load: %v", err)
	}
}

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must validate: %v", err)
	}
}
