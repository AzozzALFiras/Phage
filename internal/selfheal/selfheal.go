// Package selfheal restores a sentinel file to its last known-good content after
// a malicious write, keeping the attacker's version as evidence. It snapshots a
// small set of high-value persistence/credential files at startup; on a
// malicious-write verdict (enforce only) it atomically rewrites the good content
// and quarantines what the attacker wrote. It only heals files it snapshotted and
// only on a verdict the engine judged malicious, so a legitimate edit — which
// scores low — is never reverted.
package selfheal

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store holds the known-good snapshots and a quarantine directory for evidence.
type Store struct {
	mu         sync.Mutex
	good       map[string]snapshot
	quarantine string
}

type snapshot struct {
	content []byte
	mode    os.FileMode
}

// New returns a Store that quarantines attacker versions under quarantineDir.
func New(quarantineDir string) *Store {
	_ = os.MkdirAll(quarantineDir, 0o700)
	return &Store{good: map[string]snapshot{}, quarantine: quarantineDir}
}

// DefaultSentinels resolves the built-in high-value set that exists on this host:
// SSH authorized_keys (root and each home), cron, and the dynamic-loader preload.
func DefaultSentinels() []string {
	var out []string
	add := func(p string) {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	add("/root/.ssh/authorized_keys")
	add("/root/.ssh/authorized_keys2")
	homes, _ := filepath.Glob("/home/*/.ssh/authorized_keys")
	out = append(out, homes...)
	add("/etc/crontab")
	crond, _ := filepath.Glob("/etc/cron.d/*")
	out = append(out, crond...)
	add("/etc/ld.so.preload")
	return out
}

// Snapshot records the current content of a file as known-good.
func (s *Store) Snapshot(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	s.mu.Lock()
	s.good[path] = snapshot{content: data, mode: mode}
	s.mu.Unlock()
	return nil
}

// SnapshotAll snapshots every path and returns how many were captured.
func (s *Store) SnapshotAll(paths []string) int {
	n := 0
	for _, p := range paths {
		if s.Snapshot(p) == nil {
			n++
		}
	}
	return n
}

// Watched reports whether a path has a known-good snapshot.
func (s *Store) Watched(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.good[path]
	return ok
}

// Heal saves the current (tampered) file to quarantine and atomically restores
// the known-good content. Returns the quarantine path, or "" if the content
// already matches the snapshot (nothing to do). Only snapshotted files heal.
func (s *Store) Heal(path string) (string, error) {
	s.mu.Lock()
	snap, ok := s.good[path]
	s.mu.Unlock()
	if !ok {
		return "", nil
	}

	cur, _ := os.ReadFile(path)
	if string(cur) == string(snap.content) {
		return "", nil // unchanged from known-good; the write was benign/identical
	}

	qpath := filepath.Join(s.quarantine, fmt.Sprintf("%d-%s", time.Now().Unix(), sanitize(path)))
	if len(cur) > 0 {
		_ = os.WriteFile(qpath, cur, 0o600)
	}

	tmp := path + ".phage-heal"
	if err := os.WriteFile(tmp, snap.content, snap.mode); err != nil {
		return "", fmt.Errorf("write restored content: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("atomic restore: %w", err)
	}
	return qpath, nil
}

func sanitize(p string) string {
	out := []rune(p)
	for i, r := range out {
		if r == '/' {
			out[i] = '_'
		}
	}
	return string(out)
}
