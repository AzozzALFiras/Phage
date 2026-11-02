//go:build !linux

package netquarantine

import "errors"

// Manager is a non-functional placeholder off Linux.
type Manager struct{}

// New always fails off Linux.
func New(objPath string) (*Manager, error) {
	return nil, errors.New("network quarantine requires Linux (cgroup eBPF)")
}

// Isolate always fails off Linux.
func (m *Manager) Isolate(pid int32) error { return errors.New("requires Linux") }

// Release is a no-op off Linux.
func (m *Manager) Release(pid int32) error { return nil }

// Close is a no-op off Linux.
func (m *Manager) Close() error { return nil }
