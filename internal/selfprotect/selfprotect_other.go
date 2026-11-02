//go:build !linux

package selfprotect

import "errors"

// Available is always false off Linux.
func Available() bool { return false }

// Guard is a non-functional placeholder off Linux.
type Guard struct{}

// Arm always fails off Linux.
func Arm(objPath string, pid, ppid uint32) (*Guard, error) {
	return nil, errors.New("self-protection requires Linux (eBPF-LSM)")
}

// Close is a no-op off Linux.
func (g *Guard) Close() error { return nil }
