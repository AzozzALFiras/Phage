//go:build !linux

package sensor

import "errors"

// Profiler is a non-functional placeholder off Linux so the command and its
// tests build anywhere; eBPF profiling requires a Linux kernel.
type Profiler struct{}

// Open always fails off Linux.
func Open(objPath string, cgroupID uint64) (*Profiler, error) {
	return nil, errors.New("syscall profiling requires Linux (eBPF)")
}

// SetTarget always fails off Linux.
func (p *Profiler) SetTarget(cgroupID uint64) error {
	return errors.New("syscall profiling requires Linux (eBPF)")
}

// Snapshot always fails off Linux.
func (p *Profiler) Snapshot() (map[int]uint64, error) {
	return nil, errors.New("syscall profiling requires Linux (eBPF)")
}

// Close is a no-op off Linux.
func (p *Profiler) Close() error { return nil }
