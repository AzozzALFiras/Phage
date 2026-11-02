//go:build !linux

package enforce

import "errors"

// BPFLSMActive is always false off Linux.
func BPFLSMActive() bool { return false }

// ExecLock is a non-functional placeholder off Linux.
type ExecLock struct{}

// LoadExecLock always fails off Linux.
func LoadExecLock(objPath string) (*ExecLock, error) {
	return nil, errors.New("eBPF-LSM enforcement requires Linux")
}

// Learn always fails off Linux.
func (e *ExecLock) Learn(cgroupID uint64) error {
	return errors.New("eBPF-LSM enforcement requires Linux")
}

// Enforce always fails off Linux.
func (e *ExecLock) Enforce(cgroupID uint64) error {
	return errors.New("eBPF-LSM enforcement requires Linux")
}

// Unlock always fails off Linux.
func (e *ExecLock) Unlock(cgroupID uint64) error {
	return errors.New("eBPF-LSM enforcement requires Linux")
}

// AllowedCount is always 0 off Linux.
func (e *ExecLock) AllowedCount(cgroupID uint64) int { return 0 }

// Close is a no-op off Linux.
func (e *ExecLock) Close() error { return nil }
