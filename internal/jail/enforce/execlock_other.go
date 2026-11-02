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

// Lock always fails off Linux.
func (e *ExecLock) Lock(cgroupID uint64) error {
	return errors.New("eBPF-LSM enforcement requires Linux")
}

// Unlock always fails off Linux.
func (e *ExecLock) Unlock(cgroupID uint64) error {
	return errors.New("eBPF-LSM enforcement requires Linux")
}

// Close is a no-op off Linux.
func (e *ExecLock) Close() error { return nil }
