//go:build !linux

// Off Linux there are no cgroups; these stubs keep the module building and
// unit-testable on a dev laptop.
package contain

import "errors"

// ErrUnsupported is returned by containment operations off Linux.
var ErrUnsupported = errors.New("phage: containment is only supported on Linux")

// Freezer is a no-op placeholder on non-Linux platforms.
type Freezer struct{}

// NewFreezer returns a stub Freezer.
func NewFreezer() *Freezer { return &Freezer{} }

// Freeze always fails off Linux.
func (f *Freezer) Freeze(pid int32) error { return ErrUnsupported }

// Thaw always fails off Linux.
func (f *Freezer) Thaw(pid int32) error { return ErrUnsupported }
