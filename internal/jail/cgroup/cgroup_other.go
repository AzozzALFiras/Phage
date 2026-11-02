//go:build !linux

package cgroup

import "errors"

var errNotLinux = errors.New("cgroup resolution requires Linux")

// IDForPath always fails off Linux.
func IDForPath(cgPath string) (uint64, error) { return 0, errNotLinux }

// IDForUnit always fails off Linux.
func IDForUnit(unit string) (uint64, string, error) { return 0, "", errNotLinux }

// MountedV2 is always false off Linux.
func MountedV2() bool { return false }
