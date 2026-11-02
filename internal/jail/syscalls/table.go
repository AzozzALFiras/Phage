// Package syscalls maps between Linux syscall numbers and names for the target
// architecture. The number->name data is generated from the kernel's own UAPI
// header (see tabledata.go and scripts/gen/syscalls.sh); this file is the
// hand-written lookup API over it. Keeping the raw table generated means a
// profile always names exactly what the kernel reported, never a stale guess.
package syscalls

import "fmt"

// Name returns the canonical syscall name for a number, or a synthetic
// "syscall_<nr>" placeholder if the number is unknown to the embedded table. The
// placeholder is never valid in a seccomp filter, so callers can detect and
// surface an incomplete table rather than emit a silently-wrong profile.
func Name(nr int) string {
	if name, ok := amd64ByNr[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// Known reports whether a number is present in the embedded table.
func Known(nr int) bool {
	_, ok := amd64ByNr[nr]
	return ok
}

// Count is the number of syscalls in the embedded table.
func Count() int { return len(amd64ByNr) }
