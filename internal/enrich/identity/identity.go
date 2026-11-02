// Package identity resolves the authenticated origin of a process via its audit
// login uid. A set loginuid means the process traces back to an interactive
// login (console or SSH). An unset one — no login session behind it — is the
// hallmark of a process spawned by a network-facing service, which is exactly
// the provenance Phage weighs when a process reaches root.
package identity

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// loginUIDUnset is the kernel's "no login session" sentinel, (uid_t)-1.
const loginUIDUnset = 0xFFFFFFFF

// LoginUID reads /proc/<pid>/loginuid. ok is false when the process has no
// login session behind it (or /proc is unavailable).
func LoginUID(pid int32) (uid int32, ok bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return -1, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || v == loginUIDUnset {
		return -1, false
	}
	return int32(v), true
}
