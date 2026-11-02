package enforce

import "strings"

// bpfInLSMList reports whether "bpf" appears in the comma-separated contents of
// /sys/kernel/security/lsm (the kernel's active LSM list). Kept pure and
// build-tag-free so it is unit-tested on every platform.
func bpfInLSMList(content string) bool {
	for _, name := range strings.Split(strings.TrimSpace(content), ",") {
		if strings.TrimSpace(name) == "bpf" {
			return true
		}
	}
	return false
}
