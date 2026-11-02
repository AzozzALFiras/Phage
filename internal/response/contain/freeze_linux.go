//go:build linux

// Package contain applies the containment actions the policy engine decides on.
// The first actuator is a cgroup-v2 freeze: the offending process tree is moved
// into a dedicated cgroup and frozen. Freezing is reversible — a false positive
// is thawed, not left as a killed process — which is what makes auto-response
// safe enough to enable.
package contain

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/AzozzALFiras/Phage/internal/enrich/process"
)

const cgroupRoot = "/sys/fs/cgroup"

// Freezer quarantines process trees under a dedicated cgroup v2 subtree.
type Freezer struct {
	base string
}

// NewFreezer returns a Freezer rooted at /sys/fs/cgroup/phage.
func NewFreezer() *Freezer { return &Freezer{base: filepath.Join(cgroupRoot, "phage")} }

// Freeze moves the process tree rooted at pid into its own cgroup and freezes
// it. Processes that have already exited are skipped. The call fails only if
// cgroup v2 is unavailable or the freeze write fails.
func (f *Freezer) Freeze(pid int32) error {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 not available: %w", err)
	}
	dir := filepath.Join(f.base, fmt.Sprintf("quar-%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create quarantine cgroup: %w", err)
	}
	procs := filepath.Join(dir, "cgroup.procs")
	for _, p := range tree(pid) {
		_ = os.WriteFile(procs, []byte(strconv.Itoa(int(p))), 0) // best effort
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("1"), 0); err != nil {
		return fmt.Errorf("freeze cgroup: %w", err)
	}
	return nil
}

// Thaw unfreezes a previously frozen tree (used to release a false positive).
func (f *Freezer) Thaw(pid int32) error {
	dir := filepath.Join(f.base, fmt.Sprintf("quar-%d", pid))
	return os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("0"), 0)
}

// tree returns pid and all of its descendants, discovered via /proc.
func tree(root int32) []int32 {
	children := map[int32][]int32{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []int32{root}
	}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pid := int32(n)
		if st, err := process.ReadStat(pid); err == nil && st.PPID > 0 {
			children[st.PPID] = append(children[st.PPID], pid)
		}
	}
	var out []int32
	seen := map[int32]bool{}
	var walk func(int32)
	walk = func(p int32) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
		for _, c := range children[p] {
			walk(c)
		}
	}
	walk(root)
	return out
}
