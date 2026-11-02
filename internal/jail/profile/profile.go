// Package profile is the learned syscall profile of a single service: the set of
// syscalls it was observed making during a representative window. It is the
// "learn" half of auto-jail — the input from which a least-privilege seccomp
// policy is generated (internal/jail/seccomp). It is pure data, decoupled from
// how the observations were gathered (eBPF) so it stays testable and portable.
package profile

import (
	"sort"
	"time"
)

// Profile is an immutable-after-build record of what one service did.
type Profile struct {
	Unit      string         `json:"unit"`       // systemd unit (or label) profiled
	CgroupID  uint64         `json:"cgroup_id"`  // cgroup v2 id the syscalls were attributed to
	LearnedAt time.Time      `json:"learned_at"` // when the window started
	Duration  time.Duration  `json:"duration"`   // how long observation ran
	Counts    map[int]uint64 `json:"counts"`     // syscall number -> times observed
}

// New builds a Profile from a raw (syscall number -> count) map, as dumped from
// the kernel profiler. The map is copied so later mutation cannot alias it.
func New(unit string, cgroupID uint64, counts map[int]uint64, d time.Duration) *Profile {
	c := make(map[int]uint64, len(counts))
	for nr, n := range counts {
		c[nr] = n
	}
	return &Profile{
		Unit:      unit,
		CgroupID:  cgroupID,
		LearnedAt: time.Now().UTC(),
		Duration:  d,
		Counts:    c,
	}
}

// Syscalls returns the observed syscall numbers, ascending and de-duplicated.
func (p *Profile) Syscalls() []int {
	out := make([]int, 0, len(p.Counts))
	for nr := range p.Counts {
		out = append(out, nr)
	}
	sort.Ints(out)
	return out
}

// TotalEvents is the number of syscall invocations observed. A tiny total means
// the window was too short to trust the profile — callers should surface it.
func (p *Profile) TotalEvents() uint64 {
	var t uint64
	for _, n := range p.Counts {
		t += n
	}
	return t
}
