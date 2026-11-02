//go:build linux

// Package sensor is the userspace side of the auto-jail syscall profiler: it
// loads the jail eBPF object, points it at one service's cgroup, and reads back
// the set of syscalls that service made. It is separate from the detection
// sensor loader (internal/sensor/loader) because the two have different
// lifecycles — detection runs forever, profiling runs for a bounded window.
package sensor

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	progName      = "on_sys_enter"
	targetMapName = "target_cgid"
	seenMapName   = "syscalls_seen"
	nrSyscalls    = 1024 // must match NR_SYSCALLS in bpf/programs/jail.bpf.c
)

// Profiler is a loaded, attached syscall profiler bound to one cgroup.
type Profiler struct {
	coll *ebpf.Collection
	link link.Link
}

// Open loads the jail object at objPath, sets the target cgroup id, and attaches
// the sys_enter program. Counting starts immediately; call Snapshot when the
// window is over and Close to detach.
func Open(objPath string, cgroupID uint64) (*Profiler, error) {
	if cgroupID == 0 {
		return nil, fmt.Errorf("refusing to profile cgroup id 0 (would match nothing)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec %q: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}
	p := &Profiler{coll: coll}

	// Point the profiler at the target cgroup before attaching, so no stray
	// syscalls are counted against the wrong service.
	target := coll.Maps[targetMapName]
	if target == nil {
		p.Close()
		return nil, fmt.Errorf("map %q not found in object", targetMapName)
	}
	if err := target.Update(uint32(0), cgroupID, ebpf.UpdateAny); err != nil {
		p.Close()
		return nil, fmt.Errorf("set target cgroup: %w", err)
	}

	prog := coll.Programs[progName]
	if prog == nil {
		p.Close()
		return nil, fmt.Errorf("program %q not found in object", progName)
	}
	lnk, err := link.AttachTracing(link.TracingOptions{Program: prog})
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("attach %q: %w", progName, err)
	}
	p.link = lnk
	return p, nil
}

// SetTarget re-points the profiler at a different cgroup id. It is used by
// -follow: a systemd unit gets a new cgroup id each restart, so following it
// across a restart (to capture startup syscalls) means updating the target the
// moment the id changes.
func (p *Profiler) SetTarget(cgroupID uint64) error {
	if cgroupID == 0 {
		return fmt.Errorf("refusing to set target cgroup id 0")
	}
	target := p.coll.Maps[targetMapName]
	if target == nil {
		return fmt.Errorf("map %q not found", targetMapName)
	}
	return target.Update(uint32(0), cgroupID, ebpf.UpdateAny)
}

// Snapshot reads the current per-syscall counts, returning only the syscalls
// seen at least once (number -> count).
func (p *Profiler) Snapshot() (map[int]uint64, error) {
	seen := p.coll.Maps[seenMapName]
	if seen == nil {
		return nil, fmt.Errorf("map %q not found", seenMapName)
	}
	out := make(map[int]uint64)
	for nr := uint32(0); nr < nrSyscalls; nr++ {
		var count uint64
		if err := seen.Lookup(nr, &count); err != nil {
			continue // unset slots read as not-found on some kernels
		}
		if count > 0 {
			out[int(nr)] = count
		}
	}
	return out, nil
}

// Close detaches the program and releases kernel resources. Safe to call twice.
func (p *Profiler) Close() error {
	if p.link != nil {
		p.link.Close()
		p.link = nil
	}
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
	return nil
}
