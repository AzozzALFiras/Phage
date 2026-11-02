//go:build linux

// Package enforce is the eBPF-LSM side of auto-jail: it loads the LSM object and
// manages which cgroups are under exec-lock. It is separate from the syscall
// profiler (internal/jail/sensor) because enforcement and profiling have
// different lifecycles and different kernel requirements (LSM needs bpf in the
// active LSM list; profiling does not).
package enforce

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	execGuardProg  = "exec_guard"
	execLockedMap  = "exec_locked"
	activeLSMsFile = "/sys/kernel/security/lsm"
)

// BPFLSMActive reports whether the kernel was booted with the BPF LSM enabled,
// which eBPF-LSM enforcement requires. Without it, attaching an lsm program
// fails, so callers can give a clear message instead of an opaque error.
func BPFLSMActive() bool {
	b, err := os.ReadFile(activeLSMsFile)
	if err != nil {
		return false
	}
	return bpfInLSMList(string(b))
}

// ExecLock is a loaded, attached LSM program plus the map of locked cgroups.
type ExecLock struct {
	coll   *ebpf.Collection
	link   link.Link
	locked *ebpf.Map
}

// LoadExecLock loads the LSM object at objPath and attaches the exec guard. On
// its own this changes nothing: no cgroup is locked until Lock is called.
func LoadExecLock(objPath string) (*ExecLock, error) {
	if !BPFLSMActive() {
		return nil, errors.New("BPF LSM is not active (need 'bpf' in /sys/kernel/security/lsm; boot with lsm=...,bpf)")
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
	e := &ExecLock{coll: coll}

	e.locked = coll.Maps[execLockedMap]
	if e.locked == nil {
		e.Close()
		return nil, fmt.Errorf("map %q not found", execLockedMap)
	}
	prog := coll.Programs[execGuardProg]
	if prog == nil {
		e.Close()
		return nil, fmt.Errorf("program %q not found", execGuardProg)
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("attach LSM %q: %w", execGuardProg, err)
	}
	e.link = lnk
	return e, nil
}

// Lock puts a cgroup under exec-lock: from now, no process in it may execve a
// new program. Call it after the service has finished starting.
func (e *ExecLock) Lock(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("refusing to lock cgroup id 0")
	}
	return e.locked.Update(cgroupID, uint8(1), ebpf.UpdateAny)
}

// Unlock lifts the exec-lock on a cgroup.
func (e *ExecLock) Unlock(cgroupID uint64) error {
	return e.locked.Delete(cgroupID)
}

// Close detaches the LSM program (lifting all enforcement) and frees resources.
func (e *ExecLock) Close() error {
	if e.link != nil {
		e.link.Close()
		e.link = nil
	}
	if e.coll != nil {
		e.coll.Close()
		e.coll = nil
	}
	return nil
}
