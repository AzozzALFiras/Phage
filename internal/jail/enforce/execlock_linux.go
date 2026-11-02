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
	modeMapName    = "jail_mode"
	allowedMapName = "allowed_exec"
	activeLSMsFile = "/sys/kernel/security/lsm"

	// Modes must match the JAIL_* constants in bpf/programs/jail_lsm.bpf.c.
	modeOff     uint8 = 0
	modeLearn   uint8 = 1
	modeEnforce uint8 = 2
)

// execKey mirrors struct exec_key in jail_lsm.bpf.c (two u64, no padding):
// the cgroup id and an FNV-1a hash of the executable path.
type execKey struct {
	Cgid     uint64
	PathHash uint64
}

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

// ExecLock is a loaded, attached LSM program plus its policy maps.
type ExecLock struct {
	coll    *ebpf.Collection
	link    link.Link
	mode    *ebpf.Map
	allowed *ebpf.Map
}

// LoadExecLock loads the LSM object at objPath and attaches the exec guard. On
// its own this changes nothing: no cgroup is jailed until a mode is set.
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

	if e.mode = coll.Maps[modeMapName]; e.mode == nil {
		e.Close()
		return nil, fmt.Errorf("map %q not found", modeMapName)
	}
	if e.allowed = coll.Maps[allowedMapName]; e.allowed == nil {
		e.Close()
		return nil, fmt.Errorf("map %q not found", allowedMapName)
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

// Learn puts a cgroup in learn mode: every program it execs is recorded as
// allowed, and nothing is denied. Run it while the service does normal work.
func (e *ExecLock) Learn(cgroupID uint64) error {
	return e.setMode(cgroupID, modeLearn)
}

// Enforce puts a cgroup in enforce mode: only programs learned so far may
// execve; anything else is denied. With no prior learn this is a strict
// exec-lock (no new program at all).
func (e *ExecLock) Enforce(cgroupID uint64) error {
	return e.setMode(cgroupID, modeEnforce)
}

// Unlock removes a cgroup's jail (mode off), so exec is unrestricted again.
func (e *ExecLock) Unlock(cgroupID uint64) error {
	return e.mode.Delete(cgroupID)
}

// AllowedCount returns how many distinct programs are currently allowed for a
// cgroup — the size of what learn captured, for the operator summary.
func (e *ExecLock) AllowedCount(cgroupID uint64) int {
	var (
		k    execKey
		v    uint8
		n    int
		iter = e.allowed.Iterate()
	)
	for iter.Next(&k, &v) {
		if k.Cgid == cgroupID {
			n++
		}
	}
	return n
}

func (e *ExecLock) setMode(cgroupID uint64, mode uint8) error {
	if cgroupID == 0 {
		return errors.New("refusing to jail cgroup id 0")
	}
	return e.mode.Update(cgroupID, mode, ebpf.UpdateAny)
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
