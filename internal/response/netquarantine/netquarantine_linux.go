//go:build linux

// Package netquarantine severs a suspect's outbound network without killing it —
// the reversible response rung between alert and freeze. It attaches
// cgroup/connect programs to the offending process's own cgroup (its service),
// denying new egress (loopback excepted) for every process in it — including
// children it forks per connection, which a per-pid approach would miss. A
// reverse shell or C2 beacon can no longer dial out while the process keeps
// running for inspection; releasing detaches the programs and restores the net.
package netquarantine

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const cgroupRoot = "/sys/fs/cgroup"

// Manager owns the loaded cgroup/connect programs and the set of isolated cgroups.
type Manager struct {
	coll   *ebpf.Collection
	mu     sync.Mutex
	active map[string][]link.Link // cgroup dir -> attached links
	pidDir map[int32]string       // pid -> the cgroup dir it isolated
}

// New loads the netquarantine object (the connect4/connect6 programs).
func New(objPath string) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load %q: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}
	return &Manager{coll: coll, active: map[string][]link.Link{}, pidDir: map[int32]string{}}, nil
}

// Isolate severs egress for the cgroup the process belongs to (its service), so
// all its processes — present and future — lose outbound network. Reversible.
func (m *Manager) Isolate(pid int32) error {
	dir, err := cgroupDir(pid)
	if err != nil {
		return err
	}
	if dir == cgroupRoot || !strings.HasPrefix(dir, cgroupRoot+"/") {
		return fmt.Errorf("refusing to isolate a non-leaf/root cgroup %q", dir)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.pidDir[pid] = dir
	if _, ok := m.active[dir]; ok {
		return nil // this cgroup is already isolated
	}
	var links []link.Link
	for _, a := range []struct {
		prog   string
		attach ebpf.AttachType
	}{
		{"netq_connect4", ebpf.AttachCGroupInet4Connect},
		{"netq_connect6", ebpf.AttachCGroupInet6Connect},
	} {
		prog := m.coll.Programs[a.prog]
		if prog == nil {
			closeAll(links)
			return fmt.Errorf("program %q not found", a.prog)
		}
		lnk, err := link.AttachCgroup(link.CgroupOptions{Path: dir, Attach: a.attach, Program: prog})
		if err != nil {
			closeAll(links)
			return fmt.Errorf("attach %s to %s: %w", a.prog, dir, err)
		}
		links = append(links, lnk)
	}
	m.active[dir] = links
	return nil
}

// Release restores the network for the cgroup a pid was isolated in.
func (m *Manager) Release(pid int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir, ok := m.pidDir[pid]
	if !ok {
		return nil
	}
	delete(m.pidDir, pid)
	if links, ok := m.active[dir]; ok {
		closeAll(links)
		delete(m.active, dir)
	}
	return nil
}

// Close lifts every active isolation and frees the programs.
func (m *Manager) Close() error {
	m.mu.Lock()
	for dir, links := range m.active {
		closeAll(links)
		delete(m.active, dir)
	}
	m.mu.Unlock()
	if m.coll != nil {
		m.coll.Close()
	}
	return nil
}

func closeAll(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}

// cgroupDir resolves a pid to its cgroup-v2 directory under /sys/fs/cgroup, from
// the unified-hierarchy line ("0::/path") in /proc/<pid>/cgroup.
func cgroupDir(pid int32) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read cgroup of pid %d: %w", pid, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return cgroupRoot + strings.TrimPrefix(line, "0::"), nil
		}
	}
	return "", fmt.Errorf("no unified cgroup for pid %d", pid)
}
