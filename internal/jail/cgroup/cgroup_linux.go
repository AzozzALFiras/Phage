//go:build linux

// Package cgroup resolves a service to the cgroup v2 id the kernel attributes
// its syscalls to. On cgroup v2 that id is the inode number of the cgroup's
// directory under /sys/fs/cgroup — the same value bpf_get_current_cgroup_id()
// returns in-kernel, which is what lets the profiler match the two.
package cgroup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const mountRoot = "/sys/fs/cgroup"

// IDForPath returns the cgroup id for a cgroup path relative to the v2 mount
// (e.g. "/system.slice/ssh.service"), or an absolute path under the mount.
func IDForPath(cgPath string) (uint64, error) {
	full := cgPath
	if !strings.HasPrefix(cgPath, mountRoot) {
		full = mountRoot + "/" + strings.TrimPrefix(cgPath, "/")
	}
	var st syscall.Stat_t
	if err := syscall.Stat(full, &st); err != nil {
		return 0, fmt.Errorf("stat cgroup %q: %w", full, err)
	}
	return st.Ino, nil
}

// IDForUnit resolves a systemd unit to its cgroup id by asking systemd for the
// unit's ControlGroup, then stat-ing it. The unit must be running (a stopped
// service has no cgroup). It returns the id and the resolved path.
func IDForUnit(unit string) (uint64, string, error) {
	if !strings.Contains(unit, ".") {
		unit += ".service"
	}
	out, err := exec.Command("systemctl", "show", "-p", "ControlGroup", "--value", unit).Output()
	if err != nil {
		return 0, "", fmt.Errorf("systemctl show %q: %w", unit, err)
	}
	cg := strings.TrimSpace(string(out))
	if cg == "" {
		return 0, "", fmt.Errorf("unit %q has no cgroup (is it running?)", unit)
	}
	id, err := IDForPath(cg)
	if err != nil {
		return 0, "", err
	}
	return id, cg, nil
}

// MountedV2 reports whether /sys/fs/cgroup is a cgroup v2 hierarchy, which the
// id-as-inode technique relies on.
func MountedV2() bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mountRoot, &st); err != nil {
		return false
	}
	const cgroup2Magic = 0x63677270 // "cgrp"
	return st.Type == cgroup2Magic && fileExists(mountRoot+"/cgroup.controllers")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
