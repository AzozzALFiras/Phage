// Package process reconstructs process context from /proc: the ancestry chain,
// the executable path, and the controlling terminal. It is read-only and
// best-effort — a process can exit between the kernel event and this lookup, in
// which case callers get whatever was still available rather than an error.
package process

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// Stat holds the few /proc/<pid>/stat fields Phage needs.
type Stat struct {
	PPID  int32
	TTYNr int32
}

// ReadStat parses /proc/<pid>/stat. The comm field can contain spaces and
// parentheses, so the numeric fields are read from after the final ')'.
func ReadStat(pid int32) (Stat, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Stat{}, err
	}
	s := string(b)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 >= len(s) {
		return Stat{}, fmt.Errorf("malformed stat for pid %d", pid)
	}
	// Fields after "<pid> (comm) ": state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
	fields := strings.Fields(s[rparen+2:])
	if len(fields) < 5 {
		return Stat{}, fmt.Errorf("short stat for pid %d", pid)
	}
	ppid, _ := strconv.Atoi(fields[1])
	tty, _ := strconv.Atoi(fields[4])
	return Stat{PPID: int32(ppid), TTYNr: int32(tty)}, nil
}

// Comm returns /proc/<pid>/comm (the short command name), or "" if unavailable.
func Comm(pid int32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Exe resolves /proc/<pid>/exe, or "" if unavailable.
func Exe(pid int32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

// Lineage walks up the parent chain from pid, immediate parent first, up to
// maxDepth entries. It stops at init (pid 1) or when a parent can no longer be
// read.
func Lineage(pid int32, maxDepth int) []model.ProcRef {
	var chain []model.ProcRef
	cur := pid
	for i := 0; i < maxDepth; i++ {
		st, err := ReadStat(cur)
		if err != nil || st.PPID <= 0 {
			break
		}
		parent := st.PPID
		chain = append(chain, model.ProcRef{
			PID:  parent,
			Comm: Comm(parent),
			Exe:  Exe(parent),
		})
		if parent == 1 {
			break
		}
		cur = parent
	}
	return chain
}
