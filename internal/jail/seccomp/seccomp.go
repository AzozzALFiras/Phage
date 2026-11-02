// Package seccomp turns a learned syscall profile into a least-privilege policy:
// an OCI seccomp JSON document and an equivalent systemd drop-in. This is the
// "generate" half of auto-jail. Enforcement is deliberately delegated to
// battle-tested machinery (the kernel's seccomp filter, applied by systemd or a
// container runtime) rather than reinvented — Phage's contribution is learning
// *which* syscalls a service legitimately needs, not a new sandbox.
//
// Safety posture: the default action is ERRNO(EPERM), not KILL. A syscall the
// learning window happened to miss then fails gracefully and shows up in the
// service log, instead of the service being killed outright. A generated profile
// is still a starting point to validate in staging, never a blind drop-in — see
// docs/concepts/auto-jail.md.
package seccomp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/AzozzALFiras/Phage/internal/jail/profile"
	"github.com/AzozzALFiras/Phage/internal/jail/syscalls"
)

// baseline is always allowed, observed or not: the minimum any process needs to
// start under systemd/a container runtime, handle signals, and run down cleanly.
//
// execve/execveat are here on purpose. systemd (and OCI runtimes) *exec* the
// service to start it, and seccomp cannot tell a startup exec from a later one —
// so denying execve would stop the service booting, and cannot be used to stop
// an exploited service spawning a shell. That job belongs to Phage's exec sensor
// (detect) and, where the kernel allows it, eBPF-LSM (block). Being honest about
// this is the difference between a real jail and security theatre.
var baseline = []string{
	"execve", "execveat",
	"exit", "exit_group", "rt_sigreturn", "rt_sigprocmask", "rt_sigaction",
	"restart_syscall", "futex", "sched_yield", "nanosleep", "clock_nanosleep",
	"getpid", "gettid", "brk", "mmap", "munmap", "mprotect",
}

// highRisk is the set whose *absence* unambiguously shrinks an exploit's blast
// radius and that a typical service never legitimately needs: debugging other
// processes, loading kernel code, mounting and namespace tricks, key management,
// and host-level control. The generator reports which of these a profile blocks,
// because that list is the security story of the jail. Networking syscalls
// (socket/connect/…) are deliberately NOT here — they are normal for most
// services; the summary notes network isolation separately when it applies.
var highRisk = []string{
	"ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
	"bpf", "kexec_load", "kexec_file_load", "perf_event_open",
	"init_module", "finit_module", "delete_module", "create_module", "query_module",
	"mount", "umount2", "move_mount", "pivot_root", "chroot",
	"setns", "unshare", "add_key", "request_key", "keyctl",
	"reboot", "swapon", "swapoff", "mknod", "mknodat",
	"open_by_handle_at", "acct", "personality", "settimeofday", "clock_settime",
}

// networkSyscalls, if none is observed, means the service never touched the
// network during profiling — so the jail denies all of them. For a service that
// only accepts (or does nothing), this blocks reverse shells and exfil outright.
var networkSyscalls = []string{"socket", "socketpair", "connect", "sendto", "sendmsg"}

// Allowed is the sorted, de-duplicated set of syscall names a profile permits:
// everything observed, plus the baseline. It errors if the profile names a
// syscall number the embedded table does not know, rather than emit a filter
// with a bogus "syscall_NNN" entry that would fail to load.
func Allowed(p *profile.Profile) ([]string, error) {
	set := map[string]struct{}{}
	for _, name := range baseline {
		set[name] = struct{}{}
	}
	for _, nr := range p.Syscalls() {
		if !syscalls.Known(nr) {
			return nil, fmt.Errorf("syscall number %d is not in the arch table; regenerate scripts/gen/syscalls.sh", nr)
		}
		set[syscalls.Name(nr)] = struct{}{}
	}
	return sortedKeys(set), nil
}

// Blocked lists the high-risk syscalls this profile does NOT allow — the
// concrete blast-radius reduction, for the operator-facing summary.
func Blocked(p *profile.Profile) ([]string, error) {
	allowed, err := Allowed(p)
	if err != nil {
		return nil, err
	}
	allow := map[string]struct{}{}
	for _, n := range allowed {
		allow[n] = struct{}{}
	}
	var blocked []string
	for _, n := range highRisk {
		if _, ok := allow[n]; !ok {
			blocked = append(blocked, n)
		}
	}
	sort.Strings(blocked)
	return blocked, nil
}

// NetworkIsolated reports whether the profile denies all networking — i.e. the
// service never created or used a socket during profiling. For such a service
// the jail blocks reverse shells and exfil at the syscall boundary.
func NetworkIsolated(p *profile.Profile) (bool, error) {
	allowed, err := Allowed(p)
	if err != nil {
		return false, err
	}
	allow := map[string]struct{}{}
	for _, n := range allowed {
		allow[n] = struct{}{}
	}
	for _, n := range networkSyscalls {
		if _, ok := allow[n]; ok {
			return false, nil
		}
	}
	return true, nil
}

// ociSyscallRule is one entry of an OCI seccomp profile's syscalls array.
type ociSyscallRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// ociProfile is the subset of the OCI runtime-spec seccomp schema we emit. It is
// accepted as-is by Docker (--security-opt seccomp=file), containerd, and podman.
type ociProfile struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures"`
	Syscalls      []ociSyscallRule `json:"syscalls"`
}

// OCI renders the profile as an indented OCI seccomp JSON document.
func OCI(p *profile.Profile) ([]byte, error) {
	allowed, err := Allowed(p)
	if err != nil {
		return nil, err
	}
	doc := ociProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64"},
		Syscalls:      []ociSyscallRule{{Names: allowed, Action: "SCMP_ACT_ALLOW"}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// SystemdDropin renders an equivalent systemd service drop-in. A bare
// SystemCallFilter list is an allowlist; everything else returns EPERM. Pair it
// with `systemctl edit <unit>` + restart to apply.
func SystemdDropin(p *profile.Profile) (string, error) {
	allowed, err := Allowed(p)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by phage-jail from a learned profile of %s.\n", p.Unit)
	fmt.Fprintf(&b, "# Observed %d syscall invocations over %s; validate in staging before trusting.\n",
		p.TotalEvents(), p.Duration.Round(1e9))
	b.WriteString("[Service]\n")
	b.WriteString("SystemCallArchitectures=native\n")
	b.WriteString("SystemCallErrorNumber=EPERM\n")
	b.WriteString("SystemCallFilter=" + strings.Join(allowed, " ") + "\n")
	return b.String(), nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
