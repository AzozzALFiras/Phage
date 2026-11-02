package seccomp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/jail/profile"
)

// A quiet service: read/write/close/epoll/accept-less serving, but NO execve,
// NO socket. The whole point of the jail is that such a service, once exploited,
// still cannot spawn a shell or dial out.
func quietWebProfile() *profile.Profile {
	// 0 read, 1 write, 3 close, 9 mmap, 232 epoll_wait, 281 epoll_pwait, 262 newfstatat
	return profile.New("web.service", 42, map[int]uint64{
		0: 5000, 1: 4000, 3: 900, 9: 40, 232: 3000, 262: 120,
	}, 2*time.Minute)
}

func TestAllowedIncludesBaselineAndObserved(t *testing.T) {
	allowed, err := Allowed(quietWebProfile())
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	set := map[string]bool{}
	for _, n := range allowed {
		set[n] = true
	}
	// observed
	for _, n := range []string{"read", "write", "close", "epoll_wait"} {
		if !set[n] {
			t.Errorf("allowed is missing observed syscall %q", n)
		}
	}
	// baseline (never observed but always granted)
	for _, n := range []string{"exit_group", "rt_sigreturn", "futex"} {
		if !set[n] {
			t.Errorf("allowed is missing baseline syscall %q", n)
		}
	}
	// sorted, de-duplicated
	for i := 1; i < len(allowed); i++ {
		if allowed[i-1] >= allowed[i] {
			t.Errorf("allowed not strictly sorted/deduped at %d: %q then %q", i, allowed[i-1], allowed[i])
		}
	}
}

func TestBlockedReportsHighRiskAbsences(t *testing.T) {
	blocked, err := Blocked(quietWebProfile())
	if err != nil {
		t.Fatalf("Blocked: %v", err)
	}
	set := map[string]bool{}
	for _, n := range blocked {
		set[n] = true
	}
	// Unambiguous blast-radius wins: a web server never debugs processes, loads
	// kernel modules, mounts, or touches namespaces.
	for _, n := range []string{"ptrace", "bpf", "mount", "unshare", "init_module", "kexec_load"} {
		if !set[n] {
			t.Errorf("Blocked should list %q (not observed, so denied)", n)
		}
	}
	// execve is baseline-allowed (systemd needs it to start the service) and so
	// must never be reported as a blast-radius win — that would be theatre.
	if set["execve"] {
		t.Error("execve must not be in Blocked: it is baseline-allowed, and seccomp cannot block post-startup exec anyway")
	}
}

func TestBlockedExcludesObservedHighRisk(t *testing.T) {
	// A service that legitimately debugs (e.g. a profiler) keeps ptrace allowed.
	p := profile.New("profiler.service", 7, map[int]uint64{0: 1, 1: 1, 101: 50}, time.Minute) // 101 = ptrace
	blocked, err := Blocked(p)
	if err != nil {
		t.Fatalf("Blocked: %v", err)
	}
	for _, n := range blocked {
		if n == "ptrace" {
			t.Error("ptrace was observed; it must not appear in Blocked")
		}
	}
}

func TestNetworkIsolation(t *testing.T) {
	// A compute-only service that never touched a socket is network-isolated.
	iso, err := NetworkIsolated(quietWebProfile())
	if err != nil {
		t.Fatalf("NetworkIsolated: %v", err)
	}
	if !iso {
		t.Error("a profile with no socket/connect should be network-isolated")
	}
	// Once it opens a socket (41), it is not.
	withNet := profile.New("api.service", 9, map[int]uint64{0: 1, 1: 1, 41: 10}, time.Minute)
	iso, err = NetworkIsolated(withNet)
	if err != nil {
		t.Fatalf("NetworkIsolated: %v", err)
	}
	if iso {
		t.Error("a profile that opened a socket must not be network-isolated")
	}
}

func TestOCIIsValidAndErrnoDefault(t *testing.T) {
	raw, err := OCI(quietWebProfile())
	if err != nil {
		t.Fatalf("OCI: %v", err)
	}
	var doc struct {
		DefaultAction string `json:"defaultAction"`
		Architectures []string
		Syscalls      []struct {
			Names  []string
			Action string
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("OCI output is not valid JSON: %v", err)
	}
	if doc.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction = %q, want SCMP_ACT_ERRNO (fail-safe toward the service)", doc.DefaultAction)
	}
	if len(doc.Syscalls) != 1 || doc.Syscalls[0].Action != "SCMP_ACT_ALLOW" {
		t.Fatalf("expected a single ALLOW rule, got %+v", doc.Syscalls)
	}
	names := " " + strings.Join(doc.Syscalls[0].Names, " ") + " "
	if !strings.Contains(names, " read ") || !strings.Contains(names, " write ") {
		t.Errorf("allow rule missing observed syscalls: %s", names)
	}
	if !strings.Contains(names, " execve ") {
		t.Error("execve must be allowed (baseline: systemd needs it to start the service)")
	}
	if strings.Contains(names, " ptrace ") {
		t.Error("ptrace was never observed; it must not be allowed")
	}
}

func TestSystemdDropinShape(t *testing.T) {
	out, err := SystemdDropin(quietWebProfile())
	if err != nil {
		t.Fatalf("SystemdDropin: %v", err)
	}
	for _, want := range []string{"[Service]", "SystemCallErrorNumber=EPERM", "SystemCallFilter=", "read", "write", "execve"} {
		if !strings.Contains(out, want) {
			t.Errorf("drop-in missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ptrace") {
		t.Error("drop-in allows ptrace, which was never observed")
	}
}

func TestUnknownSyscallNumberErrors(t *testing.T) {
	p := profile.New("x", 1, map[int]uint64{999999: 1}, time.Second)
	if _, err := Allowed(p); err == nil {
		t.Error("expected an error for a syscall number not in the arch table")
	}
}
