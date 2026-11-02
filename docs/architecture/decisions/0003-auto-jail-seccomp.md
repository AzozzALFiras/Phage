# ADR 0003 — Auto-jail generates seccomp, it does not reinvent a sandbox

**Status:** accepted · **Date:** 2026-11-02

## Context
Phage's detection sensors answer "is this behaviour novel?" Auto-jail (M3) is the
other half of the thesis: **shrink the attack surface** so an exploited service
cannot do what it never legitimately does. The question is what enforcement
mechanism learns and applies a per-service least-privilege policy.

Two mechanisms were on the table:

- **eBPF-LSM.** Deny actions in-kernel on an already-running process, reusing the
  signals Phage already learns (exec/egress/file). Powerful, and it can block a
  service's *own* new `execve`. But it requires the kernel booted with
  `lsm=...,bpf`; on our target box `CONFIG_BPF_LSM=y` yet `bpf` is **not** in the
  active LSM list, so enforcement would need a boot-param change and a reboot.
- **seccomp-bpf.** Filter syscalls per service. Always available
  (`CONFIG_SECCOMP_FILTER=y` everywhere), and the standard mechanism systemd
  (`SystemCallFilter=`) and container runtimes already apply. It cannot inspect
  pointers or paths, and — crucially — cannot distinguish a service's startup
  `execve` from a later one.

## Decision
Auto-jail **learns which syscalls a service uses and generates a least-privilege
seccomp profile** (OCI JSON + a systemd drop-in). Enforcement is delegated to the
kernel's seccomp filter as applied by systemd or a container runtime — Phage does
not implement a new sandbox.

- `bpf/programs/jail.bpf.c` — a `tp_btf/sys_enter` profiler, gated on one target
  cgroup id, counting syscall numbers into a map. Its own object, loaded only by
  `phage-jail`, never by the detection daemon (sys_enter is the hottest
  tracepoint in the kernel).
- `internal/jail/{syscalls,profile,seccomp,sensor,cgroup}` — the arch syscall
  table (generated from the kernel's own header), the learned profile, the
  profile→seccomp generator, the eBPF loader, and cgroup-id resolution.
- `cmd/phage-jail` — the operator tool.

## What seccomp honestly can and cannot do here
- **Can:** deny the many high-risk syscalls a typical service never needs —
  `ptrace`, `bpf`, `mount`, `unshare`/`setns`, `kexec_*`, module loading,
  `perf_event_open`, `process_vm_*`, `keyctl`, `open_by_handle_at`. Denying these
  removes most privilege-escalation, container-escape, and rootkit primitives. It
  can also deny **all networking** for a service that never opens a socket,
  killing reverse shells and exfil at the boundary.
- **Cannot:** block the service's *own* `execve` of a shell. systemd execs the
  service to start it, and seccomp cannot tell that exec from a later one, so
  `execve`/`execveat` must be allowed (they are in the always-allow baseline).
  Stopping an exploited service from spawning a shell is therefore the job of the
  **exec sensor** (detect) and, where the kernel permits it, **eBPF-LSM** (block)
  — not this profile. Claiming otherwise would be security theatre.

## Safety posture
- Default action is `ERRNO(EPERM)`, not `KILL`: a syscall the learning window
  missed fails gracefully and shows in the log, rather than crashing the service.
- Capturing a **complete** profile (including process startup) matters: a profile
  missing early-startup syscalls will stop the service booting under the filter.
  The tool captures from a cgroup it targets *before* the process starts; for an
  already-running unit it offers `-follow` (re-resolves the cgroup across a
  restart) and the guidance to validate in staging before trusting a profile.

## Consequences
- Generated profiles are a **validated starting point**, not a blind drop-in; the
  docs say so plainly.
- The seccomp gap (a service's own `execve`) is closed by an **eBPF-LSM exec-lock**
  (`lsm/bprm_check_security`), shipped alongside this. It runs the same
  learn → enforce ladder per cgroup: learn the programs a service legitimately
  execs, then allow only those and deny anything new with `EPERM` (or, with no
  learn, a strict lock denying every new exec). Default-allow, scoped to the
  cgroups you lock, lifted when the tool exits. It required enabling the BPF LSM
  on the target (`lsm=...,bpf` at boot; safe — the hook is inert until a program
  attaches).
- The exec allowlist keys on the executable **path** (`bprm->filename`, hashed),
  not the inode: coreutils/busybox multi-call binaries hardlink many applets to
  one inode, so an inode key would let "allow `date`" silently allow `id`. (We
  cannot use `bpf_d_path` here — `bprm_check_security` is not on its allowlist —
  so we hash the path string the caller passed.)
- Extending LSM enforcement to egress/file per cgroup, reusing the detection
  baseline, remains a future increment.
