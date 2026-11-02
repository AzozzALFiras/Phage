# Auto-jail (least-privilege by learning)

Detection catches an intrusion as it happens. Auto-jail attacks the problem from
the other side: **shrink what a service can do at all**, so that an exploited
process is boxed in before it ever does anything novel. An attacker who lands RCE
in a web app that physically cannot `ptrace`, load a kernel module, enter a new
namespace, or open an outbound socket has won far less.

The hard part of least-privilege is *writing* the policy — nobody knows every
syscall their service legitimately makes. Phage learns it.

## How it works

```
run service ──► [jail.bpf.c: tp_btf/sys_enter, per cgroup] ──► syscall set
                                                                    │
                                                 [internal/jail/seccomp]
                                                                    │
                                     least-privilege profile (OCI JSON + systemd drop-in)
```

1. **Learn.** `phage-jail` attaches an eBPF program to the raw syscall-entry
   tracepoint, gated on one service's cgroup id, and records which syscall
   numbers it makes over a representative window.
2. **Generate.** It turns that set into a seccomp allowlist: every observed
   syscall, plus a minimal always-allow baseline, with a default action of
   `ERRNO(EPERM)` for everything else.
3. **Apply (you, in staging first).** The profile ships as an OCI seccomp JSON
   (for `docker --security-opt seccomp=…` / containerd / podman) and a systemd
   drop-in (`SystemCallFilter=…`). Enforcement is the kernel's seccomp filter —
   Phage does not reinvent the sandbox (see
   [ADR 0003](../architecture/decisions/0003-auto-jail-seccomp.md)).

## What the jail removes (and what it cannot)
A typical service never debugs other processes, loads kernel code, mounts
filesystems, or juggles namespaces. The generated profile denies all of that:
`ptrace`, `process_vm_readv/writev`, `bpf`, `kexec_load`, `init_module` /
`finit_module` / `delete_module`, `mount` / `umount2` / `pivot_root` / `chroot`,
`setns` / `unshare`, `add_key` / `request_key` / `keyctl`, `perf_event_open`,
`open_by_handle_at`, `reboot`, `swapon/off`, and more — the primitives behind
most privilege escalation, container escape, and rootkit loading. For a service
that never opens a socket, it denies **all** networking, so a reverse shell or
exfil cannot leave.

What seccomp **cannot** do, stated plainly: block the service's *own* `execve` of
a shell. systemd execs the service to start it, and seccomp cannot tell that exec
from a later one, so `execve` must stay allowed in the profile. That gap is
closed by the eBPF-LSM exec-lock below, and by Phage's exec sensor, which detects
the spawn regardless.

## Enforcement: exec-lock (eBPF-LSM)
On a kernel booted with the BPF LSM active (`bpf` in `/sys/kernel/security/lsm`),
`phage-jail lock` does what seccomp cannot: it attaches an `lsm/bprm_check_security`
program that **denies any new `execve` inside a locked service's cgroup**. Applied
to a service after it has started, an exploited instance — a webshell, an injected
command — simply cannot launch `sh`, `bash`, `curl`, or anything else; the kernel
refuses the exec with `EPERM`. The service keeps running (a long-lived daemon
never needs to spawn new programs), and nothing outside its cgroup is affected.

It is default-allow and scoped to exactly the cgroups you lock, and the lock lifts
the instant `phage-jail` exits — so it cannot lock the box out. Together with the
seccomp profile (which removes the exotic primitives) this is real blast-radius
containment: an exploit lands in a process that can neither spawn a shell nor use
the dangerous syscalls, learned per service rather than hand-written.

## Getting a trustworthy profile
- **Capture startup.** A profile missing the service's earliest syscalls will
  stop it booting under the filter. Profile from before the process starts (the
  `phage-jail -path` flow launches the service into a cgroup it already targets),
  or use `-follow` to track an existing unit across a restart.
- **Exercise every path.** Error handling, config reload, and graceful shutdown
  use syscalls steady-state serving does not. Profile long enough, and across
  those events, or the filter will EPERM them later.
- **Validate in staging.** The `ERRNO(EPERM)` default means a missed syscall
  surfaces in the service log instead of killing the process — watch for it
  before trusting the profile in production.

## Status and gaps
- **Shipped:** syscall learn + seccomp generate, and eBPF-LSM **exec-lock**
  enforcement — all live-verified (see [demo/auto-jail](../demo/auto-jail.md)).
  amd64 only (the syscall table is generated per-arch from the kernel header;
  arm64 is future work). Exec-lock needs a kernel with `bpf` in the active LSM
  list (`lsm=...,bpf`).
- **Not yet:** an *allowlist* exec-lock (permit a service's few legitimate child
  programs, deny the rest) rather than all-or-nothing; automatically applying the
  seccomp profile; and extending LSM enforcement to egress/file using the
  detection baseline. See the [roadmap](../roadmap.md).
