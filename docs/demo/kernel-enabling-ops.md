# Demo: catching the exploit *before* it escalates

A live run on the test server (kernel 7.0) showing Phage flag the **setup phase**
of a kernel exploit — an unprivileged user namespace created by a process that
has no business doing so — before any privilege escalation happens.

## Why these operations
A few kernel operations are rare in normal service workloads but are the
groundwork of modern Linux local privilege escalation and container escape:

- **unprivileged user namespaces** (`unshare(CLONE_NEWUSER)` → `create_user_ns`) —
  hand an unprivileged process capabilities inside a new namespace, widening the
  kernel surface it can reach (the enabler behind many nf_tables / net LPEs).
- **eBPF program load** (`bpf_prog_load`) — legitimate for a handful of tools,
  and also how modern eBPF rootkits install themselves.
- **io_uring** and **userfaultfd** — recurring exploit primitives for heap
  grooming and use-after-free timing.

Phage hooks each with an `fentry` program. The signal is behavioural, not a
blanket block: which programs legitimately do these is tiny and stable per host
(systemd, a container runtime, an admin tool), so a service — or a shell it
spawned — doing one it has never done stands out.

## The run
Baseline learned normal behaviour, including a legitimate admin creating a user
namespace (`unshare -Ur`). Then in `alert` mode:

```
# CONTROL — the known admin tool creates a userns again
unshare -Ur true
   → no alert   (established actor for this op)

# ATTACK — a session-less service process sets up an exploit
systemd-run -p User=nobody ./kexp      # calls unshare(CLONE_NEWUSER)
```

## The result
```
ALERT score=0.59 comm="kexp" parent="systemd" uid=65534->euid=0 interactive=false ::
    a program performed a high-risk kernel-enabling operation it has never
    performed on this host;
    high-risk kernel operation from a process with no interactive session
    (op: userns)
```

The admin's `unshare` was silent; the service's user-namespace setup was flagged,
naming the operation. This fires **before** the exploit reaches `commit_creds` —
an early-warning signal on the exploit's groundwork, caught because *this actor*
has no history of it, even though the host does use user namespaces legitimately.

## Scope
These sensors see the operation and its actor, not the exploit's internals. They
raise the alarm on the setup; the escalation itself, if it still lands, is caught
again by the privilege sensor (and, in enforce mode, contained). Defence in depth
from one learned baseline.
