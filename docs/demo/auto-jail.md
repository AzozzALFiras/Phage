# Demo: learning a least-privilege jail for a live service

A live run on the test server (Ubuntu, kernel 7.0, x86_64) showing Phage **learn
the syscalls a web service makes, generate a least-privilege seccomp profile from
them, and prove the profile enforces** — with no hand-written policy.

## Setup
A stateless web service (`python3 -m http.server`, bound to localhost) is
launched *into a cgroup the profiler already targets*, so counting begins at the
service's very first instruction — a complete profile, startup included. It then
serves real traffic for the 12-second window.

```sh
mkdir /sys/fs/cgroup/phage-jail-demo
phage-jail -path phage-jail-demo -bpf bpf/build/jail.bpf.o -seconds 12 -out ./out &
# launch the service INTO the pre-targeted cgroup, then exec (full capture):
( echo $BASHPID > /sys/fs/cgroup/phage-jail-demo/cgroup.procs; exec python3 -m http.server 8099 --bind 127.0.0.1 ) &
# ... drive it with curl ...
```

## What it learned

```
observed 4350 syscall invocations over 12s
distinct syscalls used: 52; profile allows 60 (used + minimal baseline)
blast-radius reduction — denied high-risk syscalls:
  acct add_key bpf chroot clock_settime create_module delete_module finit_module
  init_module kcmp kexec_file_load kexec_load keyctl mknod mknodat mount
  move_mount open_by_handle_at perf_event_open personality pivot_root
  process_vm_readv process_vm_writev ptrace query_module reboot request_key
  setns settimeofday swapoff swapon umount2 unshare
```

From 52 observed syscalls it generated an OCI seccomp JSON and a systemd drop-in
that allow those 52 plus a minimal baseline, and deny everything else with
`EPERM`. The denied high-risk list above is the concrete blast-radius reduction:
this web server never debugs processes, loads kernel modules, mounts, or touches
namespaces — so jailed, an exploit of it cannot either.

## Proof it enforces
Running the service's own interpreter under the generated filter, attempting two
denied high-risk syscalls:

```
-- jailed (generated filter; EPERM on anything unlisted): --
  unshare() -> -1 | Operation not permitted
  ptrace()  -> -1 | Operation not permitted
-- control, no jail: --
  unshare() -> 0 | Success
  ptrace()  -> 0 | Success
```

The interpreter itself runs fine (the profile is complete, so it does not break
the service), but `unshare` (userns/container-escape) and `ptrace` (inject into
other processes) — both in the reported blocked set — are refused. Without the
jail they succeed.

## Enforcement that seccomp can't do: exec-lock (eBPF-LSM)
The seccomp profile above cannot stop the service spawning a shell (systemd needs
`execve` to start it). On a kernel booted with the BPF LSM active, `phage-jail
lock` closes that gap — an `lsm/bprm_check_security` program denies any new
`execve` inside the locked cgroup. Same web service, locked:

```
== BEFORE lock: exec inside the service cgroup ==
  joined: 0::/system.slice/phage-webdemo.service
  -> exec SUCCEEDED (a shell could spawn here)
== apply eBPF-LSM exec-lock on the service ==
  exec-locked phage-webdemo.service (cgroup id 6774): it can no longer spawn new programs
== AFTER lock: same attempt inside the service cgroup ==
  joined: 0::/system.slice/phage-webdemo.service
  bash: /bin/echo: Operation not permitted
  -> exec DENIED (rc=126) — no new program can start in this cgroup
== is the service itself still alive? ==
  service serves HTTP: 200  state: active
== collateral check: exec OUTSIDE the locked cgroup still works ==
  -> outside-cgroup exec OK
```

A process in the locked cgroup — exactly what an exploited service's shell would
be — is refused at the kernel, while the service keeps serving and every other
cgroup is untouched. When `phage-jail` exits, the lock lifts and exec works
again: enforcement is tied to the tool's lifetime, so it cannot lock the box out.

## Honest notes
- **Capturing startup matters.** An earlier run that attached *after* the service
  started omitted its startup syscalls (`socket`/`bind`/`listen`/`execve`), which
  would stop the service rebooting under the filter. The complete-capture flow
  above (and `-follow` for existing units) fixes this; the tool and docs call it
  out because an incomplete profile is a self-inflicted outage.
- **`execve` stays allowed.** systemd execs the service to start it, and seccomp
  cannot tell that exec from a later one — so this profile does **not** claim to
  stop the service spawning a shell. That is the exec sensor's job (it already
  flags it) and, on kernels with `lsm=bpf`, eBPF-LSM's. See
  [auto-jail](../concepts/auto-jail.md) and
  [ADR 0003](../architecture/decisions/0003-auto-jail-seccomp.md).
- **Validate before trusting.** The `EPERM` default degrades a missed syscall to
  a logged error rather than a crash, but a profile should still be exercised
  across error paths, reloads, and shutdown in staging first.
