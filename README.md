<div align="center">

# Phage

**An autonomous immune system for Linux servers — it contains what it can't yet patch.**

*A phage is a biological agent that hunts down invaders and neutralizes them — a
living defense that works without knowing the pathogen in advance. This one does
the same for your server.*

</div>

---

New vulnerabilities never stop appearing — in PHP, in Node.js, in the kernel
itself, and in things not written yet. Chasing a patch for each one is a race you
lose by design. Phage takes the other path: **assume the breach**, then make it
survivable.

Phage is a lightweight eBPF agent that learns how a server *normally* behaves,
then detects and contains anything that steps outside it — **without a signature
for the specific vulnerability**. The heavy lifting runs in the kernel, so it
stays cheap; the userspace agent ships as a single static binary.

## Seeing it work: a real attack, stopped

On a test server, a remote machine exploited a vulnerable web app (command
injection) to run as the unprivileged `webapp` user, then escalated to root via a
setuid binary. In `enforce` mode Phage caught and froze the escalation the instant
it happened — no signature for the bug, the payload, or the binary:

```
CRITICAL score=0.83 action=freeze pid=6518 comm="rootshell" uid=999->euid=0 ::
    an unprivileged process raised itself to root;
    raised to root with no login session behind it (never seen on this host)
CONTAIN pid=6518 FROZEN (process tree quarantined, reversible)
```

Legitimate privilege use inside an SSH login stayed silent. Full write-up:
[docs/demo/external-escalation.md](docs/demo/external-escalation.md).

## The thesis

1. **Shrink the attack surface.** Fewer doors, fewer ways in.
2. **Contain the blast radius.** An exploited service still can't do more than it
   normally does.
3. **Detect by behavior, not signatures.** Catch the *effect* of an exploit (an
   impossible path to root, a service spawning a shell), not a fingerprint.
4. **Respond and recover on its own** — freeze, isolate, roll back.

The first three need no prior knowledge of the vulnerability. That is the point.

## How it detects

Phage watches a few kernel signals and scores each against the host's **learned
baseline** — never a hardcoded rule:

| Signal | Catches | Status |
|---|---|---|
| A process reaches **root with no login session** behind it | Linux/kernel privesc, SQLi/RCE → root | ✅ |
| A service spawns a **never-before-seen program** (parent→child) | PHP/Node RCE, command injection, webshells, reverse shells | ✅ |
| **Outbound connection from a process that never egresses** | reverse shells, C2, exfil | ✅ |
| **Writes to persistence/credential files** (web-root `.php`, `authorized_keys`, cron) | webshell drop, backdoored keys, persistence | ✅ |

<sub>✅ verified live against a real attack on a test server</sub>

What it **cannot** see, stated plainly: XSS (runs in the victim's browser) and raw
SQL-injection payloads (inside the DB query) are not host-observable. Phage
detects their *effects* when they reach the OS, not the payloads themselves. See
[docs/concepts/threats-and-behavioral-defense.md](docs/concepts/threats-and-behavioral-defense.md).

## Safety: the ladder, and what enforce will never touch

Phage never jumps to enforcement. Every deployment climbs `learn → alert →
enforce`, so an immature baseline can't act. And containment has hard guardrails
(learned from a real lockout): it **never freezes an interactive login session or
the control plane** (`sshd`, `systemd`, `phaged`, …), and only ever contains an
actual privilege escalation. See [docs/concepts/modes.md](docs/concepts/modes.md).

## Build and run

Requires Linux with kernel BTF (`/sys/kernel/btf/vmlinux`) to run; the Go agent
builds anywhere.

```sh
make bpf            # compile the eBPF sensors (Linux; needs clang + libbpf)
make build          # build bin/phaged and bin/phage
sudo ./bin/phaged -mode learn          # learn normal behaviour first (days)
sudo ./bin/phaged -mode alert          # then watch what it flags
sudo ./bin/phaged -mode enforce        # then let it contain
./bin/phage status | events | thaw <pid>   # operator CLI
```

See [docs/guides/quickstart.md](docs/guides/quickstart.md) and
[development.md](docs/guides/development.md).

## How it's built

Go userspace agent (`cilium/ebpf`, cgo-free static binary) + C/eBPF CO-RE kernel
sensors. Architecture and the design decisions behind it:
[docs/README.md](docs/README.md).

## Status

🚧 **Early but real.** Privilege-escalation, exec, **egress**, and
**file/persistence** detection work end to end, with reversible containment, an
audit trail, and an operator CLI — all verified live against real attacks on a
test server ([privesc](docs/demo/external-escalation.md),
[reverse shell](docs/demo/egress-detection.md),
[persistence](docs/demo/file-persistence.md)). Blast-radius containment
(auto-jail) is next ([roadmap](docs/roadmap.md)). Not yet production-ready.

## License

[MIT](LICENSE).
