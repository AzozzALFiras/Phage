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

## Contents

- [Seeing it work](#seeing-it-work-a-real-attack-stopped)
- [The thesis](#the-thesis)
- [How it detects](#how-it-detects) — the learned baseline, in detail
- [How it responds](#how-it-responds) — the graduated-response matrix
- [Safety](#safety-the-ladder-and-what-enforce-will-never-touch)
- [How it's built](#how-its-built) — architecture, inline
- [Build and run](#build-and-run)
- [Honest limitations](#honest-limitations)
- [Status](#status) · [Contributing & security](#contributing--security) · [License](#license)

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

Legitimate privilege use inside an SSH login stayed silent — because on this host
root is only ever reached *through a login session*, and this wasn't one. Phage
didn't recognize the exploit; it recognized that the result was impossible for
this server.

> Evidence and reproduction: four attacks run with Phage off (they succeed) and on
> (detected / contained / blocked) in [docs/demo/proof-before-after.md](docs/demo/proof-before-after.md);
> detection-rate *and* false-positives measured together in [PhageBench](docs/benchmark/phagebench.md).

## The thesis

1. **Shrink the attack surface.** Fewer doors, fewer ways in.
2. **Contain the blast radius.** An exploited service still can't do more than it
   normally does.
3. **Detect by behavior, not signatures.** Catch the *effect* of an exploit (an
   impossible path to root, a service spawning a shell), not a fingerprint.
4. **Respond and recover on its own** — freeze, isolate, roll back.

The first three need no prior knowledge of the vulnerability. That is the point:
a signature can only catch an attack someone has already seen and described;
behavior catches the *consequence*, which an attacker cannot avoid producing.

## How it detects

Phage never ships a list of "bad" things. Instead, every interesting kernel event
flows through a four-stage pipeline, and the host's own history decides what is
normal:

```
kernel event  ──►  feature  ──►  baseline  ──►  score + reasons  ──►  verdict
 (eBPF sensor)    (measure it)  (seen before?)  (how surprising?)   (what to do)
```

1. **Measure, don't match.** A sensor turns each event into a few plain features —
   e.g. *"this process reached euid 0"*, *"there was no login session behind it"*,
   *"this parent has never spawned this child before"*. No feature says "bad"; it
   just describes what happened.
2. **Compare to the learned baseline.** In `learn` mode Phage records these
   features per host and builds a statistical picture of normal. Scoring is based
   on **novelty**, not rarity: a value the host has genuinely never produced is
   surprising; a value it produces all day is not — even if there are thousands of
   distinct ones.
3. **Score with confidence gating.** A feature Phage has barely observed counts for
   little, so a freshly-deployed agent off a thin baseline does not raise confident
   alerts. Weak signals are averaged; a handful of **red-flag features** that mean
   malice on their own (fileless execution, an `LD_PRELOAD` hijack, a root
   escalation with no session) instead *floor* the score high — so an attacker who
   disguises everything else as normal is still caught.
4. **Explain the verdict.** Every score carries human-readable reasons ("raised to
   root with no login session behind it (never seen on this host)"), so an operator
   can always see *why* — there is no opaque model to trust.

The signals Phage watches today, each scored this way:

| Signal | Catches | Status |
|---|---|---|
| A process reaches **root with no login session** behind it | Linux/kernel privesc, SQLi/RCE → root | ✅ |
| A service spawns a **never-before-seen program** (parent→child), incl. **fileless** in-memory execution and **LD_PRELOAD** hijacks | PHP/Node RCE, command injection, webshells, reverse shells, memfd malware, linker injection | ✅ |
| **Outbound connection from a process that never egresses** | reverse shells, C2, exfil | ✅ |
| **Writes to persistence/credential files** (web-root `.php`, `authorized_keys`, cron) | webshell drop, backdoored keys, persistence | ✅ |
| **High-risk kernel-enabling ops** by a process with no history of them (userns, eBPF load, io_uring, userfaultfd) | kernel-exploit setup, container escape, eBPF rootkits | ✅ |
| **Tamper with the agent itself** — kill/stop/ptrace it, or telemetry going silent | EDR blinding / anti-detection | ✅ |
| **A process reads a planted decoy** (honeytoken) credential file | credential theft, intruder snooping | ✅ |

<sub>✅ verified live against a real attack on a test server. Each row links to a full write-up from the [docs index](docs/README.md#demos--live-verified-against-real-attacks).</sub>

**What it cannot see, stated plainly:** XSS runs in the victim's browser and
raw SQL-injection payloads live inside the DB query — neither is host-observable,
so Phage cannot see the payload. What it *can* see is the moment that exploit
reaches the operating system: the shell it spawns, the root it gains, the
connection it opens. It defends the server by catching effects, not payloads.

## How it responds

In `enforce` mode Phage doesn't just kill — killing destroys the evidence and
tips the attacker off. A **graduated-response matrix** picks the least-invasive
action that is *enough* for what the process actually did, and climbs only if the
process keeps earning it:

| Rung | What it does | Mechanism | Chosen for |
|---|---|---|---|
| **notify** | alert + append to the audit trail, nothing else | — | lower-confidence or easily-inspected signals |
| **isolate** | sever the process's outbound network, keep it running | an eBPF `cgroup/connect` hook on its cgroup denies new egress | a reverse shell / C2 beacon — the channel dies, forensics survive |
| **freeze** | pause the whole process tree, reversibly | moved into a cgroup-v2 freezer | a near-certain intruder (honeytoken read, no-session root) |

Two properties make this safe to leave on:

- **Escalation only moves up.** A process already contained at one rung isn't
  re-actuated or re-logged for a weaker verdict; a *stronger* verdict promotes it.
  In a live run one process dialed out (→ **isolate**) and then read a credential
  decoy (→ **freeze**) — the same pid climbed the ladder as the evidence mounted.
- **Containment is a lease, not a life sentence.** An isolated process that goes
  quiet is **released automatically** (it kept running and stopped misbehaving —
  that's real evidence it was benign or transient). A **frozen** process is
  *held* for a human (`phage thaw`), never auto-released: a frozen process is
  silent by construction, so "quiet" proves nothing, and freeze is reserved for
  near-certain verdicts.

Phage also **self-heals**: a malicious write to a watched file (`authorized_keys`,
cron, `ld.so.preload`) is rolled back to the known-good version within
milliseconds, and the attacker's version is kept in quarantine as evidence.

> Full runs with raw logs: [graduated-response](docs/demo/graduated-response.md),
> [network-quarantine](docs/demo/network-quarantine.md),
> [self-healing](docs/demo/self-healing.md).

## Safety: the ladder, and what enforce will never touch

A security tool that can lock you out of your own server is worse than none. Two
guarantees prevent that:

- **Phage never jumps to enforcement.** Every deployment climbs the ladder:
  `learn` (watch and build the baseline, act on nothing) → `alert` (score and
  warn, still act on nothing) → `enforce` (contain). An immature baseline
  therefore *cannot* act, and an empty one is neutral by construction.
- **Containment has hard guardrails** — born from a real lockout during
  development, where an early build froze `sshd` and shut the door on itself.
  Enforce mode will **never freeze an interactive login session or the control
  plane** (`sshd`, `systemd`, `phaged`, …), whatever the score. An attacker
  operating *as* the control plane is deliberately out of scope for automatic
  containment — availability wins that trade.

The `phage` CLI (`status`, `events`, `thaw <pid>`) gives an operator a live view
and a manual override at all times.

## How it's built

Phage is one Go binary and a set of small eBPF programs — no kernel module, no
agent fleet, no Kubernetes:

- **Kernel side (C / eBPF CO-RE).** A handful of programs attached to the events
  that matter — `commit_creds` (privilege changes), `sched_process_exec` (exec),
  `tcp_connect` (egress), `security_file_open` (writes + honeytokens), plus
  kernel-enabling hooks and LSM hooks for self-defense. They do the hot-path
  filtering in-kernel and push only the few events worth analysing up a single
  shared ring buffer. CO-RE + BTF means one compiled object runs across kernels
  without recompilation.
- **Userspace side (Go, `cilium/ebpf`).** A cgo-free, statically-linked daemon
  (`phaged`) loads the sensors and runs the pipeline: **sensor → enrich →
  analysis → policy → response**, one package per stage. `enrich` adds process
  lineage and session context; `analysis` is the feature/baseline/score/verdict
  engine above; `policy` is the response matrix; `response` actuates (freeze,
  isolate, self-heal) — all reversible.
- **Operations.** An append-only JSON audit trail records every verdict and
  action; the `phage` CLI talks to the daemon over a local Unix socket.

Because detection is a pluggable `Scorer` and detectors are just *features* over a
baseline, adding a new detector means adding a measurement — never an `if parent
== "bash"` rule. The design decisions behind this (why Go + eBPF, why behavioral,
why seccomp for jails) are recorded as ADRs under
[docs/architecture/decisions](docs/architecture/decisions/).

## Build and run

Requires Linux with kernel BTF (`/sys/kernel/btf/vmlinux`) to run; the Go agent
builds on any OS (a stub covers non-Linux).

```sh
make bpf            # compile the eBPF sensors (Linux; needs clang + libbpf)
make build          # build bin/phaged (daemon) and bin/phage (CLI)

sudo ./bin/phaged -mode learn      # 1. learn normal behaviour first (days, not minutes)
sudo ./bin/phaged -mode alert      # 2. then watch what it would flag — tune, don't act
sudo ./bin/phaged -mode enforce    # 3. then let it contain

./bin/phage status                 # live status
./bin/phage events                 # recent verdicts
./bin/phage thaw <pid>             # release a contained process
```

Useful flags: `-honeytokens` (plant decoy credential files), `-heal` (self-heal
watched files), `-protect` (arm eBPF-LSM tamper-resistance; needs BPF LSM),
`-release-after <s>` (de-escalation lease). Step-by-step:
[quickstart](docs/guides/quickstart.md); building the sensors:
[development](docs/guides/development.md).

## Honest limitations

Phage raises an attacker's cost and makes a breach survivable; it is not magic,
and saying so is part of being a security tool worth trusting:

- **Its ceiling is a kernel-level (ring-0) attacker.** Someone who can already load
  kernel code or disable the BPF LSM can blind or remove Phage. Self-defense makes
  that *noisy* and costly, not impossible.
- **Detection is behavioral and probabilistic.** A patient attacker who stays
  inside a host's learned-normal envelope can evade it, and an immature baseline
  both misses more and false-positives more. The real numbers — including where
  the false positives come from — are in [PhageBench](docs/benchmark/phagebench.md).
- **It is not a replacement for patching, least privilege, or a firewall.** It is
  the layer that assumes those will sometimes fail.

The full threat model, and Phage's own security policy, are in
[docs/concepts/threat-model.md](docs/concepts/threat-model.md) and
[SECURITY.md](SECURITY.md).

## Status

🚧 **Early but real — not yet production-ready.** The whole loop above works end to
end and is verified live against real attacks on a test server (kernel 7.0, BPF
LSM): learned-baseline detection across the seven signal classes, the graduated
reversible response, self-healing, agent self-defense, and the beginnings of
attack-surface reduction (auto-jail + an eBPF-LSM exec-lock that stops an exploited
service from spawning a shell at all). Next: automatic jail application,
baseline-driven LSM enforcement, broader kernel coverage, and a public benchmark
comparison. See the [roadmap](docs/roadmap.md).

## Contributing & security

Contributions are welcome — please keep the core principles (behavioral, not
signatures; a control plane that can't be locked out; one concern per package).
See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in Phage itself,
follow [SECURITY.md](SECURITY.md) (please don't open a public issue for it).

## License

[MIT](LICENSE).
