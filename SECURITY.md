# Security policy

Phage is a defensive security tool. This document is about the security **of
Phage itself** — how to report a vulnerability in the agent, and what Phage does
and does not promise as a piece of privileged software.

## Reporting a vulnerability

Phage is an open-source project and its repository is **public**, so anything
filed in the public issue tracker is visible to everyone — including attackers.
**Please don't report a security vulnerability in a public issue.** Instead use a
private channel (the repository stays public; only the *report* is kept private):

1. **GitHub's private vulnerability reporting** (preferred) — on the repository,
   *Security → Report a vulnerability*. It opens a draft security advisory that
   only you and the maintainers can see.
2. **Email** — `azozzalfiras@gmail.com` with `[Phage security]` in the subject.

Please include, as far as you can:
- the affected component (eBPF sensor, agent, CLI, a specific package) and version
  or commit;
- what an attacker can achieve (e.g. bypass a detector, evade containment, crash
  or blind the agent, escalate through it);
- a minimal reproduction — kernel version, distro, config/mode, and the steps or
  a small PoC.

### What to expect
This is an early, maintainer-led project, so timelines are best-effort, not a
contractual SLA:
- acknowledgement within a few days;
- an initial assessment (severity, affected versions) after that;
- a fix on `main` and a GitHub Security Advisory crediting you (unless you prefer
  to stay anonymous) once a fix is available.

Coordinated disclosure is welcome — tell us if you have a deadline and we will
work to it.

## Supported versions

Phage is pre-1.0 and moves fast. Only the latest `main` is supported; fixes land
there. Pin a commit for reproducibility, but expect to update to get security
fixes.

## Phage's own threat model (what it does *not* promise)

Phage is designed to raise an attacker's cost and to survive a compromised
*service*, not to be unbreakable. Stated plainly:

- **It is not a substitute for patching, least privilege, or network controls.**
  It assumes the breach and makes it survivable; it does not make a vulnerable
  app safe.
- **Its ceiling is a kernel-level (ring-0) attacker.** An adversary who already
  has the ability to load kernel code, unload eBPF programs, or disable the BPF
  LSM can blind or remove Phage. Self-defense and the dead-man's-switch raise the
  cost and make blinding *noisy*, but do not make it impossible. See
  [docs/demo/tamper-resistance.md](docs/demo/tamper-resistance.md).
- **Detection is behavioral and probabilistic.** A patient attacker who stays
  inside a host's learned-normal envelope can evade it; an immature baseline both
  misses and false-positives more. The honest numbers are in
  [docs/benchmark/phagebench.md](docs/benchmark/phagebench.md).
- **Enforcement has hard safety limits by design** — it will not freeze an
  interactive login or the control plane (`sshd`, `systemd`, `phaged`). That is a
  deliberate availability trade-off, not an oversight; an attacker operating
  *as* the control plane is out of scope for automatic containment.

These limits are features of an honest security tool. If you find a way to defeat
a guarantee Phage *does* make (e.g. evade a detector that should fire, or make
enforce mode lock an operator out), that is a vulnerability — please report it.

## Responsible use

Phage is for defending and testing systems **you own or are authorized to
operate**. Every attack in this repository's demos and benchmarks is run only
against the maintainer's own authorized test infrastructure. Do not use Phage, or
the attack scripts shipped alongside it, against systems you do not have explicit
permission to test.
