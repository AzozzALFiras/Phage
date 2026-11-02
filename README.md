<div align="center">

# Phage

**An autonomous immune system for Linux servers — it contains what it can't yet patch.**

*A phage is a biological agent that hunts down invaders and neutralizes them — a living defense that works without knowing the pathogen in advance. This one does the same for your server.*

</div>

---

New vulnerabilities never stop appearing — in PHP, in Node.js, in the kernel
itself, and in things not written yet. Chasing a patch for each one is a race
you lose by design. Phage takes the other path: **assume the breach**, then
make it survivable.

Phage is a lightweight agent that learns how a server *normally* behaves, then
detects and contains anything that steps outside it — **without a signature for
the specific vulnerability**. That is what lets it stand against the unknown.

## The thesis

1. **Shrink the attack surface.** Fewer doors, fewer ways in.
2. **Contain the blast radius.** If a service is exploited, it still cannot do
   more than it normally does.
3. **Detect by behavior, not signatures.** Catch the *effect* of an exploit
   (an unexpected path to root), not a known exploit's fingerprint.
4. **Respond and recover on its own.** Isolate, freeze, roll back — without a
   human in the loop.

The first three need no prior knowledge of the vulnerability. That is the point.

## First module: privilege-escalation defense

Phage starts where the damage is worst: a process gaining **root**. Every
privilege change in Linux passes through one kernel chokepoint, so Phage
watches it with eBPF and asks a behavioral question, not a rule:

> Does this path to root match how root is *normally* reached on this host —
> traced back to a real, authenticated SSH/login session?

A root transition with no interactive session behind it — say, a web process
that suddenly becomes root — scores as anomalous because the **learned
baseline** says so, not because someone hardcoded an `if`.

## Status

🚧 **Early development.** The architecture and the analysis seams are in place;
sensors and the behavioral model are being built. Not production-ready.

## How it is built

- **Language:** Go (userspace agent) + C/eBPF CO-RE (kernel sensors).
- **Why:** the hot path runs in-kernel (cheap), the agent ships as a single
  static binary (easy to adopt). See
  [docs/architecture/decisions/0001](docs/architecture/decisions/0001-language-go-and-ebpf.md).

## Documentation

Start at **[docs/README.md](docs/README.md)** — architecture, threat model, the
operating modes, and the analysis-engine design.

## Safety: the three-mode ladder

Phage never jumps to enforcement. Every deployment climbs a ladder:

`learn` → `alert` → `enforce`

so an immature baseline can never kill a legitimate process. See
[docs/concepts/modes.md](docs/concepts/modes.md).

## License

[MIT](LICENSE).
