# Threat model

Being explicit about what Phage does and does not defend keeps the project
honest and the roadmap focused.

## Assumptions
- Phage runs on the host it protects, as a privileged agent, with eBPF access.
- The host kernel exposes BTF (most distributions since ~2021).
- The attacker does **not** have kernel-level code execution *yet* — Phage's
  job is largely to notice and stop the attempt to get there.

## What Phage defends against (now and near-term)
- **Privilege escalation to root** via an unexpected path — the first module.
  Example: a web/app process that becomes root through a code-exec bug.
- **Post-exploitation actions that deviate from the baseline** (future modules):
  spawning shells, unusual outbound connections, tampering with sensitive files.
- **The blast radius of an exploited service** — containment keeps a popped
  process boxed into its normal behavior (future: auto-jail module).

The common thread: Phage detects the **effect** of exploitation behaviorally,
so it does not need a signature for the specific CVE.

## What Phage does *not* claim to do
- It is **not** a patch. Patch anyway; Phage buys time and contains fallout.
- It does **not** stop an attacker who already has kernel code execution and can
  disable the agent. (Tamper-resistance is a later, separate concern.)
- It is **not** a network firewall, a WAF, or an antivirus. It is complementary.
- A brand-new install **cannot** detect anything until it has learned — an empty
  baseline is neutral by design (see [modes](modes.md)).

## Trust boundaries
- **Kernel ↔ agent:** the eBPF program is trusted (verifier-checked, signed in
  future). The ring buffer is one-directional (kernel → userspace).
- **Agent ↔ operator:** the CLI is a thin client; all authority and state live
  in the daemon.
