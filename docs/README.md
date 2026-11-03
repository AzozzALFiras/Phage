# Phage documentation

Start here. The docs are split so each folder holds one concern.

## Architecture
- [overview](architecture/overview.md) — the components and how they fit.
- [data-flow](architecture/data-flow.md) — one event, from kernel to response.
- [decisions/](architecture/decisions/) — the *why* behind the big choices (ADRs):
  - [0001](architecture/decisions/0001-language-go-and-ebpf.md) — Go for the agent, C/eBPF for the sensors.
  - [0002](architecture/decisions/0002-analysis-not-ifelse.md) — detection is behavioral, not a rulebook.
  - [0003](architecture/decisions/0003-auto-jail-seccomp.md) — auto-jail generates seccomp, it does not reinvent a sandbox.

## Concepts
- [threat-model](concepts/threat-model.md) — what Phage defends against, and what it does not.
- [threats-and-behavioral-defense](concepts/threats-and-behavioral-defense.md) — exploit classes (PHP/Node/Linux/kernel/SQLi/XSS) → host-observable effects → Phage's signals, with honest blind spots.
- [modes](concepts/modes.md) — the learn → alert → enforce ladder, and the containment guardrails.
- [privilege-escalation](concepts/privilege-escalation.md) — the first module, in depth.
- [egress-detection](concepts/egress-detection.md) — catching reverse shells and C2 by egress novelty.
- [file-persistence-detection](concepts/file-persistence-detection.md) — catching webshells, backdoored keys, and cron/unit persistence by write novelty.
- [auto-jail](concepts/auto-jail.md) — learning a least-privilege seccomp profile per service to shrink the attack surface.

## Design
- [analysis-engine](design/analysis-engine.md) — features, baseline, scoring, explainability.

## Demos — live-verified against real attacks
Each demo is a real run on a test server (kernel 7.0, BPF LSM), with the raw
evidence and a reproducible script.

**Detection**
- [external-escalation](demo/external-escalation.md) — a real external attack → root escalation, frozen the instant it happened.
- [egress-detection](demo/egress-detection.md) — a reverse shell caught by egress novelty.
- [file-persistence](demo/file-persistence.md) — persistence caught by write novelty.
- [fileless-execution](demo/fileless-execution.md) — in-memory (memfd) execution, no program on disk.
- [dynamic-linker-hijack](demo/dynamic-linker-hijack.md) — an `LD_PRELOAD` / linker hijack caught at exec.
- [kernel-enabling-ops](demo/kernel-enabling-ops.md) — catching the exploit *setup* before it escalates.
- [honeytokens](demo/honeytokens.md) — decoy credential files, fused into the kernel sensor.

**Response & resilience**
- [graduated-response](demo/graduated-response.md) — the matrix: least-invasive sufficient action, escalation, reversible lease.
- [network-quarantine](demo/network-quarantine.md) — sever a process's C2 without killing it (the `isolate` rung).
- [self-healing](demo/self-healing.md) — undo an attacker's persistence in milliseconds, keep their copy as evidence.
- [auto-jail](demo/auto-jail.md) — learning a least-privilege jail for a live service.
- [agent-self-defense](demo/agent-self-defense.md) — the agent detects attempts to blind it.
- [tamper-resistance](demo/tamper-resistance.md) — the agent survives an attacker with root (eBPF-LSM).

## Benchmark
- [phagebench](benchmark/phagebench.md) — an honest evaluation: detection rate *and* false-positives together, reproducible with one script.

## Guides
- [quickstart](guides/quickstart.md) — run it on a server.
- [development](guides/development.md) — build the Go agent and the eBPF sensors.

## Direction
- [roadmap](roadmap.md) — where this is going, module by module.
- [future-directions](future-directions.md) — the prioritized R&D map behind the roadmap.
