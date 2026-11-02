# Phage documentation

Start here. The docs are split so each folder holds one concern.

## Architecture
- [overview](architecture/overview.md) — the components and how they fit.
- [data-flow](architecture/data-flow.md) — one event, from kernel to response.
- [decisions/](architecture/decisions/) — the *why* behind the big choices (ADRs).

## Concepts
- [threat-model](concepts/threat-model.md) — what Phage defends against, and what it does not.
- [modes](concepts/modes.md) — the learn → alert → enforce ladder.
- [privilege-escalation](concepts/privilege-escalation.md) — the first module, in depth.
- [egress-detection](concepts/egress-detection.md) — catching reverse shells and C2 by egress novelty.
- [file-persistence-detection](concepts/file-persistence-detection.md) — catching webshells, backdoored keys, and cron/unit persistence by write novelty.
- [auto-jail](concepts/auto-jail.md) — learning a least-privilege seccomp profile per service to shrink the attack surface.
- [threats-and-behavioral-defense](concepts/threats-and-behavioral-defense.md) — exploit classes (PHP/Node/Linux/kernel/SQLi/XSS) → host-observable effects → Phage's signals, with honest blind spots.

## Design
- [analysis-engine](design/analysis-engine.md) — features, baseline, scoring, explainability.

## Guides
- [quickstart](guides/quickstart.md) — run it on a server.
- [development](guides/development.md) — build the Go agent and the eBPF sensors.

## [roadmap](roadmap.md)
Where this is going, module by module.
