# ADR 0002 — Detection is behavioral, not a rulebook

**Status:** accepted · **Date:** 2026-11-02

## Context
The whole premise of Phage is surviving vulnerabilities that do not exist yet.
A detection layer built from hardcoded `if parent == "nginx" then alert` rules
can only ever catch what its author already imagined. It also rots: every new
service or deployment needs new rules, and attackers study the rules to slip
between them.

## Decision
Detection is a **behavioral anomaly pipeline**, never a set of hand-written
attack conditions:

```
features (measure)  →  scorer (compare to learned baseline)  →  verdict (score + reasons)
```

- `internal/analysis/feature` only **measures** (did root appear? was there a
  session? how deep is the lineage?). It makes no judgement.
- `internal/analysis/baseline` is the host's **learned** notion of normal.
- `internal/analysis/scorer` outputs a **score plus explanation** — the surprise
  of the observed features relative to the baseline.

## What "no if/else" means precisely
It bans **hardcoded detection logic** — deciding "malicious" from fixed
conditions on raw events. It does **not** ban all conditionals: the policy layer
still uses thresholds and a mode switch to decide *how to respond*. Those are
operational knobs (data, config), not the detection itself.

## Why this is the right call
- **Catches the unknown.** It flags the *effect* of an exploit (an impossible
  path to root) without knowing the exploit.
- **Adapts per host.** "Normal" on a database box differs from a web box; the
  baseline learns each rather than us guessing.
- **Explains itself.** Every verdict carries reasons, which is non-negotiable
  before we ever let it act (enforce mode).

## Consequences
- We must solve **false positives** with the learn→alert→enforce ladder and a
  baseline that is honestly neutral until well-sampled (`Surprise` returns 0 for
  unlearned features).
- The model starts simple (frequency-based surprise) and is expected to grow
  (co-occurrence, time decay, sequence models). The seam (`scorer.Scorer`) keeps
  that growth from touching anything else.
