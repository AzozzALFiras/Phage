# Design: the analysis engine

This is the heart of Phage — the part that must be *intelligent* rather than a
pile of conditions. It is three small, swappable pieces.

```
Event ──► [feature.Extractor] ──► Vector ──► [scorer.Scorer] ──► Verdict
                                                  ▲
                                                  │ reads / updates
                                            [baseline.Profile]
```

## 1. Features (`internal/analysis/feature`)
Pure measurement. An `Extractor` turns an `Event` into a `Vector` — a
`map[string]float64` of named signals. Rules for features:
- **No judgement.** A feature says *what is*, never *what is bad*.
- **Stable keys.** Key names are part of the baseline's on-disk contract.
- **Cheap.** Extraction runs per event.

Categorical values (like a parent command name) are hashed to a stable number
(FNV-1a) so they live in the same numeric vector without a side table.

## 2. Baseline (`internal/analysis/baseline`)
The learned notion of "normal" for *this host*. The first implementation is a
**frequency model**: for each feature key it counts how often each value has
been seen, and exposes:
- `Observe(key, value)` — learn (learn mode only).
- `Surprise(key, value) → 0..1` — how unexpected a value is. It measures
  **novelty, not rarity**: a value seen enough times to be *established* is not
  surprising at all (0), however small its share of all events; a never-seen
  value is maximally surprising (1); in between it ramps. **Unsampled feature →
  0** (neutral), so an empty baseline never invents anomalies. This distinction
  is what keeps high-cardinality features (exec pairs, ports) quiet: a
  probability-share measure (`1 - count/total`) would brand a pair seen hundreds
  of times as surprising simply because the host runs many distinct pairs — a
  flaw caught live in the [egress demo](../demo/egress-detection.md).
- `Samples(key)` — confidence; lets callers distinguish "confidently normal"
  from "not yet learned". A feature below `minConfidentSamples` has its
  contribution scaled down, so a fresh agent never raises confident alerts.

### Planned evolution (seam stays fixed)
1. **Co-occurrence** — not just "is this value normal" but "is this *combination*
   normal" (root + no-session together).
2. **Time decay** — recent behavior weighs more; stale patterns fade.
3. **Continuous distributions** — for numeric features like lineage depth.
4. **Sequence / graph models** — model the *shape* of normal process trees; this
   is where ML slots in, behind the same `scorer.Scorer` interface.

## 3. Scorer (`internal/analysis/scorer`)
The single `Scorer` interface: `Score(Vector) → Verdict`. The first
implementation, `behavioral.Anomaly`, combines per-feature surprise with weights
(provenance features weigh most) into a normalized score, and records a `Reason`
for each surprising feature so the verdict is always explainable.

Because everything upstream and downstream depends only on this interface, the
model can go from frequency counting to a neural sequence model without changing
a single sensor, enricher, or response.

## Explainability is a requirement
A `Verdict` is a score **and** reasons. Nothing enters enforce mode without a
reason a human can read — see [ADR 0002](../architecture/decisions/0002-analysis-not-ifelse.md)
and [modes](../concepts/modes.md).
