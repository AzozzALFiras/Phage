# Operating modes: the learn → alert → enforce ladder

The fastest way to kill an auto-response tool is to have it stop something
legitimate once. Phage's defence against that is a strict ladder. A deployment
only climbs when the operator is ready.

```
  learn ─────────────► alert ─────────────► enforce
  observe &            score &              score, notify
  build baseline       notify, no action    & contain
```

## learn
- Observes events and **updates the baseline** only.
- **Never** scores for action, **never** alerts, **never** acts.
- This is where every install starts. The baseline is empty, so everything would
  look anomalous — acting now would be all false positives.
- Stay here at least `learn_window` (default one week) to capture daily and
  weekly rhythms (cron, backups, deploys, maintenance).

## alert
- Scores events against the now-populated baseline and **notifies** on anomalies.
- Still takes **no action** on any process.
- This is the trust-building phase: watch what it flags, confirm the signal is
  real and the noise is low, tune `thresholds.notify`.

## enforce
- Scores, notifies, and **contains**: at/above `thresholds.contain` it acts.
- Default containment is **freeze** (cgroup-freeze the process tree), not kill —
  reversible, so a mistake is recoverable. Kill/isolate are opt-in.

## Why this ordering is non-negotiable
An anomaly model is only as trustworthy as its baseline. The ladder guarantees
Phage can never act on a baseline it has not earned. It also gives operators a
safe, legible path to adoption — exactly what gets a security tool deployed
rather than uninstalled.

See `internal/policy/mode` and `internal/policy/engine` for the implementation.
