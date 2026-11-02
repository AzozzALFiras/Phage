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

## Containment safety — what enforce will NEVER freeze
Learned the hard way: an early enforce build froze the shell of an incoming SSH
login (a program combination its baseline had never seen) and locked the server
out. Autonomy must never be able to wedge the machine or lock out the operator,
so containment has hard guardrails that sit *above* the score (`containmentSafe`
in `internal/agent/app`):

1. **Never freeze an interactive login session.** Anything with a login
   session behind it (loginuid set) is the admin path and is exempt — Phage
   alerts, never contains, there.
2. **Never freeze the control plane.** `sshd`, `systemd`, `init`, `login`,
   `getty`, `systemd-logind`, `dbus-daemon`, and `phaged` itself (and their
   direct children) are never frozen.
3. **Only contain an actual privilege escalation.** A generic exec-pattern
   anomaly alerts but never freezes; freezing is reserved for an unprivileged
   process that reached root with no session — the high-confidence signal.

These are deliberate hardcoded rules, not learned behaviour: safety of the
control plane is not something to infer from a baseline.

## Why this ordering is non-negotiable
An anomaly model is only as trustworthy as its baseline. The ladder guarantees
Phage can never act on a baseline it has not earned. It also gives operators a
safe, legible path to adoption — exactly what gets a security tool deployed
rather than uninstalled.

See `internal/policy/mode` and `internal/policy/engine` for the implementation.
