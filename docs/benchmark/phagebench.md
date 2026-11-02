# PhageBench — an honest evaluation

Security tools love to publish detection rates. Almost none publish their
**false-positive rate** next to it, because that number is where behavioral tools
get embarrassing. PhageBench measures both, on one reproducible harness
([`scripts/bench/phagebench.sh`](../../scripts/bench/phagebench.sh)), and reports
whatever comes out — including the parts that need work.

## What it measures
1. **Detection rate** — of a labeled attack corpus, how many Phage flags, counting
   a hit only when the *signal-specific* reason fires (not the incidental "a
   service spawned a novel program" alert every launch raises).
2. **False positives** — alerts raised while only **benign** work runs, after
   learning, expressed as alerts per window (and extrapolated per host/day).

## Methodology
On one test host (Ubuntu, kernel 7.0.0-30, x86_64), with **no signatures**:
1. **Learn** a baseline from a benign workload (admin tools, web serving, outbound
   HTTPS, a privileged op *with* a session, user-namespace use) — ~60 iterations.
2. **Detection:** one `alert`-mode agent; run each attack once; record whether its
   specific detector fired and at what score.
3. **False positives:** with the same frozen baseline, run a fresh 60-second
   benign-only workload and count every alert — each is a false positive.

## Results (this run)

### Detection — 7 / 7
| Attack | Result | Score |
|---|---|---|
| Privilege escalation (no-session root) | ✅ detected | 0.65 |
| Fileless / in-memory execution | ✅ detected | 1.00 |
| LD_PRELOAD dynamic-linker hijack | ✅ detected | 1.00 |
| Reverse-shell egress | ✅ detected | 1.00 |
| Persistence (webshell + `authorized_keys`) | ✅ detected | 0.57 |
| Kernel-enabling op (user namespace) | ✅ detected | 0.74 |
| Self-tamper (ptrace the agent) | ✅ detected | 1.00 |

Every attack was caught by its own behavioral signal, against a baseline that had
never seen it. Scores vary honestly: fileless/LD_PRELOAD/egress/self-tamper are
near-unforgeable (1.00); the webshell is 0.57 because this host *does* legitimately
write PHP, so only the unusual writer stands out — the model being correctly
relative to the host, not a fixed rule.

### False positives — 7 in 60 s, and what they actually were
```
false-positive programs (comm):
  2 tail   2 sshd-session   2 sshd-auth   1 unix_chkpwd
  1 uniq   1 sort           1 sleep       1 awk
```
This is the honest, important part. **None of the false positives were attacks
misclassified.** Every one was a *benign system program the short baseline never
observed* — SSH re-authentication (`sshd-session`/`sshd-auth`), PAM's
`unix_chkpwd`, and ordinary shell text tools — flagged by the exec-novelty
detector as "a parent→child pair never seen on this host."

That is the central, honestly-stated tradeoff of novelty-based exec detection: on
an **immature baseline it flags benign-but-unlearned programs**. The naive
extrapolation (7 / 60 s ≈ 10,000 alerts/host/day) is what a *frozen 60-second
baseline* would produce forever — which is exactly why Phage ships a
`learn → alert → enforce` ladder and advises a **multi-day** learn that covers the
host's full ambient activity (cron cycles, log rotation, logins, backups). The
number is a function of baseline completeness, not of the attack surface.

## Threats to validity (stated plainly)
- **Single host, short baseline.** 60 iterations is deliberately minimal; it makes
  the FP behavior visible but is not a production baseline.
- **Synthetic corpus.** The attacks are representative PoCs, not a live malware
  zoo; the benign workload is scripted, not a real production mix.
- **No competitor numbers yet.** The harness is built to also run Falco/Tracee on
  the same corpus; that comparison is future work and will be published with the
  same honesty, including where Phage loses.
- **Detection attribution** counts a signal-specific reason; the incidental
  launch-time exec alert is excluded, so the 7/7 is not inflated by it.

## What this benchmark drives
The FP result makes the priorities concrete and measurable:
1. **Cut exec-novelty false positives** — co-occurrence and time-decay models
   behind the `scorer.Scorer` seam, and learning/allowlisting ambient system
   programs (PAM, sshd re-auth) so they stop surprising a mature baseline.
2. **Baseline maturity as a first-class metric** — report FP as a function of
   learn duration, and refuse `enforce` until the baseline is demonstrably mature.
3. **Enable-op cold start** — a host that never performs an enabling op has no
   baseline for it; decide whether such ops should default to suspicious.

Re-run it yourself: `sudo ./scripts/bench/phagebench.sh`.
