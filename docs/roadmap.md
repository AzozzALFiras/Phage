# Roadmap

Direction, not dates. Each milestone ships something usable and demonstrable.

## M0 — Scaffolding ✅
Architecture, pipeline seams, docs, buildable Go skeleton. (You are here.)

## M1 — Privilege-escalation detection (learn + alert)
The first real value.
- [x] `creds.bpf.c` hooking `commit_creds` — compiles with CO-RE and passes the
      kernel verifier on the target (Ubuntu 26.04, kernel 7.0, x86_64).
- [x] Stream events to userspace: sensor loader (`cilium/ebpf`) + ring-buffer
      reader + decode. Verified live on the test server — real credential
      transitions captured end to end (pid, comm, uid/euid, caps).
- [x] Measure transition *direction*: a non-root process raising to root vs
      root dropping privileges. Direction is a feature, not a rule.
- [x] Enrichment: process lineage + session provenance (audit loginuid, tty).
      Live-verified — the same setuid escalation is told apart by provenance:
      spawned by systemd with no login session vs run inside an admin login.
- [x] Baseline persistence: atomic JSON snapshot behind a pluggable
      `store.Repository` seam (embedded KV can drop in later).
- [x] Learn mode end-to-end; alert mode scoring with explained verdicts and the
      policy engine choosing the response.
- [ ] Deterministic pipeline tests from recorded fixtures.
- **Demo — done.** A real HTTP attack from a remote machine exploited a lab web
  app (command injection) to run as `webapp`, then escalated to root via a
  setuid binary. Phage flagged the escalation **CRITICAL (score 0.83)** with the
  reason "raised to root with no login session behind it (never seen on this
  host)", while legitimate raises inside a login session stayed silent. See
  [docs/demo/external-escalation.md](demo/external-escalation.md).

## M2 — Enforcement (contain)
- [ ] Reversible containment: cgroup freeze of the offending process tree.
- [ ] Audit log with the triggering reason.
- [ ] Threshold tuning and a `phage` CLI to inspect/override.

## M3 — Blast-radius containment (auto-jail)
- [ ] Learn a service's normal syscall/file/network behavior.
- [ ] Generate and apply a least-privilege profile (seccomp/eBPF LSM).
- [ ] "Learn → enforce" per service, same ladder philosophy.

## M4 — Self-healing
- [ ] Automated response playbooks (isolate network, restart clean, roll back).
- [ ] Recovery to a known-good state.

## Model evolution (crosscutting)
Frequency surprise → co-occurrence → time decay → sequence/graph models, all
behind the fixed `scorer.Scorer` seam. See
[design/analysis-engine](design/analysis-engine.md).

## Later
Tamper-resistance, signed eBPF, multi-host aggregation, a fleet view.
