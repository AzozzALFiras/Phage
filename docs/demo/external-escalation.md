# Demo: catching a real external attack → root escalation

This is the end-to-end scenario Phage is built for: an attacker comes in over
the network through a vulnerable service, lands as an unprivileged service user,
and escalates to root. Phage catches the escalation **behaviorally** — it has no
signature for the vulnerability, the exploit, or the setuid binary involved.

## Setup (lab, on a server we own)
- A deliberately vulnerable web app (shell command injection) runs as the
  unprivileged `webapp` user under systemd — so it has **no login session**
  behind it, exactly like a real network daemon.
- A setuid-root binary on the box stands in for any local privilege-escalation
  primitive an attacker might abuse.
- Phage runs in `learn` mode first to build the host baseline, then switches to
  `alert`.

> The vulnerable app is lab-only and is stopped/disabled after the demo. Do not
> expose a command-injection endpoint on a real network.

## The attack (from a separate machine, over the internet)
```sh
# 1. foothold: command injection runs as the webapp service user
curl "http://SERVER:8080/ping?host=;id"
#    => uid=999(webapp) ...   (remote code execution)

# 2. escalation: the injected command runs the setuid-root binary
curl "http://SERVER:8080/ping?host=;/opt/phagelab/rootshell"
```

## What Phage reported
The escalation surfaced immediately, with an explanation and a high score:

```
CRITICAL score=0.83 action=notify pid=5232 comm="rootshell" parent="sh"
  uid=999->euid=0 interactive=false ::
    an unprivileged process raised itself to root;
    raised to root with no login session behind it (never seen on this host);
    privilege change with no interactive session behind it;
    priv.parent_comm_id ... unusual for this host (surprise 1.00)
```

The command-injection foothold itself (a network service spawning `sh`/`ping`
with no session) also drew lower-scored notices — a bonus, not the target.

## Why this matters
- **No signature.** Phage never knew the CVE, the payload, or the binary. It
  scored the *effect* — an unprivileged process reaching root with no login
  session behind it — against what it had learned was normal for this host.
- **Provenance is the signal.** During learning, every privilege raise on this
  host had a login session behind it. The attack's raise had none, a
  combination the baseline had **never seen** → maximal surprise.
- **Explainable.** The verdict reads in plain language, which is the
  precondition for ever letting it act (enforce mode, M2).

## Enforcement: it doesn't just alert, it contains

Re-run in `enforce` mode, the same escalation is **frozen in place** the instant
it is detected:

```
CRITICAL score=0.83 action=freeze pid=6518 comm="rootshell" uid=999->euid=0 ::
    an unprivileged process raised itself to root;
    raised to root with no login session behind it (never seen on this host)
CONTAIN pid=6518 comm="rootshell" FROZEN (process tree quarantined, reversible)
```

Verified on the box: the process reached `euid 0` (`/proc/<pid>/status` →
`Uid: 999 0 0 0`) but sits in a dedicated cgroup with `cgroup.freeze=1` — it
cannot run. Containment is a **freeze, not a kill**, so a false positive is
released with `cgroup.freeze=0` rather than leaving a dead process. Every action
is written to an append-only audit trail with its reason.

## Honest caveats
- On this quiet host the baseline also learned "activity is interactive" because
  learn-phase traffic came through SSH; on a busy server the robust
  discriminator is the *raise-with-no-session* feature plus parent novelty, not
  interactivity alone.
- This is `alert` mode. Containment (freeze the process tree) is M2.
