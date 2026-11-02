# Privilege-escalation defense (the first module)

Phage starts at the worst outcome: a process gaining **root**. If we can catch
the moment privilege is obtained through an abnormal path, we catch a huge class
of exploitation regardless of the bug that enabled it.

## The one chokepoint
Whatever the syscall or exploit, a Linux privilege change ends at **one** kernel
function: `commit_creds`. Hooking it with eBPF means we observe *every*
transition to root — we cannot be bypassed by picking a different syscall.

## The question we ask (provenance, not pattern)
Instead of "does this match a known exploit?", Phage asks:

> Is this path to root consistent with how root is *normally* reached on this
> host — and is it backed by a real, authenticated interactive session?

Legitimate root almost always has **provenance**: an admin over SSH, a login
shell with a TTY, a known service manager, a scheduled job. Exploited root
usually has **none** of that — it descends from a network-facing service with no
session and no terminal.

## The signals (features)
Measured in `internal/analysis/feature`, judged against the baseline:

| Feature | What it captures |
|---|---|
| `priv.gained_root` | did the process obtain root at all |
| `priv.interactive_origin` | is there a login/SSH session behind it |
| `priv.has_tty` | is there a controlling terminal |
| `priv.lineage_depth` | how long the ancestry chain is |
| `priv.parent_comm_id` | who the immediate parent is (stable id) |

None of these is a rule. Each is a measurement the baseline turns into
"expected" or "surprising" for this specific host. On a web server, root with
`interactive_origin=0` is deeply surprising; on a CI runner it might be normal —
and the baseline, not us, knows the difference.

## "Outside root and SSH"
This is the case you care about most: a privilege gain that did **not** come
through the legitimate root/SSH door. In feature terms that is
`interactive_origin=0` and `has_tty=0` on a `gained_root=1` event — which the
baseline of a normal host scores as highly anomalous. That is provenance-based
detection, not a hand-written condition.

## Sensors backing this module
- `bpf/programs/privilege/creds.bpf.c` — the `commit_creds` hook.
- `bpf/programs/privilege/exec.bpf.c` — execve, for lineage and the new image.
- `bpf/programs/privilege/capability.bpf.c` — capability grants (root-equivalent
  powers without uid 0).
- `bpf/programs/access/ssh.bpf.c`, `tty.bpf.c` — to establish session provenance.
