# Demo: catching fileless (in-memory) execution

A live run on the test server (kernel 7.0) showing Phage detect a program that
runs **entirely from memory, with no file on disk** — the technique sophisticated
malware uses to evade every scanner that inspects files.

## The technique
An attacker with a foothold does not drop an ELF on disk (where an integrity
scanner or AV would find it). Instead they:
1. `memfd_create(...)` — make an anonymous file that exists only in memory,
2. write the payload ELF into it,
3. `execveat(fd, "", ..., AT_EMPTY_PATH)` — run it straight from the fd.

Nothing is ever written to disk. `/proc/<pid>/exe` points at
`/memfd:<name> (deleted)`, and the executable's inode has **zero directory links**
(`i_nlink == 0`). The same is true of the run-then-unlink variant (copy to disk,
open, `unlink`, exec the fd).

## The signal (behavioural, not a path match)
Phage's exec sensor reads the executed image's link count in-kernel. A legitimate
program always runs from a linked file (`i_nlink ≥ 1`); `i_nlink == 0` means the
image has no name on disk. That is the signal — it holds even when the attacker
names the memfd after a trusted program, and it catches the unlink variant too.

## The run
Baseline learned normal execs, then in `alert` mode:

```
# CONTROL — a normal on-disk program
/usr/bin/id
   → no alert

# ATTACK — an ELF run from an anonymous memfd named "nginx" (to blend in)
memfd_create("nginx") + write + execveat(AT_EMPTY_PATH)
```

## The result
```
CRITICAL score=0.87 comm="memfd:nginx" parent="bash" ::
    a program was spawned in a parent->child combination never seen on this host;
    executed from an anonymous in-memory file (fileless) — no program on disk
```

The normal `id` was silent; the fileless process was flagged **CRITICAL**, naming
the reason. No file was written to disk at any point, so a disk-based scanner has
nothing to find — Phage caught it on behaviour alone.

## Why it weighs heavily
Fileless execution is almost never legitimate, so the signal is near-zero false
positive and carries the heaviest exec weight. Even if the attacker forges a
normal-looking process name and a plausible parent, the missing on-disk link
still betrays it. See `internal/analysis/scorer/behavioral` (`FeatExecFileless`)
and the exec sensor in `bpf/programs/sensors.bpf.c`.
