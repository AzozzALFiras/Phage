# Persistence detection (webshells, backdoored keys, cron)

An exploit gets code running; a beacon phones home. The next thing an intruder
does is **dig in** so a reboot or a killed process doesn't cost them the host — a
webshell dropped in the web root, an SSH key appended to `authorized_keys`, a
cron job or systemd unit planted, `ld.so.preload` pointed at a rootkit. Like
privilege escalation and egress, persistence is an *effect* shared by nearly
every intrusion, independent of the bug that started it. Phage watches for it.

## The one chokepoint
Every file open on Linux passes through **one** LSM hook: `security_file_open`.
Hooking it with eBPF (fentry) means we see every open regardless of syscall
(`open`, `openat`, `openat2`), library, or language. That hook is also on the
kernel's allowlist for `bpf_d_path()`, which resolves the file's full path in
kernel — so we get the real, absolute path, not whatever relative string the
program happened to pass.

We gate in-kernel on two things before an event ever reaches userspace:
1. **Write intent** — `file->f_mode & FMODE_WRITE`. Reads are ignored.
2. **A watched location** — the path falls under a persistence-relevant tree
   (`/etc/cron*`, `/root/`, `/home/`, web roots, `/etc/systemd/`, …).

That second gate is a **scoping filter**, not a detection rule — the kernel
equivalent of choosing to hook `tcp_connect` for egress. It decides what is worth
looking at; it never decides what is *bad*. Over-inclusion only means more for the
baseline to learn.

## The question we ask (novelty, not a blocklist)
Not "is writing `authorized_keys` forbidden?" — plenty of legitimate tooling
writes every path on that list. Instead:

> Does this program, on this host, ever write this *class* of sensitive
> artifact — and is there a session behind it?

A host where a deploy pipeline writes `.php` into the web root learns that as
normal. The same host has *never* seen its `php-fpm`-spawned `sh` write a `.php`,
and has never seen anything append to `authorized_keys`. Those are the novel
program→artifact-class pairs that stand out.

## Class, not filename
The learned key is a **coarse artifact class** (`web_php`, `ssh_authorized_keys`,
`cron`, `systemd_unit`, `ld_preload`, `sudoers`, …), assigned from the resolved
path in userspace (`model.CategorizePath`). Filenames themselves are deliberately
*not* learned: every freshly-named webshell (`x9f3.php`) would otherwise look
novel. Learning the class keeps "this program writes this *kind* of thing" stable
across names, while the concrete path is kept for the reason and audit trail
(`(wrote /var/www/html/uploads/shell.php)`).

## The signals (features)
Measured in `internal/analysis/feature` (the `Filesystem` extractor), judged
against the baseline:

| Feature | What it captures |
|---|---|
| `fs.write_comm_category_id` | the program→artifact-class pair (the dominant signal) |
| `fs.write_category_id` | the artifact class on its own |
| `fs.write_comm_id` | which program is writing (stable id) |
| `fs.write_interactive` | is there a login/SSH session behind it |

None is a rule. The baseline turns each into "expected" or "surprising" for this
host.

## Response: alert, don't freeze
Persistence anomalies **alert**; they do not trigger containment on their own. The
`containmentSafe` guardrail only ever freezes an actual privilege escalation —
file-write novelty is more prone to false positives than a no-session root
transition, and freezing a process mid-write could leave a half-written config.
An intrusion is usually caught several times anyway — a novel exec pair
(`php-fpm → sh`), novel egress, *and* a novel persistence write — and the
escalation that often accompanies it is what gets contained.

## Known gaps (stated plainly)
- **Rename / hardlink drops.** A webshell staged elsewhere and `mv`'d or
  hard-linked into place is not seen by `security_file_open` (no write-open of the
  final path). Hooking `security_inode_rename`/`_link` is future work.
- **Path truncation.** The resolved path is carried in a fixed 160-byte field;
  a pathological depth beyond that truncates, and such a write degrades to the
  coarse `sensitive_write` class rather than a precise one. It is still flagged.
- **Scope is a filter, not completeness.** A persistence location outside the
  watched trees is a blind spot until added. The trees cover the common cases
  (SSH, cron, systemd, web roots, loader/preload, passwd/shadow/sudoers).
- **Blending in.** A write to a class this host writes often, by a program that
  often writes it, will not stand out — which is why the program→class pair and
  session provenance matter more than the class alone.

## Sensor backing this module
- `bpf/programs/sensors.bpf.c` — the `security_file_open` fentry hook
  (`on_file_open`) with `bpf_d_path` resolution, sharing the one ring buffer with
  the creds, exec, and egress sensors.
