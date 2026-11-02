# Data flow: one event, end to end

Follow a single privilege change through the pipeline. The running example is a
web process that becomes root through an exploit.

### 1. Kernel sensor fires
Every credential change in Linux passes through `commit_creds`. The eBPF
program (`bpf/programs/privilege/creds.bpf.c`) is attached there, so the
transition to `euid=0` cannot be missed, whatever syscall or bug caused it. It
writes a fixed-size `phage_event` into the ring buffer.

### 2. Decode
`internal/sensor/decode` reads the raw bytes and produces an
`event.model.Event` — still minimal: pid, comm, old/new uid, timestamp.

### 3. Enrich
`internal/enrich` adds the context that makes judgement possible:
- **process**: the ancestry chain (`www-data → sh → <exploit> → root`).
- **identity/session**: is there a login/SSH session behind this pid? a TTY?
- **container**: cgroup/container id, if any.

For our example, enrichment finds **no interactive session and no TTY** — the
root transition descends from a network-facing service.

### 4. Analyse
`internal/analysis/feature` measures the event into a `Vector`:
`gained_root=1`, `interactive_origin=0`, `has_tty=0`, `lineage_depth=4`, …

`internal/analysis/scorer/behavioral` compares each value against the
`baseline.Profile`. On a normal host, root transitions almost always carry
`interactive_origin=1`; the value `0` is therefore highly *surprising*. The
scorer returns a high `Score` and a `Reason`:
> "privilege change with no interactive session behind it"

Note what did **not** happen: no rule named nginx, www-data, or any exploit. The
baseline decided this was abnormal.

### 5. Decide
`internal/policy/engine` sees the score under the current mode:
- **learn**: record only, update the baseline.
- **alert**: emit the alert with its reason.
- **enforce**: score ≥ contain threshold → `Freeze` action (reversible).

### 6. Respond
`internal/response` applies the action and writes an audit record carrying the
reason. In enforce mode the process tree is frozen, stopping the exploit mid-run
while a human reviews — without killing anything irreversibly.
