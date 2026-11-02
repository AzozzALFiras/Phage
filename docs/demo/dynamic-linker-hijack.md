# Demo: catching a dynamic-linker hijack (LD_PRELOAD)

A live run on the test server (kernel 7.0) showing Phage flag a program launched
with a **dynamic-linker hijack** in its environment — `LD_PRELOAD`, `LD_AUDIT`,
or `GLIBC_TUNABLES` — the way an attacker forces a chosen `.so` (or a dangerous
tunable) into a legitimate program for injection, persistence, or privilege
escalation (GLIBC_TUNABLES was the core of the 2023 "Looney Tunables" LPE).

## The signal
Phage's exec sensor reads a bounded window of the new process's environment
in-kernel (via `mm->env_start`) and sets a flag if it carries one of those
variables. Most service execs never do, so it is a near-zero-false-positive
"red flag": the scorer floors the verdict on it when novel for this host, so it
is caught even if the attacker disguises the program name and parent — and it
stays behavioural (a host that uses `LD_PRELOAD` legitimately learns it and the
flag floors nothing).

## The run
Baseline learned normal execs (none using `LD_PRELOAD`), then in `alert` mode:

```
# CONTROL — a normal program, no preload
id
   → no alert

# ATTACK — the same program, launched by a service with LD_PRELOAD set
systemd-run -p User=nobody  bash -c 'LD_PRELOAD=/tmp/evillib.so id'
```

## The result
```
CRITICAL score=1.00 comm="id" parent="bash" interactive=false ::
    program launched by a service with no interactive session;
    launched with a dynamic-linker hijack in its environment
    (LD_PRELOAD / LD_AUDIT / GLIBC_TUNABLES)
```

The normal `id` was silent; the preloaded one was flagged **CRITICAL**, naming
the technique. The `.so` need not even load successfully — the hijack is visible
in the environment at exec.

## Known bound
The environment is scanned for the first 512 bytes (an eBPF verifier
complexity limit on the in-kernel scan). In a service context — the realistic
place an exploit runs — the environment is small and the hijack var appears
early, so this covers the case that matters; a var buried past 512 bytes of a
very large interactive environment is a documented gap. See the exec sensor in
`bpf/programs/sensors.bpf.c` and `FeatExecLdPreload` in
`internal/analysis/scorer/behavioral`.
