# Demo: the agent defends itself (anti-blinding)

A live run on the test server (kernel 7.0) showing Phage detect an attack on
**itself**. The dominant 2025 evasion against host agents is *blinding* — rather
than defeat the detections, the attacker kills, stops, ptraces, or unhooks the
security agent so its telemetry goes dark. A self-defending agent has to watch
its own sensory nerves.

## The signal
At startup the agent writes its own pid into a kernel map, arming two sensors:
- `tp_btf/signal_generate` — a lethal/stop signal (`SIGKILL`/`SIGSTOP`/`SIGTERM`/
  `SIGINT`/`SIGQUIT`) aimed at the agent by anything other than its service
  supervisor.
- `fentry/ptrace_attach` — any process attaching a debugger/injector to the agent.

These are scored outside the learned baseline on purpose: tampering with the
monitor is self-evidently hostile and must surface even on an empty baseline. The
only benign case is the service manager (`systemd`) sending a stop signal during
shutdown, which is allowlisted. A **dead-man's-switch** backs it up: if a
previously-active event stream suddenly goes silent, the sensors may have been
detached — something a rule engine structurally cannot detect, because it reasons
about events that happen, not their absence.

## The run (alert mode)
```
agent pid=10698, armed for self-defense

>>> ATTACK 1: a process attaches ptrace to the agent
CRITICAL score=1.00 comm="ptrace_poc" :: attempt to tamper with the Phage agent:
    ptrace by "ptrace_poc" (pid 10710) — monitor blinding/kill attempt
CRITICAL score=1.00 comm="ptrace_poc" :: attempt to tamper with the Phage agent:
    SIGSTOP by "ptrace_poc" (pid 10710) — monitor blinding/kill attempt

>>> ATTACK 2: a non-supervisor shell sends SIGKILL to the agent
agent process alive now? killed
```

The ptrace attach was flagged **CRITICAL** — twice, because attaching also
delivers a `SIGSTOP`, which the signal sensor caught independently — while the
agent kept running. Note the honest part: a direct `SIGKILL` races the agent's
own teardown; if the agent dies before it drains that event, the kill itself is
not logged — which is exactly what the dead-man's-switch exists to cover (the
sudden telemetry silence is the alert).

## Honest ceiling
Phage sees everything up to an attacker who is *already more privileged than
Phage* — a malicious kernel module, a `CONFIG_BPF`-disabling ring-0 actor, or
someone who unloads the agent's eBPF before it can react to a `SIGKILL`. The
honest claim is: Phage makes blinding **loud and expensive**, not impossible.
True survive-the-root tamper-resistance (an `lsm/task_kill` that *denies* the
kill, agent binary/map write-protection via BPF-LSM, a watchdog that restarts it)
is the enforcement follow-up to this detection. See `bpf/programs/sensors.bpf.c`
(`on_signal_generate`, `on_ptrace_attach`) and `respondSelfDefense` in
`internal/agent/app`.
