# Demo: per-process network quarantine (sever C2, don't kill)

A live run on the test server (kernel 7.0) showing Phage's reversible **isolate**
rung: when a service dials out like a reverse shell / C2 beacon, Phage severs that
service's outbound network — **without killing it**. The process keeps running
(so forensics and attribution survive), but its channel to the attacker is dead.

## Why a middle rung
Killing (`SIGKILL`, Tetragon-style) destroys the process and the evidence and
tips the attacker off; freezing pauses the whole tree. Network quarantine sits
between alert and freeze: the process lives and can be inspected, but it cannot
reach its C2. It is implemented with `cgroup/connect4`+`connect6` eBPF programs
attached to the offending process's **cgroup** (its service), so every process in
it — including the short-lived children a beacon forks per connection — is denied
new egress (loopback excepted). Detaching restores the network (`phage thaw`).

## The run (enforce mode)
A service beacon dials `1.1.1.1:53` every two seconds:
```
# Phage
CRITICAL score=1.00 comm="bash" interactive=false ::
    an outbound connection from a program that has never egressed on this host
    (-> 1.1.1.1:53)
CONTAIN pid=... comm="bash" ISOLATED (egress severed, process alive, reversible)

# the beacon's own log
beacon iter 1: CONNECTED      <- the first dial, which Phage detected
beacon iter 2: BLOCKED        <- Phage severed the service's egress
beacon iter 3: BLOCKED
beacon iter 4: BLOCKED        <- ... C2 dead, but the process never stopped
...
```
The first dial got out (and gave Phage the signal); from the next one on, every
connection was refused by the kernel — while the beacon process kept running the
entire time.

## Notes
- **Granularity is the cgroup (service), not a single pid** — deliberately, so a
  beacon that forks a fresh process per connection can't evade it. A compromised
  service losing all egress is the right containment.
- **Reversible:** `phage thaw <pid>` detaches the programs and restores the
  network; the agent also lifts all isolation on shutdown.
- **New connections** are what's denied; cutting an already-established long-lived
  socket needs a `cgroup_skb/egress` drop (future). Beacons that reconnect — the
  common case — are stopped.
- Safe: refuses to attach to the root cgroup, so it can never cut the whole host's
  network.

Implements the `isolate` action. See `bpf/programs/netquarantine.bpf.c` and
`internal/response/netquarantine`.
