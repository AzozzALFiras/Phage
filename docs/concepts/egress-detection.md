# Egress detection (reverse shells and C2)

An exploit gets code running. The next thing that code almost always does is
**reach back out** — a reverse shell to the attacker, a beacon to a C2 server,
or a request to pull down the next stage. Like privilege escalation, this is an
*effect* shared by nearly every intrusion, independent of the vulnerability that
started it. Phage watches for it.

## The one chokepoint
Every outbound TCP connection on Linux passes through **one** kernel function:
`tcp_connect`. Both IPv4 and IPv6 active opens reach it once the destination is
set. Hooking it with eBPF (fentry) means we see *every* dial-out — we cannot be
bypassed by a choice of syscall, library, or language. UDP and raw sockets are a
known gap (see below).

## The question we ask (novelty, not blocklist)
Not "is this IP on a threat feed?" — feeds are always behind, and an attacker's
box is new. Instead:

> Does this program, on this host, ever make outbound connections like this —
> and is there a session behind it?

A web server's normal egress is tiny and stable: its database, a cache, a
package mirror, an API or two. It does **not** normally open a shell that dials a
random host on port 4444. A reverse shell is a process with *no history of
egress at all* suddenly connecting out — the sharpest signal we have.

## The signals (features)
Measured in `internal/analysis/feature` (the `Network` extractor), judged against
the baseline:

| Feature | What it captures |
|---|---|
| `net.egress_comm_id` | which program is making the connection (stable id) |
| `net.egress_comm_port_id` | the program→destination-port pair |
| `net.egress_port` | the destination port on its own |
| `net.egress_interactive` | is there a login/SSH session behind it |

None is a rule. The baseline turns each into "expected" or "surprising" for this
host: `curl` reaching port 443 may be normal; `sh` — spawned by `php-fpm` — doing
the same is a never-seen program egressing with no session, which scores high.

## Why the destination IP is *not* a feature
Addresses are deliberately left out of the learned model. IPs are too
high-cardinality — every new mirror, every CDN rotation, every fresh API host
would look "novel", drowning the signal in false positives. Phage learns the
**program and the port**, which are stable, and keeps the concrete destination in
the human-readable reason and the audit trail (`-> 203.0.113.5:4444`) so an
operator always knows *where* without the model choking on *where*.

## Response: alert, don't freeze (yet)
Egress anomalies **alert**; they do not trigger containment on their own. The
`containmentSafe` guardrail only ever freezes an actual privilege escalation,
because network novelty is more prone to false positives than a no-session root
transition. A reverse shell is usually caught twice anyway — once as a novel
exec pair (`php-fpm → sh`) and again as novel egress (`sh → :4444`) — and the
escalation that often follows is what gets contained.

## Known gaps (stated plainly)
- **UDP / ICMP / raw sockets.** `tcp_connect` is TCP only. DNS-tunnelling C2 and
  UDP beacons are not yet observed; a separate hook is future work.
- **Loopback is dropped in-kernel.** Connections to `127.0.0.0/8` are ignored to
  keep the hot path and the baseline clean. A localhost-pivot is a blind spot we
  accept for now.
- **Blending in.** A beacon to port 443 from a program that *already* talks to
  443 will not stand out on the port alone — which is why the program identity
  and session provenance matter more than the port.

## Sensor backing this module
- `bpf/programs/sensors.bpf.c` — the `tcp_connect` fentry hook (`on_tcp_connect`),
  sharing the one ring buffer with the creds and exec sensors.
