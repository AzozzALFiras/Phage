# Demo: catching a reverse shell by egress novelty

A live run on the test server (Ubuntu, kernel 7.0, x86_64) showing Phage detect a
service-spawned shell dialing out — the universal shape of a reverse shell or C2
beacon — with **no signature** for the program, port, or destination.

## Setup
1. **Learn.** Phage ran in `learn` mode while the host did representative work:
   shell utilities (`ls`, `grep`, `cat`, `sleep`), and outbound HTTPS with `curl`
   both from an interactive session and from transient services (`systemd-run`),
   so "a service using curl to reach :443" is firmly normal. Resulting baseline:
   ~2,900 exec-pair observations and ~480 egress observations (balanced between
   session and no-session origins).
2. **Alert.** Phage switched to `alert` mode against that baseline.

## The two events
A control and an attack, back to back:

```sh
# CONTROL — a service makes a normal outbound call. Baseline-normal.
systemd-run curl -s https://1.1.1.1/

# ATTACK — a service-spawned shell dials out (reverse-shell shape).
systemd-run bash -c 'exec 3<>/dev/tcp/1.1.1.1/53'
```

## The result
The control produced **no alert**. The attack was the **only** thing flagged:

```
CRITICAL score=0.84 action=notify pid=5643 comm="bash" parent="systemd"
    uid=0->euid=0 interactive=false ::
    an outbound connection from a program that has never egressed on this host;
    net.egress_port=53 is unusual for this host (surprise 1.00);
    an outbound connection to a destination port this program never uses
    (-> 1.1.1.1:53)
```

Phage had never seen a signature for any of this. It flagged the *behaviour*: a
program with no history of egress reaching out, to a port it never uses. The
concrete destination (`-> 1.1.1.1:53`) is carried in the reason and the audit
trail, but the destination address is deliberately **not** part of the learned
model — see [egress-detection](../concepts/egress-detection.md) for why.

## Why the control stayed silent (and why that matters)
`curl` reaching `:443` from a transient service matched the baseline on every
feature, so it scored near zero. The discrimination is the point: Phage does not
alert on "an outbound connection" — it alerts on an outbound connection that is
*new for this host*. A tool that cried wolf on every `curl` would be turned off
in a day.

## A real flaw this demo surfaced (and the fix)
The first run against a thin, ~10-second baseline was noisy: ordinary execs
(`grep`, `sleep`, …) scored ~0.8 alongside the real egress alert. The cause was
in the scoring model, not the sensor: surprise was computed as `1 - count/total`
— a value's *share* of all events. On a host with many distinct exec pairs, even
a pair seen hundreds of times is a small share of the total, so it read as
"surprising."

The model now scores **novelty, not rarity**: a value seen enough times to be
established is not surprising at all, however small its share; only genuinely new
behaviour scores high (see `internal/analysis/baseline`,
`TestSurpriseIsNoveltyNotRarity`). Re-running the *same* attack against the
*same* baseline with the fixed scorer produced exactly one alert — the egress
above — and nothing else. Behavioral detection is only as good as its false-
positive rate; this was a real step toward trustworthy enforcement.
