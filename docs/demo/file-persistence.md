# Demo: catching persistence by write novelty

A live run on the test server (Ubuntu, kernel 7.0, x86_64) showing Phage detect
an intruder digging in — a webshell drop and a backdoored `authorized_keys` —
with **no signature** for the filename, the content, or the program.

## Setup
1. **Learn.** Phage ran in `learn` mode while a deploy pipeline did representative
   work: 20 legitimate writes of `.php` files into the web root
   (`cp → /var/www/html/app_N.php`), run as transient services. So "a deploy tool
   writing PHP into the web root" is firmly normal on this host.
2. **Alert.** Phage switched to `alert` mode against that baseline.

## The events
A legit control and a two-part persistence attack, back to back — all spawned by
`systemd-run`, so none has an interactive session behind it (the shape of code
running from an exploited service, not an admin at a keyboard):

```sh
# CONTROL — the deploy writes another PHP file. Baseline-normal.
systemd-run cp seed.php /var/www/html/app_new.php

# ATTACK — a service-spawned shell drops a webshell AND backdoors an SSH key.
systemd-run bash -c '
  echo "<?php system(\$_GET[0]); ?>" > /var/www/html/uploads/shell.php
  echo "ssh-ed25519 AAAA... attacker@evil" >> /home/demo/.ssh/authorized_keys'
```

(The key lands in a throwaway `/home/demo` — the demo never touches real keys.)

## The result
The control produced **no alert**. The attack's two writes were both flagged:

```
CRITICAL score=0.83 comm="bash" parent="systemd" interactive=false ::
    a write to a persistence/credential file class rarely seen on this host;
    a program wrote a persistence/credential file class it has never written
    on this host (wrote /home/demo/.ssh/authorized_keys)

ALERT    score=0.57 comm="bash" parent="systemd" interactive=false ::
    a program wrote a persistence/credential file class it has never written
    on this host (wrote /var/www/html/uploads/shell.php)
```

Phage had no signature for any of this. It flagged the *behaviour*: a program
with no history of writing these artifact classes doing so, with no session
behind it. The concrete path is carried in the reason and the audit trail; the
filename is deliberately **not** part of the learned model — see
[file-persistence-detection](../concepts/file-persistence-detection.md).

## Why the webshell scored lower than the key (and why that's correct)
This is the behavioral model earning its keep. This host **legitimately writes
PHP into the web root** during deploys, so the `web_php` *class* is established —
only the unusual **writer** (`bash`, never seen writing PHP here) stands out, for
a moderate `0.57`. Nothing *ever* writes `authorized_keys` here, so that write is
novel on both the class *and* the writer, scoring `0.83`. The same webshell drop
on a host that never serves PHP would score critical. Phage does not alert on
"a file was written" — it alerts on a write that is *new for this host*.

## The control stayed silent
`cp` writing another `.php` matched the baseline on every feature — established
program, established class, established (program→class) pair — so it scored near
zero. A tool that cried wolf on every deploy would be turned off in a day; the
discrimination is the whole point.

## Caught more than once
In the same run the **exec** sensor independently flagged the service-spawned
`bash` (a `systemd → bash` pair never seen on this host, `0.76`) — the RCE shape
that *precedes* the persistence. A real intrusion trips several of Phage's
signals at once: the exec that lands the foothold, the egress that phones home,
and the file writes that make it survive a reboot. Defence in depth from one
learned baseline.

## Response
All verdicts here are `notify` (the run was in `alert` mode). Even in `enforce`
mode, persistence writes alert but are never auto-frozen: the `containmentSafe`
guardrail only contains an actual privilege escalation, so Phage never kills a
process mid-write on a file-novelty signal alone.
