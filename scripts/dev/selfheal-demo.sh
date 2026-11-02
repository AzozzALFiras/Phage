#!/usr/bin/env bash
# selfheal-demo.sh — live proof of self-healing. An attacker backdoors an SSH
# authorized_keys; Phage (enforce) detects the malicious write and restores the
# known-good file in a moment, keeping the attacker's version as evidence.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/sh-base.json
LOG=/tmp/sh.log
KEYS=/home/demo/.ssh/authorized_keys
QDIR=/var/lib/phage/quarantine

cleanup(){ pkill -x phaged 2>/dev/null; systemctl stop sh-attack.service 2>/dev/null; systemctl reset-failed sh-attack.service 2>/dev/null; rm -rf /home/demo /var/www "$STATE" "$LOG" "$QDIR"; }
trap cleanup EXIT

echo "== set up a legitimate authorized_keys (the known-good state) =="
mkdir -p /home/demo/.ssh /var/www/html; rm -rf "$QDIR"
echo "ssh-ed25519 AAAAC3LEGITIMATEadminkey admin@company" > "$KEYS"
echo "   good authorized_keys:"; sed 's/^/     /' "$KEYS"
echo '<?php ?>' > /tmp/seed.php

echo "== learn a baseline (benign file writes so the file keys are confident) =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1; for i in $(seq 1 20); do cp /tmp/seed.php "/var/www/html/app_$i.php"; ls / >/dev/null; done; sleep 1
kill -INT "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start the agent: enforce + self-heal (snapshots the sentinel set) =="
./bin/phaged -bpf "$OBJ" -mode enforce -state "$STATE" -heal >"$LOG" 2>&1 &
sleep 2
grep -i "self-heal armed" "$LOG" | sed 's/^/   /'

echo ">>> ATTACK: a session-less process backdoors authorized_keys"
systemd-run --quiet --unit=sh-attack bash -c 'echo "ssh-ed25519 AAAAATTACKERbackdoorkey evil@attacker" >> /home/demo/.ssh/authorized_keys'
systemctl reset-failed sh-attack.service 2>/dev/null || true
sleep 2

echo "== Phage verdict + action =="
grep -iE "authorized_keys|SELF-HEALED" "$LOG" | sed 's/^/   /'
echo "== authorized_keys AFTER (attacker key should be gone) =="
sed 's/^/     /' "$KEYS"
echo "== quarantined attacker version (evidence) =="
for f in "$QDIR"/*; do echo "   $f:"; sed 's/^/     /' "$f"; done 2>/dev/null || echo "   (none)"
echo "== done =="
