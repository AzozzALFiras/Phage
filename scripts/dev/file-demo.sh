#!/usr/bin/env bash
# file-demo.sh — live proof of the persistence (file-write) sensor.
#
# It (1) learns a baseline of LEGIT writes to the web root (a deploy copying
# .php files), then (2) in alert mode runs a persistence attack — a service-
# spawned `bash` dropping a webshell AND appending an SSH key to a demo
# authorized_keys — plus a legit control deploy. The attack writes a
# program->artifact-class pair the host has never seen; the control repeats an
# established one. Only the attack should fire.
#
# Safety: never touches /root/.ssh. The demo key lands in a throwaway /home/demo.
set -euo pipefail
cd /root/phage

OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/phage-files.json
LOG=/tmp/phage-alert.log
WEBROOT=/var/www/html
DEMO_HOME=/home/demo

echo "== setup =="
rm -f "$STATE" "$LOG"
mkdir -p "$WEBROOT/uploads" "$DEMO_HOME/.ssh"
: > "$DEMO_HOME/.ssh/authorized_keys"
cat > /tmp/seed.php <<'PHP'
<?php /* legitimate application file */ echo "ok"; ?>
PHP

run() { systemd-run --wait --collect --quiet --unit="$1" "${@:2}"; }

echo "== phase 1: LEARN (20 legit deploy writes: cp -> web_php) =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/tmp/phage-learn.log 2>&1 &
LPID=$!
sleep 1
for i in $(seq 1 20); do
	run "phage-deploy-$i" cp /tmp/seed.php "$WEBROOT/app_$i.php"
done
sleep 1
kill -TERM "$LPID"; wait "$LPID" 2>/dev/null || true
grep -c . "$STATE" >/dev/null && echo "baseline written: $(wc -c < "$STATE") bytes"

echo "== phase 2: ALERT (attack + legit control) =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >"$LOG" 2>&1 &
APID=$!
sleep 1

echo "-- control: legit deploy (cp -> web_php, established) --"
run phage-control cp /tmp/seed.php "$WEBROOT/app_new.php"

echo "-- attack: service-spawned bash drops webshell + appends authorized_keys --"
run phage-attack bash -c \
	'echo "<?php system(\$_GET[0]); ?>" > /var/www/html/uploads/shell.php; \
	 echo "ssh-ed25519 AAAADEMOKEYonly-not-a-real-key attacker@evil" >> /home/demo/.ssh/authorized_keys'

sleep 2
kill -TERM "$APID"; wait "$APID" 2>/dev/null || true

echo
echo "================ ALERT LOG (full, unfiltered) ================"
grep -E 'score=|CONTAIN' "$LOG" || echo "(no alerts)"
echo "=============================================================="

echo "== cleanup =="
rm -rf "$WEBROOT" "$DEMO_HOME" /tmp/seed.php
systemctl reset-failed 'phage-*' 2>/dev/null || true
echo "done"
