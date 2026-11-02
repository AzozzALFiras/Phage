#!/usr/bin/env bash
# matrix-experiments.sh — real, multi-way experiments on the graduated-response
# matrix. Each attack must draw the LEAST-invasive sufficient action; a process
# that climbs the evidence ladder gets escalated; an isolated process that goes
# quiet is auto-released, while a frozen one is HELD for a human.
# Enforce mode, with honeytokens + self-heal + a short (12s) release lease.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/mx-base.json
LOG=/tmp/mx.log
SR="systemd-run --quiet"

cleanup(){
  pkill -x phaged 2>/dev/null
  for u in mx-egr mx-priv mx-persist mx-ns mx-esc mx-deesc mx-hold; do systemctl stop "$u.service" 2>/dev/null; systemctl reset-failed "$u.service" 2>/dev/null; done
  # cgroup dirs must be emptied (thaw + kill members) then rmdir'd — rm -rf fails
  # on the pseudo-files and would leave the quarantine tree behind.
  for d in /sys/fs/cgroup/phage/quar-* /sys/fs/cgroup/phage/netq-*; do
    [ -d "$d" ] || continue
    [ -f "$d/cgroup.freeze" ] && echo 0 >"$d/cgroup.freeze" 2>/dev/null
    [ -f "$d/cgroup.procs" ] && while read -r p; do kill -9 "$p" 2>/dev/null; done <"$d/cgroup.procs"
    rmdir "$d" 2>/dev/null
  done
  rm -rf /home/demo /var/www /var/lib/phage/quarantine /usr/local/bin/mx-rootsh /tmp/mx-* /root/.aws /root/.ssh/id_ed25519_backup /var/backups/.pgpass 2>/dev/null
}
trap cleanup EXIT

echo "=============== graduated-response experiments ==============="
# ---- helpers (built once) -------------------------------------------------
cat >/tmp/mx-rootsh.c <<'C'
#include <unistd.h>
int main(int c,char**v){setgid(0);setuid(0);if(c>1)execvp(v[1],v+1);execl("/usr/bin/id","id",0);return 1;}
C
clang -O2 -o /usr/local/bin/mx-rootsh /tmp/mx-rootsh.c; chown root:root /usr/local/bin/mx-rootsh; chmod 4755 /usr/local/bin/mx-rootsh
cat >/tmp/mx-sleeper.c <<'C'
#include <unistd.h>
int main(void){sleep(3);return 0;}
C
clang -O2 -o /tmp/mx-sleeper /tmp/mx-sleeper.c
cat >/tmp/mx-memfd.c <<'C'
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
int main(void){int fd=syscall(SYS_memfd_create,"x",0);int s=open("/tmp/mx-sleeper",O_RDONLY);char b[65536];ssize_t n;while((n=read(s,b,sizeof b))>0)write(fd,b,n);close(s);char*a[]={"x",0},*e[]={0};syscall(SYS_execveat,fd,"",a,e,AT_EMPTY_PATH);return 1;}
C
clang -O2 -o /tmp/mx-memfd /tmp/mx-memfd.c
cat >/tmp/mx-kexp.c <<'C'
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
int main(void){unshare(CLONE_NEWUSER);sleep(1);return 0;}
C
clang -O2 -o /tmp/mx-kexp /tmp/mx-kexp.c
mkdir -p /home/demo/.ssh /var/www/html; echo "ssh-ed25519 LEGITKEY admin@co" > /home/demo/.ssh/authorized_keys; echo '<?php ?>' >/tmp/seed.php

# ---- learn a realistic baseline (NO attack behaviour trained) -------------
# curl -> egress; cp .php -> benign web writes; runuser nobody -> benign
# privilege *drop*; unshare -> benign kernel-enabling op. Enough samples per
# signal class for confidence, none of them the attacks we test below.
echo "== learn baseline (benign activity only) =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1
for i in $(seq 1 20); do
  ls / >/dev/null
  curl -s -o /dev/null --max-time 2 https://1.1.1.1/ || true
  cp /tmp/seed.php /var/www/html/a_$i.php
  runuser -u nobody -- true 2>/dev/null || true      # benign root->nobody drop
  unshare -Ur true 2>/dev/null || true               # benign userns by 'unshare'
done
sleep 1; kill -INT "$LP" 2>/dev/null; wait "$LP" 2>/dev/null

echo "== start agent: enforce + honeytokens + heal + 12s release lease =="
./bin/phaged -bpf "$OBJ" -mode enforce -state "$STATE" -honeytokens -heal -release-after 12 >"$LOG" 2>&1 &
sleep 2

# extraction: attribute the decision to a scenario by its reason text within a
# bounded log window, and report the STRONGEST action taken (an attack emits
# several events; the matrix's answer is the highest rung it reached), so an
# incidental launch-exec alert can't be mistaken for the attack's own verdict.
mark(){ echo $(( $(wc -l <"$LOG")+1 )); }
verdict(){ # $1=start $2=end $3=reason regex -> "action  [TAG]"
  local acts best tag
  acts=$(sed -n "${1},${2}p" "$LOG" | grep -E ":: .*($3)" | grep -oE "action=[a-z]+" | cut -d= -f2)
  if   echo "$acts" | grep -qx freeze;  then best=freeze
  elif echo "$acts" | grep -qx isolate; then best=isolate
  elif echo "$acts" | grep -qx notify;  then best=notify
  else best=none; fi
  tag=$(sed -n "${1},${2}p" "$LOG" | grep -m1 -oE "ISOLATED|FROZEN|SELF-HEALED")
  printf "%-7s [%s]" "$best" "${tag:-}"
}

echo
echo "== A. proportional responses — one attack each, least-invasive sufficient action =="
m=$(mark); $SR --unit=mx-egr -p User=nobody --wait bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' 2>/dev/null; sleep 2
printf "   %-34s -> %s\n" "egress / reverse-shell dial-out" "$(verdict "$m" "$(mark)" 'outbound')"
m=$(mark); $SR --unit=mx-priv -p User=nobody bash -c '/usr/local/bin/mx-rootsh sleep 3; true' 2>/dev/null; sleep 2
printf "   %-34s -> %s\n" "privilege escalation (no session)" "$(verdict "$m" "$(mark)" 'raised to root with no login|privilege change')"
m=$(mark); $SR --unit=mx-persist bash -c 'echo "ssh-ed25519 EVIL evil@x" >> /home/demo/.ssh/authorized_keys' 2>/dev/null; sleep 2
printf "   %-34s -> %s\n" "persistence (authorized_keys)" "$(verdict "$m" "$(mark)" 'persistence')"
m=$(mark); $SR --unit=mx-ns -p User=nobody /tmp/mx-kexp 2>/dev/null; sleep 2
printf "   %-34s -> %s\n" "kernel-enabling (user namespace)" "$(verdict "$m" "$(mark)" 'kernel-enabling')"
m=$(mark); /tmp/mx-memfd >/dev/null 2>&1 & sleep 2
printf "   %-34s -> %s\n" "fileless execution (memfd)" "$(verdict "$m" "$(mark)" 'fileless')"
for u in mx-egr mx-priv mx-persist mx-ns; do systemctl reset-failed "$u.service" 2>/dev/null; done

echo
echo "== B. ESCALATION — one process climbs the ladder: dial out (isolate), then read a decoy (freeze) =="
m=$(mark)
$SR --unit=mx-esc bash -c 'bash -c "exec 3<>/dev/tcp/1.1.1.1/53; sleep 2; exec 4</root/.aws/credentials; sleep 20"; true' 2>/dev/null
sleep 6
tail -n +"$m" "$LOG" | grep -E "action=|ISOLATED|FROZEN" | sed 's/^/     /'

echo
echo "== C. two-sided lease — isolated+quiet is RELEASED, frozen is HELD for a human =="
mg=$(mark)
$SR --unit=mx-deesc -p User=nobody bash -c 'exec 3<>/dev/tcp/1.1.1.1/53; sleep 60' 2>/dev/null   # -> isolate
$SR --unit=mx-hold  -p User=nobody bash -c '/usr/local/bin/mx-rootsh sleep 60; true' 2>/dev/null  # -> freeze
sleep 3
iso_pid=$(tail -n +"$mg" "$LOG" | grep -m1 'ISOLATED' | grep -oE 'pid=[0-9]+' | cut -d= -f2)
frz_pid=$(tail -n +"$mg" "$LOG" | grep -m1 'FROZEN'   | grep -oE 'pid=[0-9]+' | cut -d= -f2)
echo "     isolated pid=$iso_pid (egress severed, still running)   frozen pid=$frz_pid (held)"
echo "     ...waiting out the 12s quiet lease (ticker is 10s, so ~25s)..."
sleep 24
echo "   -- after the lease window --"
tail -n +"$mg" "$LOG" | grep -E "DE-ESCALATED" | sed 's/^/     /'
fstate=$(cat /sys/fs/cgroup/phage/quar-$frz_pid/cgroup.freeze 2>/dev/null)
if tail -n +"$mg" "$LOG" | grep -q "DE-ESCALATED pid=$frz_pid"; then
  echo "     frozen pid=$frz_pid: WRONGLY auto-released"
else
  echo "     frozen pid=$frz_pid: still HELD (cgroup.freeze=$fstate, no DE-ESCALATED) — awaits 'phage thaw'"
fi
echo
echo "== done =="
