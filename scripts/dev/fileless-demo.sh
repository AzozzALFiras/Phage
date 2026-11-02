#!/usr/bin/env bash
# fileless-demo.sh — live proof that Phage catches in-memory (fileless) execution
# that disk-based scanners miss: a program run from an anonymous memfd, leaving
# no file on disk. The signal is behavioural — the executed image has no on-disk
# link (i_nlink == 0) — so it holds even when the memfd is named after a trusted
# program.
set -uo pipefail
cd /root/phage
OBJ=bpf/build/sensors.bpf.o
STATE=/tmp/fileless-base.json

cleanup(){ pkill -x phaged 2>/dev/null||true; pkill -9 -f memfd_poc 2>/dev/null||true; rm -f /tmp/memfd_poc /tmp/memfd_poc.c /tmp/sleeper /tmp/sleeper.c "$STATE"; }
trap cleanup EXIT

echo "== build a fileless-exec PoC (harmless: runs a sleeper from an anonymous memfd) =="
cat > /tmp/sleeper.c <<'C'
#include <unistd.h>
int main(void){ sleep(3); return 0; }
C
clang -O2 -o /tmp/sleeper /tmp/sleeper.c
cat > /tmp/memfd_poc.c <<'C'
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
int main(void){
    int fd = syscall(SYS_memfd_create, "nginx", 0);   /* named to blend in */
    int src = open("/tmp/sleeper", O_RDONLY);
    char buf[65536]; ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0) write(fd, buf, n);
    close(src);
    char *av[] = {"nginx",0}, *ev[]={0};
    syscall(SYS_execveat, fd, "", av, ev, AT_EMPTY_PATH);
    perror("execveat"); return 1;
}
C
clang -O2 -o /tmp/memfd_poc /tmp/memfd_poc.c && echo "built"

echo "== baseline: Phage learns normal execs =="
./bin/phaged -bpf "$OBJ" -mode learn -state "$STATE" >/tmp/fileless-learn.log 2>&1 &
LP=$!; sleep 1
for i in $(seq 1 20); do ls / >/dev/null; date >/dev/null; /bin/bash -c true; /usr/bin/id >/dev/null; sleep 0.1; done
sleep 1; kill -TERM "$LP" 2>/dev/null; wait "$LP" 2>/dev/null
echo "baseline: $(wc -c < "$STATE") bytes"

echo "== alert mode =="
./bin/phaged -bpf "$OBJ" -mode alert -state "$STATE" >/tmp/fileless-alert.log 2>&1 &
AP=$!; sleep 1

echo ">>> CONTROL: a normal on-disk program runs"
/usr/bin/id >/dev/null; sleep 1
echo "   normal exec verdict (expect none):"
grep -E "score=" /tmp/fileless-alert.log | grep -i "fileless" | sed 's/^/     /' || true

echo ">>> ATTACK: fileless exec from an anonymous memfd (named \"nginx\")"
/tmp/memfd_poc >/dev/null 2>&1 &
sleep 2
echo "   Phage verdict:"
grep -E "score=" /tmp/fileless-alert.log | grep -iE "fileless|memfd" | sed 's/^/     /'
kill -TERM "$AP" 2>/dev/null; wait "$AP" 2>/dev/null
echo "== done (no file was ever written to disk by the attack) =="
