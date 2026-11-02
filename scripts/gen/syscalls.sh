#!/usr/bin/env bash
# Regenerate internal/jail/syscalls/tabledata.go from the kernel's own
# UAPI header, so the number->name map matches the target architecture exactly.
# Run on a Linux/x86_64 host (or over SSH to one). Usage: scripts/gen/syscalls.sh
set -euo pipefail

SRC="${1:-/usr/include/x86_64-linux-gnu/asm/unistd_64.h}"
OUT="internal/jail/syscalls/tabledata.go"

[ -r "$SRC" ] || { echo "cannot read $SRC (run on Linux/x86_64)" >&2; exit 1; }

{
	cat <<'HDR'
// Code generated from <asm/unistd_64.h> (x86_64). DO NOT EDIT BY HAND.
// Regenerate with scripts/gen/syscalls.sh on a Linux host.
//
// This is the authoritative number->name map for the target architecture, taken
// from the kernel's own UAPI header, so a generated seccomp profile names
// exactly the syscalls the kernel reported observing.

package syscalls

// amd64ByNr maps a Linux/x86_64 syscall number to its canonical name.
var amd64ByNr = map[int]string{
HDR
	grep -E "^#define __NR_" "$SRC" |
		sed -E 's/^#define __NR_([a-zA-Z0-9_]+)[[:space:]]+([0-9]+).*/\2 \1/' |
		sort -n |
		awk '{printf "\t%s: \"%s\",\n", $1, $2}'
	echo "}"
} > "$OUT"

gofmt -w "$OUT"
echo "wrote $OUT ($(grep -c ':' "$OUT") entries)"
