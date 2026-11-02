#!/usr/bin/env bash
# Generate the CO-RE kernel header from the running kernel's BTF.
# Linux only. Requires bpftool and a kernel with CONFIG_DEBUG_INFO_BTF=y.
set -euo pipefail

OUT="bpf/include/vmlinux/vmlinux.h"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
	echo "error: /sys/kernel/btf/vmlinux not found — kernel lacks BTF" >&2
	exit 1
fi

mkdir -p "$(dirname "$OUT")"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
echo "wrote $OUT"
