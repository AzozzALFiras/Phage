#!/usr/bin/env bash
# Sync the working tree to the test server and rebuild the eBPF object there.
# The repo is private, so we push code with rsync over our SSH key rather than
# cloning on the server. Usage: scripts/dev/sync.sh [ssh-alias]  (default: servertest)
set -euo pipefail

HOST="${1:-servertest}"
DEST="/root/phage"

rsync -az --delete \
	--exclude '.git' --exclude 'bin' --exclude 'bpf/build' \
	--exclude 'bpf/include/vmlinux' --exclude '.DS_Store' \
	--exclude '*.json' --exclude '*.jsonl' \
	-e "ssh -o BatchMode=yes" ./ "$HOST:$DEST/"

ssh -o BatchMode=yes "$HOST" "cd $DEST && make bpf"
echo "synced to $HOST:$DEST and rebuilt eBPF"
