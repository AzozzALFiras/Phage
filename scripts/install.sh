#!/usr/bin/env bash
# Phage installer — builds from source and installs the daemon, CLI, eBPF
# objects, config, and systemd unit, then starts it in LEARN mode.
#
# From a clone:   sudo ./scripts/install.sh
# One-liner:      curl -fsSL https://raw.githubusercontent.com/AzozzALFiras/Phage/main/scripts/install.sh | sudo bash
#
# There are no prebuilt releases yet, so this needs a Go + clang/libbpf
# toolchain on the target (which is also where Phage runs). Env overrides:
#   REPO_URL (default the GitHub repo)  REPO_REF (default main)  PREFIX (/usr/local)
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/AzozzALFiras/Phage.git}"
REPO_REF="${REPO_REF:-main}"
PREFIX="${PREFIX:-/usr/local}"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "Phage runs on Linux only (you are on $(uname -s))."
[ "$(id -u)" = "0" ] || die "run as root (installs into $PREFIX, /etc, and systemd): use sudo."

[ -r /sys/kernel/btf/vmlinux ] || die \
  "kernel BTF (/sys/kernel/btf/vmlinux) not found — Phage's CO-RE sensors need it to run. \
Enable CONFIG_DEBUG_INFO_BTF or use a kernel that ships BTF."

missing=""
for t in go clang make; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
[ -z "$missing" ] || die "missing build tools:$missing (need Go, clang/libbpf, make). Install them and re-run."

# --- get the source --------------------------------------------------------
if grep -qs 'github.com/AzozzALFiras/Phage' go.mod 2>/dev/null; then
  SRC="$(pwd)"
  say "building from the current checkout ($SRC)"
else
  command -v git >/dev/null 2>&1 || die "git not found and not run from a clone — install git or clone the repo first."
  SRC="$(mktemp -d)"
  say "cloning $REPO_URL ($REPO_REF) -> $SRC"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$SRC"
fi
cd "$SRC"

# --- build + install -------------------------------------------------------
say "compiling eBPF sensors (make bpf)"
make bpf
say "building the agent and CLI (make build)"
make build
say "installing into $PREFIX, /etc/phage, and systemd"
make install PREFIX="$PREFIX"

# --- enable in LEARN mode (acts on nothing) --------------------------------
say "enabling the service in LEARN mode"
systemctl daemon-reload
systemctl enable --now phage.service

cat <<EOF

$(systemctl is-active phage.service >/dev/null 2>&1 && printf '\033[32mPhage is running in LEARN mode.\033[0m' || printf '\033[33mInstalled, but the service is not active — check: journalctl -u phage -n 50\033[0m')

Next steps (the safe ladder — never skip to enforce on a fresh baseline):
  journalctl -u phage -f          # watch it learn normal behaviour (give it days)
  phage status                    # live status
  phage events                    # what it would flag

When the baseline is mature, move up a rung by editing /etc/phage/phage.yaml
(mode: alert, then mode: enforce) and: systemctl restart phage
To arm the opt-in defences (honeytokens / self-heal / tamper-resistance):
  systemctl edit phage            # see the drop-in example in the unit file

Docs: https://github.com/AzozzALFiras/Phage/blob/main/docs/guides/quickstart.md
EOF
