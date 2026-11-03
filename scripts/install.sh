#!/usr/bin/env bash
# Phage installer.
#
#   curl -fsSL https://raw.githubusercontent.com/AzozzALFiras/Phage/main/scripts/install.sh | sudo bash
#
# By default it downloads a prebuilt release (static binaries + CO-RE eBPF
# objects — no toolchain needed) for linux/amd64 and installs it. If no prebuilt
# release is available (or the arch has none, or you ask for it), it falls back
# to building from source, which needs a Go + clang/libbpf toolchain.
#
# It installs the daemon, CLI, eBPF objects, a default config, and the systemd
# unit, then starts the service in LEARN mode (watches and learns, acts on
# nothing). Env overrides:
#   PHAGE_FROM_SOURCE=1   force a source build
#   PHAGE_VERSION=vX.Y.Z  install a specific release instead of the latest
#   PHAGE_TARBALL=/path   install from a local tarball (offline), skip download
#   PREFIX=/usr/local  REPO_URL  REPO_REF
set -euo pipefail

REPO="AzozzALFiras/Phage"
REPO_URL="${REPO_URL:-https://github.com/$REPO.git}"
REPO_REF="${REPO_REF:-main}"
PREFIX="${PREFIX:-/usr/local}"
ASSET="phage_linux_amd64.tar.gz"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "Phage runs on Linux only (you are on $(uname -s))."
[ "$(id -u)" = "0" ] || die "run as root (installs into $PREFIX, /etc, and systemd): use sudo."
[ -r /sys/kernel/btf/vmlinux ] || die \
  "kernel BTF (/sys/kernel/btf/vmlinux) not found — Phage's CO-RE sensors need it to run."

SHASUM="$(command -v sha256sum >/dev/null 2>&1 && echo 'sha256sum' || echo 'shasum -a 256')"
dl() { # dl URL OUTFILE  -> 0 on success
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else die "need curl or wget to download a release"; fi
}

# --- shared install steps (from a directory holding the extracted artifacts) --
install_tree() { # install_tree <dir with phaged/phage/phage-jail/bpf/phage.service/phage.example.yaml>
  local d="$1"
  install -d "$PREFIX/bin" "$PREFIX/lib/phage" /etc/phage /etc/systemd/system
  install -m 0755 "$d/phaged" "$d/phage" "$d/phage-jail" "$PREFIX/bin/"
  install -m 0644 "$d"/bpf/*.bpf.o "$PREFIX/lib/phage/"
  install -m 0644 "$d/phage.service" /etc/systemd/system/phage.service
  if [ -f /etc/phage/phage.yaml ]; then
    say "keeping existing /etc/phage/phage.yaml"
  else
    install -m 0644 "$d/phage.example.yaml" /etc/phage/phage.yaml
    say "installed default config -> /etc/phage/phage.yaml (mode: learn)"
  fi
}

install_prebuilt() { # install_prebuilt <tarball> [sumsfile]
  local tgz="$1" sums="${2:-}" tmp
  if [ -n "$sums" ] && [ -f "$sums" ]; then
    say "verifying checksum"
    ( cd "$(dirname "$tgz")" && grep " $(basename "$tgz")\$" "$sums" | $SHASUM -c - ) \
      || die "checksum verification failed for $(basename "$tgz")"
  else
    warn "no checksum file — skipping verification"
  fi
  tmp="$(mktemp -d)"
  tar xzf "$tgz" -C "$tmp"
  say "installing prebuilt $(cat "$tmp/phage_linux_amd64/VERSION" 2>/dev/null || echo release)"
  install_tree "$tmp/phage_linux_amd64"
  rm -rf "$tmp"
}

install_from_source() {
  local missing="" src
  for t in go clang make; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
  [ -z "$missing" ] || die "source build needs:$missing (Go, clang/libbpf, make). Install them and re-run."
  if grep -qs "github.com/$REPO" go.mod 2>/dev/null; then
    src="$(pwd)"; say "building from the current checkout ($src)"
  else
    command -v git >/dev/null 2>&1 || die "git not found and not run from a clone."
    src="$(mktemp -d)"; say "cloning $REPO_URL ($REPO_REF)"; git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$src"
  fi
  ( cd "$src" && say "compiling eBPF sensors" && make bpf \
      && say "building agent + CLI" && make build \
      && say "installing" && make install PREFIX="$PREFIX" )
}

# --- choose a path ---------------------------------------------------------
if [ "${PHAGE_FROM_SOURCE:-0}" = "1" ]; then
  install_from_source
elif [ -n "${PHAGE_TARBALL:-}" ]; then
  [ -f "$PHAGE_TARBALL" ] || die "PHAGE_TARBALL=$PHAGE_TARBALL not found"
  say "installing from local tarball $PHAGE_TARBALL"
  install_prebuilt "$PHAGE_TARBALL" "$(dirname "$PHAGE_TARBALL")/SHA256SUMS"
elif [ "$(uname -m)" != "x86_64" ]; then
  warn "no prebuilt release for $(uname -m) yet — building from source"
  install_from_source
else
  # Try a prebuilt release; fall back to source if there isn't one yet.
  if [ -n "${PHAGE_VERSION:-}" ]; then
    base="https://github.com/$REPO/releases/download/$PHAGE_VERSION"
  else
    base="https://github.com/$REPO/releases/latest/download"
  fi
  tmp="$(mktemp -d)"
  if dl "$base/$ASSET" "$tmp/$ASSET" 2>/dev/null; then
    dl "$base/SHA256SUMS" "$tmp/SHA256SUMS" 2>/dev/null || true
    install_prebuilt "$tmp/$ASSET" "$tmp/SHA256SUMS"
    rm -rf "$tmp"
  else
    rm -rf "$tmp"
    warn "no prebuilt release found at $base — building from source instead"
    install_from_source
  fi
fi

# --- enable in LEARN mode --------------------------------------------------
say "enabling the service in LEARN mode"
systemctl daemon-reload
systemctl enable --now phage.service

echo
if systemctl is-active phage.service >/dev/null 2>&1; then
  printf '\033[32mPhage is running in LEARN mode.\033[0m\n'
else
  printf '\033[33mInstalled, but the service is not active — check: journalctl -u phage -n 50\033[0m\n'
fi
cat <<'EOF'

Next steps (the safe ladder — never skip to enforce on a fresh baseline):
  journalctl -u phage -f          # watch it learn normal behaviour (give it days)
  phage status                    # live status
  phage events                    # what it would flag

When the baseline is mature, edit /etc/phage/phage.yaml (mode: alert, then
enforce) and: systemctl restart phage
Arm the opt-in defences (honeytokens / self-heal / tamper-resistance):
  systemctl edit phage            # drop-in example is in the unit file

Docs: https://github.com/AzozzALFiras/Phage/blob/main/docs/guides/quickstart.md
EOF
