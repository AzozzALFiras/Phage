# Quickstart

> ⚠️ Early but working. The daemon loads the eBPF sensors, learns a baseline,
> and scores/contains in alert and enforce modes, live-verified on a test server.
> There are no prebuilt releases yet, so the installer builds from source (needs
> a Go + clang/libbpf toolchain on the target). See [development](development.md).

## Requirements
- Linux, kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`). Check:
  ```sh
  ls /sys/kernel/btf/vmlinux && echo "BTF present"
  ```
- Root (eBPF loading needs privileges).

## Install
One command — it checks prerequisites, builds the sensors and agent from source,
installs the daemon/CLI/eBPF-objects/config/systemd-unit, and starts the service
in learn mode:
```sh
curl -fsSL https://raw.githubusercontent.com/AzozzALFiras/Phage/main/scripts/install.sh | sudo bash
```
Or, from a clone, `sudo ./scripts/install.sh`. A short vanity URL
(`https://get.phage.sh`) may come later; the raw URL above is the real one today.

If you used the installer, Phage is **already running in learn mode** — skip to
[Graduate to alert](#graduate-to-alert) once the baseline is mature, and use
`journalctl -u phage -f` to watch it. The manual steps below are for running
straight from a source tree instead.

## First run — always start in learn mode
```sh
sudo mkdir -p /etc/phage
sudo cp configs/phage.example.yaml /etc/phage/phage.yaml
# mode: learn   (do not change yet)
sudo phaged -config /etc/phage/phage.yaml
```
Any flag overrides the file for that run — e.g. `sudo phaged -config
/etc/phage/phage.yaml -mode alert` to try alert mode without editing the file.
Let it learn for at least a week (`learn_window`). It is building the baseline of
how your server normally behaves. It will not alert or act in this phase — that
is correct.

## Graduate to alert
Once the baseline is populated, set `mode: alert`, restart, and watch what it
flags:
```sh
phage events          # live anomalies with their reasons
```
Tune `thresholds.notify` until the signal is trustworthy.

## Graduate to enforce
Only when you trust the alerts, set `mode: enforce`. Default containment is a
reversible **freeze**; a mistakenly frozen process can be released, nothing is
killed unless you opt in.

See [modes](../concepts/modes.md) for why this ordering matters.
