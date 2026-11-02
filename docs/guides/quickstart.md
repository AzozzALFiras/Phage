# Quickstart

> ⚠️ Early but working. The daemon loads the eBPF sensors, learns a baseline,
> and scores/contains in alert and enforce modes. All four sensors —
> privilege-escalation, exec, egress, and file/persistence — are live-verified on
> a test server. The hosted installer below is still a placeholder — build from
> source for now. See [development](development.md).

## Requirements
- Linux, kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`). Check:
  ```sh
  ls /sys/kernel/btf/vmlinux && echo "BTF present"
  ```
- Root (eBPF loading needs privileges).

## Install (intended)
```sh
curl -fsSL https://get.phage.sh | sh     # placeholder; not live yet
```

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
