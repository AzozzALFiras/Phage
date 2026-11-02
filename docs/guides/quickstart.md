# Quickstart

> ⚠️ Early development. These steps describe the intended operator experience;
> the daemon does not yet wire up sensors. See [development](development.md) for
> what actually builds today.

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
sudo cp configs/phage.example.yaml /etc/phage/phage.yaml
# mode: learn   (do not change yet)
sudo phaged
```
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
