# ADR 0001 — Go for the agent, C/eBPF for the sensors

**Status:** accepted · **Date:** 2026-11-02

## Context
Phage needs kernel-level visibility into privilege changes and a userspace
agent that reasons and responds. We must pick languages for both, balancing
performance, resource use, shipping speed, and hireability of the skillset.

## Decision
- **Kernel sensors:** C compiled to eBPF with **CO-RE** (Compile Once, Run
  Everywhere) via libbpf, so one object runs across kernel versions that expose
  BTF.
- **Userspace agent:** **Go**, using `cilium/ebpf` (pure Go, no cgo) to load and
  talk to the programs. Ships as a single static binary.

## Why not Rust/aya or pure C userspace?
The performance-critical work happens **in the kernel**, in eBPF bytecode, which
is the same regardless of the userspace language. The userspace agent only reads
already-filtered events and acts. So Go's garbage collector costs us a modestly
larger *baseline* memory footprint (~tens of MiB), not per-event CPU.

Against that fixed cost we get: the fastest path to shipping, the largest
ecosystem in cloud-native security (Falco, Tetragon, Cilium, Tracee are all Go),
cgo-free static binaries that make `curl | sh` adoption trivial, and the biggest
hiring market in this niche.

## Consequences
- Resource use stays low because the hot path is in-kernel; we must keep it that
  way (filter aggressively in eBPF, never ship noise to userspace).
- **Future option:** if an ultra-low-footprint build becomes a selling point, the
  agent core can be rewritten in Rust/aya as a v2 — a deliberate, separate effort,
  not a day-one cost. The pipeline seams make this swappable.
