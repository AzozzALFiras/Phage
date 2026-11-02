# Contributing to Phage

Thanks for looking. Phage is early; focused contributions are very welcome.

## Principles (please keep these)
- **Detection is behavioral, never a signature.** New detectors add a *measured
  feature* and let the learned baseline decide — no hardcoded "if parent == X"
  attack rules. (Operational guardrails and thresholds are fine; see the ADRs.)
- **The kernel side stays small.** eBPF filters on the hot path; userspace reads
  only what matters. Keep the agent lightweight.
- **Safety of the control plane is not negotiable.** Enforcement must never be
  able to lock an operator out. See `containmentSafe` and `docs/concepts/modes.md`.
- **One concern per package.** Prefer small, deeply-nested packages over flat
  ones with many files.

## Layout
- `cmd/` — thin entrypoints (`phaged` daemon, `phage` CLI).
- `bpf/` — kernel sensors (C/eBPF CO-RE), one object, shared ring buffer.
- `internal/` — the pipeline: `sensor → enrich → analysis → policy → response`,
  one folder per stage.
- `docs/` — architecture, ADRs, concepts, the threat model, guides.

## Developing
```sh
make build && make test && go vet ./...   # Go, builds anywhere
make bpf                                   # eBPF, Linux + clang + libbpf only
```
The Go agent builds on any OS (a stub covers non-Linux); the eBPF sensors build
and run on Linux with kernel BTF. Author locally, build/run on a Linux box.

## Pull requests
- Keep them small and focused; one behavior per PR.
- Add or update tests — the decode layout contract, scorer behavior, and
  containment safety all have unit tests to protect.
- Run `gofmt`, `go vet`, and `go test ./...` before pushing.
