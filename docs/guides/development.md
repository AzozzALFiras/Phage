# Development guide

## Two build targets, two platforms
- **Go agent** (`cmd/`, `internal/`, `pkg/`) builds anywhere, including macOS.
- **eBPF sensors** (`bpf/`) build and run on **Linux only** (clang + libbpf +
  a kernel with BTF). Author them on any machine; compile and attach on Linux.

The sensible workflow: write and unit-test the Go logic locally, and build/run
the full agent (with sensors) on a Linux test server.

## Build the Go agent (works on macOS/Linux)
```sh
make build      # -> bin/phaged, bin/phage
make test       # go test ./...
make lint       # go vet ./...
```

## Build the eBPF sensors (Linux only)
Prerequisites:
```sh
# Debian/Ubuntu example
sudo apt-get install -y clang llvm libbpf-dev linux-tools-common
```
Generate the CO-RE header from the running kernel, then compile:
```sh
make gen-vmlinux    # writes bpf/include/vmlinux/vmlinux.h
make bpf            # writes bpf/build/*.bpf.o
```
`gen-vmlinux` runs:
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux/vmlinux.h
```

## Layout conventions (why the tree is deep)
One concern per folder, few files per folder. If a package starts collecting
unrelated files, split it into subpackages. The pipeline stages map 1:1 to
top-level `internal/` folders; keep that mapping intact.

## Testing the detector safely
All exploitation testing happens on **our own** test server (SSH access we
control), never against third-party systems. Scenario tests live in
`test/e2e/privesc/`; fixtures (recorded events) in `test/fixtures/events/` let us
test the analysis pipeline deterministically without a kernel.
