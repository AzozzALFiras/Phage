# Phage — build orchestration.
# Go targets run anywhere; BPF targets require Linux + clang + libbpf headers.

GO        ?= go
CLANG     ?= clang
BIN       ?= bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -X main.version=$(VERSION)

# Map `uname -m` to the arch macro clang's bpf headers expect (x86_64 -> x86).
UNAME_M   := $(shell uname -m)
BPF_ARCH  := $(if $(filter x86_64,$(UNAME_M)),x86,$(if $(filter aarch64,$(UNAME_M)),arm64,$(UNAME_M)))
BPF_OBJ   := bpf/build/creds.bpf.o

.PHONY: all build daemon cli test lint tidy clean bpf gen-vmlinux help

all: build ## Build everything (Go only)

build: daemon cli ## Build the daemon and the CLI

daemon: ## Build phaged
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/phaged ./cmd/phaged

cli: ## Build the phage CLI
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/phage ./cmd/phage

test: ## Run Go tests
	$(GO) test ./...

lint: ## Vet the Go code
	$(GO) vet ./...

tidy: ## Tidy go.mod
	$(GO) mod tidy

# --- Linux-only below ---------------------------------------------------------

gen-vmlinux: ## Generate bpf/include/vmlinux/vmlinux.h from the running kernel (Linux)
	./scripts/gen/vmlinux.sh

bpf: ## Compile eBPF programs with CO-RE (Linux)
	@mkdir -p bpf/build
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I bpf/include/vmlinux -I bpf/programs \
		-c bpf/programs/privilege/creds.bpf.c -o $(BPF_OBJ)
	@llvm-strip -g $(BPF_OBJ) 2>/dev/null || true
	@echo "built $(BPF_OBJ)"

clean: ## Remove build output
	rm -rf $(BIN) bpf/build/*.o

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
