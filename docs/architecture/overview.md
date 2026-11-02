# Architecture overview

Phage is a pipeline. Each stage has one job and a clean seam to the next, so
any stage can be rewritten without disturbing the others. This is what lets the
"intelligence" (the scorer) evolve from statistics to ML while the sensors and
the response layer stay put.

```
  kernel                         userspace (phaged)
 ┌────────┐   ring    ┌─────────┐   ┌────────┐   ┌──────────┐   ┌────────┐   ┌──────────┐
 │ eBPF   │  buffer   │ decode  │   │ enrich │   │ analysis │   │ policy │   │ response │
 │ sensor ├──────────►│ raw→evt ├──►│ context├──►│ feature  ├──►│ verdict├──►│ act /    │
 │        │           │         │   │        │   │ +scorer  │   │ →action│   │ notify   │
 └────────┘           └─────────┘   └────────┘   └────┬─────┘   └────────┘   └──────────┘
                                                      │
                                                 ┌────▼─────┐
                                                 │ baseline │  (learned "normal")
                                                 └──────────┘
```

## Stages and where they live

| Stage | Package | Responsibility |
|---|---|---|
| Sensor (kernel) | `bpf/programs/` | Capture privilege-relevant events at a kernel chokepoint. |
| Sensor (loader) | `internal/sensor/` | Load/attach eBPF, read the ring buffer, decode raw bytes. |
| Event model | `internal/event/` | The enriched, kernel-agnostic event vocabulary. |
| Enrichment | `internal/enrich/` | Add process lineage, identity/session, container context. |
| Analysis | `internal/analysis/` | Extract features, score against the baseline, explain. |
| Policy | `internal/policy/` | Map a verdict + mode to a response. |
| Response | `internal/response/` | Notify, freeze, kill, isolate. |
| State | `internal/store/` | Persist the learned baseline. |

## Two design rules that shape everything

1. **The hot path is in the kernel.** The eBPF program does the per-event
   filtering; userspace only sees what matters. This is why the choice of
   userspace language barely affects cost — see
   [ADR 0001](decisions/0001-language-go-and-ebpf.md).

2. **Detection is never hardcoded.** The policy layer has thresholds and
   conditionals, but *what counts as an attack* is decided only by the scorer
   reading the learned baseline — see
   [ADR 0002](decisions/0002-analysis-not-ifelse.md).
