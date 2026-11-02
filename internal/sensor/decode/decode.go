// Package decode turns a raw ring-buffer sample into a domain event.Model. It
// is the one place that knows the on-the-wire binary layout, keeping that
// knowledge out of both the kernel-facing loader and the analysis pipeline.
package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// raw mirrors `struct phage_event` in bpf/programs/common/events.bpf.h exactly,
// including field order and alignment. Keep the two in lockstep.
type raw struct {
	ID      uint64
	TsNs    uint64
	Kind    uint32
	PID     uint32
	PPID    uint32
	UID     uint32
	EUID    uint32
	NewEUID uint32
	CapEff  uint64
	Comm    [16]byte
}

// Size is the expected sample length in bytes.
const Size = 64

// Event decodes one raw sample. Samples are little-endian (the kernel writes
// host byte order; Phage targets x86_64/arm64, both little-endian).
func Event(b []byte) (model.Event, error) {
	if len(b) < Size {
		return model.Event{}, fmt.Errorf("short sample: %d bytes, want %d", len(b), Size)
	}
	var r raw
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &r); err != nil {
		return model.Event{}, fmt.Errorf("decode sample: %w", err)
	}
	return model.Event{
		ID:   r.ID,
		Time: time.Now(), // ts_ns is monotonic-since-boot; wall clock added here
		Kind: mapKind(r.Kind),
		PID:  int32(r.PID),
		PPID: int32(r.PPID),
		Comm: cString(r.Comm[:]),
		Creds: model.Credentials{
			UID:          int32(r.UID),
			EUID:         int32(r.NewEUID), // the euid being committed is what matters
			CapEffective: r.CapEff,
		},
	}, nil
}

func mapKind(k uint32) kind.Kind {
	switch k {
	case 1:
		return kind.Exec
	case 2:
		return kind.CredsChange
	case 3:
		return kind.CapSet
	default:
		return kind.Unknown
	}
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
