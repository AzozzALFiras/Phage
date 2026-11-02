// Package decode turns a raw ring-buffer sample into a domain event.Model. It
// is the one place that knows the on-the-wire binary layout, keeping that
// knowledge out of both the kernel-facing loader and the analysis pipeline.
package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// raw mirrors `struct phage_event` in bpf/programs/common/events.bpf.h exactly,
// including field order and alignment. Keep the two in lockstep.
type raw struct {
	ID       uint64
	TsNs     uint64
	Kind     uint32
	PID      uint32
	PPID     uint32
	UID      uint32
	EUID     uint32
	NewEUID  uint32
	LoginUID uint32
	Flags    uint32 // exec: bit 0 = fileless (image has no on-disk link)
	CapEff   uint64
	DAddr    [16]byte // destination IP, network order (connect events)
	DPort    uint16   // destination port, host order
	Family   uint16   // AF_INET (2) or AF_INET6 (10)
	Pad2     uint32
	Comm     [16]byte
	PComm    [16]byte
	Path     [160]byte // file event: resolved write path, NUL-terminated
}

// Size is the expected sample length in bytes.
const Size = 272

// loginUIDUnset is the kernel's "no login session" sentinel, (uid_t)-1.
const loginUIDUnset = 0xFFFFFFFF

// flagFileless is bit 0 of the exec event flags: the executed image had no
// on-disk link (i_nlink == 0), i.e. it ran from an anonymous in-memory file.
const flagFileless = 1 << 0

// Address families, as the kernel reports them (UAPI values).
const (
	afInet  = 2
	afInet6 = 10
)

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
	ev := model.Event{
		ID:         r.ID,
		Time:       time.Now(), // ts_ns is monotonic-since-boot; wall clock added here
		Kind:       mapKind(r.Kind),
		PID:        int32(r.PID),
		PPID:       int32(r.PPID),
		Comm:       cString(r.Comm[:]),
		ParentComm: cString(r.PComm[:]),
		Fileless:   r.Flags&flagFileless != 0,
		Creds: model.Credentials{
			UID:          int32(r.UID),
			EUID:         int32(r.NewEUID), // the euid being committed is what matters
			CapEffective: r.CapEff,
		},
	}
	// Session provenance comes from the kernel (race-free), not from /proc.
	if r.LoginUID == loginUIDUnset {
		ev.Session.LoginUID = -1
		ev.Session.Interactive = false
	} else {
		ev.Session.LoginUID = int32(r.LoginUID)
		ev.Session.Interactive = true
	}
	if ev.Kind == kind.Connect {
		ev.Net = model.NetConn{
			DestIP:   decodeIP(r.DAddr, r.Family),
			DestPort: r.DPort,
			Family:   r.Family,
		}
	}
	if ev.Kind == kind.FileWrite {
		path := cString(r.Path[:])
		ev.File = model.FileWrite{Path: path, Category: model.CategorizePath(path)}
	}
	if ev.Kind == kind.Enable {
		ev.EnableOp = enableOpName(r.Flags)
	}
	return ev, nil
}

// decodeIP renders the kernel's network-order destination bytes as text. The
// bytes are already big-endian (network order), which is exactly what net.IP
// expects, so no byte-swapping is needed here.
func decodeIP(addr [16]byte, family uint16) string {
	switch family {
	case afInet:
		return net.IP(addr[:4]).String()
	case afInet6:
		return net.IP(addr[:16]).String()
	default:
		return ""
	}
}

// enableOpName maps an enable event's op code (carried in Flags) to its name.
// The codes mirror enum phage_enable_op in events.bpf.h.
func enableOpName(op uint32) string {
	switch op {
	case 1:
		return "userns"
	case 2:
		return "bpf_load"
	case 3:
		return "io_uring"
	case 4:
		return "userfaultfd"
	default:
		return "unknown"
	}
}

func mapKind(k uint32) kind.Kind {
	switch k {
	case 1:
		return kind.Exec
	case 2:
		return kind.CredsChange
	case 3:
		return kind.CapSet
	case 4:
		return kind.Connect
	case 5:
		return kind.FileWrite
	case 6:
		return kind.Enable
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
