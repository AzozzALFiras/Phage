package decode

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
)

// sample builds a raw ring-buffer record matching struct phage_event, so this
// test also guards the C<->Go layout contract.
func sample() []byte {
	var buf bytes.Buffer
	fields := []any{
		uint64(7),          // id
		uint64(1234),       // ts_ns
		uint32(2),          // kind = creds_change
		uint32(4242),       // pid
		uint32(99),         // ppid
		uint32(999),        // uid (webapp)
		uint32(0),          // euid (unused by decode)
		uint32(0),          // new_euid -> root
		uint32(0xFFFFFFFF), // loginuid = unset (no login session)
		uint32(0),          // _pad
		uint64(0x1ff),      // cap_eff
	}
	for _, f := range fields {
		binary.Write(&buf, binary.LittleEndian, f)
	}
	comm := [16]byte{}
	copy(comm[:], "rootshell")
	buf.Write(comm[:])
	pcomm := [16]byte{}
	copy(pcomm[:], "sh")
	buf.Write(pcomm[:])
	return buf.Bytes()
}

func TestEventDecodesFields(t *testing.T) {
	b := sample()
	if len(b) != Size {
		t.Fatalf("sample size = %d, want %d (layout drift vs events.bpf.h)", len(b), Size)
	}
	ev, err := Event(b)
	if err != nil {
		t.Fatalf("Event: %v", err)
	}
	if ev.PID != 4242 {
		t.Errorf("PID = %d, want 4242", ev.PID)
	}
	if ev.Comm != "rootshell" {
		t.Errorf("Comm = %q, want %q", ev.Comm, "rootshell")
	}
	if ev.ParentComm != "sh" {
		t.Errorf("ParentComm = %q, want %q", ev.ParentComm, "sh")
	}
	if ev.Kind != kind.CredsChange {
		t.Errorf("Kind = %q, want %q", ev.Kind, kind.CredsChange)
	}
	if ev.Creds.UID != 999 || ev.Creds.EUID != 0 {
		t.Errorf("creds uid/euid = %d/%d, want 999/0", ev.Creds.UID, ev.Creds.EUID)
	}
	if !ev.RaisedToRoot() {
		t.Error("RaisedToRoot() = false, want true (uid 999 with euid 0)")
	}
	if ev.Session.Interactive {
		t.Error("Interactive = true, want false (loginuid unset)")
	}
	if ev.Session.LoginUID != -1 {
		t.Errorf("LoginUID = %d, want -1 (unset)", ev.Session.LoginUID)
	}
}

func TestEventRejectsShortSample(t *testing.T) {
	if _, err := Event([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on short sample")
	}
}
