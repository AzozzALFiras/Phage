// Package model defines the enriched, domain-level event that flows through
// Phage's analysis pipeline. It is deliberately decoupled from the raw eBPF
// wire format (decoded in internal/sensor/decode) so the kernel side and the
// reasoning side can evolve independently.
package model

import (
	"time"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
)

// ProcRef is one node in a process lineage chain.
type ProcRef struct {
	PID  int32
	Comm string
	Exe  string
}

// Credentials captures the privilege state relevant to escalation analysis.
type Credentials struct {
	UID, EUID, SUID int32
	GID, EGID, SGID int32
	CapEffective    uint64
}

// Session links an event back to its authenticated origin, if any. This is the
// backbone of provenance-based detection: a root transition with no interactive
// session behind it is exactly the signal Phage cares about.
type Session struct {
	ID          int32  // kernel session id (sid)
	TTY         string // controlling terminal; empty means none
	Interactive bool   // backed by a real login / ssh session
	LoginUID    int32  // audit login uid; -1 when there is no login session
	RemoteAddr  string // set when the session traces back to sshd
}

// Event is the unit of analysis: an enriched, self-contained description of one
// privilege-relevant thing that happened.
type Event struct {
	ID         uint64
	Time       time.Time
	Kind       kind.Kind
	PID        int32
	PPID       int32
	Comm       string
	ParentComm string // immediate parent's comm, captured in-kernel (race-free)
	Exe        string
	Args       []string
	CWD        string
	Creds      Credentials
	Session    Session
	Lineage    []ProcRef // ancestry; index 0 is the immediate parent
	Container  string    // container / cgroup id; empty on a bare host
}

// GainedRoot reports whether this event represents the process holding root
// privileges. It is a measurement, not a verdict.
func (e Event) GainedRoot() bool {
	return e.Creds.UID == 0 || e.Creds.EUID == 0
}

// RaisedToRoot reports whether an unprivileged real uid is running with a root
// effective uid — the classic shape of a setuid-style escalation. Unlike a
// root daemon (uid 0, euid 0), this is privilege being *raised*, not held.
func (e Event) RaisedToRoot() bool {
	return e.Creds.UID != 0 && e.Creds.EUID == 0
}
