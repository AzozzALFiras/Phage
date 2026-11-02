// Package feature turns an enriched Event into a numeric Vector the scorer can
// reason about. Nothing here decides whether an event is malicious — this layer
// only *measures*. Keeping measurement separate from scoring is what lets the
// model evolve from simple statistics to machine learning without touching the
// sensors or the policy layer.
package feature

import "github.com/AzozzALFiras/Phage/internal/event/model"

// Vector is a sparse, named set of measurements. Keys are stable strings so a
// learned baseline stays comparable across versions.
type Vector map[string]float64

// Extractor computes a feature Vector for an event.
type Extractor interface {
	Extract(ev model.Event) Vector
}

// Well-known feature keys. Documented in docs/design/analysis-engine.md.
const (
	FeatGainedRoot        = "priv.gained_root"        // 1 if the process holds root (uid or euid 0)
	FeatRaisedToRoot      = "priv.raised_to_root"     // 1 if an unprivileged uid now has root euid
	FeatRaiseNoSession    = "priv.raise_no_session"   // 1 if raised to root with no login session behind it
	FeatInteractiveOrigin = "priv.interactive_origin" // 1 if traceable to an interactive session
	FeatHasTTY            = "priv.has_tty"            // 1 if a controlling terminal exists
	FeatLineageDepth      = "priv.lineage_depth"      // ancestry depth
	FeatParentComm        = "priv.parent_comm_id"     // stable id of the immediate parent's comm
)

// Privilege extracts features relevant to privilege-escalation provenance.
// It answers measurable questions ("did root appear?", "was there a session
// behind it?") and leaves all judgement to the scorer.
type Privilege struct{}

// Extract implements Extractor.
func (Privilege) Extract(ev model.Event) Vector {
	v := Vector{
		FeatGainedRoot:        b2f(ev.GainedRoot()),
		FeatRaisedToRoot:      b2f(ev.RaisedToRoot()),
		FeatRaiseNoSession:    b2f(ev.RaisedToRoot() && !ev.Session.Interactive),
		FeatInteractiveOrigin: b2f(ev.Session.Interactive),
		FeatHasTTY:            b2f(ev.Session.TTY != ""),
		FeatLineageDepth:      float64(len(ev.Lineage)),
	}
	if len(ev.Lineage) > 0 {
		v[FeatParentComm] = commID(ev.Lineage[0].Comm)
	}
	return v
}

// Exec-event feature keys.
const (
	FeatExecPair        = "exec.parent_child_id" // stable id of the parent->child pair
	FeatExecChild       = "exec.child_id"        // stable id of the executed program
	FeatExecInteractive = "exec.interactive_origin"
)

// Exec extracts features for a process-execution event. The dominant signal is
// the parent->child pair: which programs spawn which is highly stable per host,
// so a long-lived service suddenly exec'ing a shell is a never-seen pair — the
// universal effect of RCE, independent of the vulnerability behind it.
type Exec struct{}

// Extract implements Extractor for exec events.
func (Exec) Extract(ev model.Event) Vector {
	return Vector{
		FeatExecPair:        pairID(ev.ParentComm, ev.Comm),
		FeatExecChild:       commID(ev.Comm),
		FeatExecInteractive: b2f(ev.Session.Interactive),
	}
}

// Network-event feature keys.
const (
	FeatNetEgressComm        = "net.egress_comm_id"      // stable id of the program making the connection
	FeatNetEgressPort        = "net.egress_port"         // destination port
	FeatNetEgressPair        = "net.egress_comm_port_id" // stable id of the program->port pair
	FeatNetEgressInteractive = "net.egress_interactive"  // 1 if a session is behind it
)

// Network extracts features for an outbound-connection event. The dominant
// signal mirrors exec's: which programs egress, and to which ports, is highly
// stable per host. A long-lived service — or a shell it spawned — suddenly
// dialing out is the universal effect of a reverse shell or C2 beacon, whatever
// the vulnerability behind it. The destination IP is deliberately *not* a
// feature: addresses are too high-cardinality to learn (every new IP would look
// novel), so Phage learns the egress program and port, and keeps the concrete
// address for the human-readable reason and the audit trail.
type Network struct{}

// Extract implements Extractor for connect events.
func (Network) Extract(ev model.Event) Vector {
	port := strconvPort(ev.Net.DestPort)
	return Vector{
		FeatNetEgressComm:        commID(ev.Comm),
		FeatNetEgressPort:        float64(ev.Net.DestPort),
		FeatNetEgressPair:        commID(ev.Comm + ":" + port),
		FeatNetEgressInteractive: b2f(ev.Session.Interactive),
	}
}

func strconvPort(p uint16) string {
	// small, allocation-light itoa for the pair key
	if p == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}

func pairID(parent, child string) float64 { return commID(parent + ">" + child) }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// commID maps a command name to a stable numeric id (FNV-1a) so categorical
// values fit the numeric Vector without an external table.
func commID(s string) float64 {
	const (
		offset = 2166136261
		prime  = 16777619
	)
	var h uint32 = offset
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return float64(h)
}
