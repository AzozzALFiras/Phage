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
		FeatInteractiveOrigin: b2f(ev.Session.Interactive),
		FeatHasTTY:            b2f(ev.Session.TTY != ""),
		FeatLineageDepth:      float64(len(ev.Lineage)),
	}
	if len(ev.Lineage) > 0 {
		v[FeatParentComm] = commID(ev.Lineage[0].Comm)
	}
	return v
}

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
