// Package response is the graduated-response matrix: it chooses the
// least-invasive action that is sufficient for an event, rather than one fixed
// action per rule. The ladder, least to most invasive, is
// none < notify < isolate < freeze: observe, then alert, then sever the
// network (reversible, process lives), then freeze the tree (reversible). The
// choice is a pure function of the event kind, the score, the mode, and a little
// context — so it is auditable and testable; the app layer actuates it and adds
// escalation (a second high verdict for an already-contained process moves it up
// the ladder) and de-escalation (a quiet contained process is auto-released).
package response

import (
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

// Thresholds are the score cut-offs (mirrors config.Thresholds).
type Thresholds struct {
	Notify  float64
	Contain float64
}

// Context is the little extra an event carries that changes proportionality.
type Context struct {
	Interactive  bool
	RaisedToRoot bool
}

// Rung orders actions by invasiveness so escalation can compare them.
func Rung(a action.Type) int {
	switch a {
	case action.Notify:
		return 1
	case action.Isolate:
		return 2
	case action.Freeze:
		return 3
	case action.Kill:
		return 4
	default:
		return 0 // None
	}
}

// Decide returns the least-invasive sufficient action for one event.
func Decide(k kind.Kind, score float64, m mode.Mode, t Thresholds, ctx Context) action.Type {
	if m == mode.Learn || score < t.Notify {
		return action.None
	}
	// Below the containment threshold, or not yet allowed to act: alert only.
	if score < t.Contain || m != mode.Enforce {
		return action.Notify
	}
	// Enforce, high confidence: pick containment proportional to the threat.
	switch k {
	case kind.Connect:
		// A reverse shell / C2: sever its network but keep it running (forensics).
		return action.Isolate
	case kind.CredsChange:
		// A real escalation to root with no session is dangerous — freeze it.
		if ctx.RaisedToRoot && !ctx.Interactive {
			return action.Freeze
		}
		return action.Notify
	case kind.Honeytoken, kind.SelfDefense:
		// High-fidelity: an intruder reading a decoy, or attacking the agent.
		return action.Freeze
	case kind.FileWrite:
		// The file itself is restored (self-heal); the writer is often transient,
		// so don't freeze on the write alone — alert and let escalation decide.
		return action.Notify
	case kind.Exec, kind.Enable:
		// Exec-pair novelty and pre-exploit setup are more false-positive prone
		// and inspectable; alert rather than freeze unless escalation says more.
		return action.Notify
	default:
		return action.Notify
	}
}
