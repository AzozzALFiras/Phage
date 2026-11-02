// Package behavioral is Phage's first Scorer: a statistical anomaly model that
// scores how far an event's features deviate from the host's learned baseline.
// It encodes no hardcoded attack rules — the baseline alone decides what is
// normal, which is what lets it flag exploits it has never seen before.
package behavioral

import (
	"fmt"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
)

// Anomaly scores feature vectors against a learned baseline profile.
type Anomaly struct {
	profile *baseline.Profile
	// weights lets some features matter more than others without changing the
	// model. Provenance features dominate because a missing session behind a
	// root transition is the strongest escalation signal we have.
	weights map[string]float64
}

// New returns an Anomaly scorer bound to a profile with sensible default
// weights.
func New(p *baseline.Profile) *Anomaly {
	return &Anomaly{
		profile: p,
		weights: map[string]float64{
			// privilege-change features
			feature.FeatRaiseNoSession:    1.0, // raised to root with no login session: the sharpest signal
			feature.FeatRaisedToRoot:      0.7, // unprivileged -> root
			feature.FeatInteractiveOrigin: 0.5,
			feature.FeatParentComm:        0.4, // an unusual parent for a root transition
			feature.FeatGainedRoot:        0.2,
			feature.FeatHasTTY:            0.2,
			// exec features
			feature.FeatExecPair:        1.0, // a never-seen parent->child execution: the RCE effect
			feature.FeatExecInteractive: 0.4,
			feature.FeatExecChild:       0.3,
			// network (egress) features
			feature.FeatNetEgressComm:        1.0, // a program that never egresses dialing out: reverse shell / C2
			feature.FeatNetEgressPair:        0.8, // ...to a port it never uses
			feature.FeatNetEgressInteractive: 0.4,
			feature.FeatNetEgressPort:        0.3,
		},
	}
}

// Score implements scorer.Scorer. The score is the weighted, baseline-relative
// surprise of the event's features; each surprising feature records a reason so
// the verdict can always explain itself.
func (a *Anomaly) Score(v feature.Vector) verdict.Verdict {
	out := verdict.Verdict{}
	if a.profile == nil {
		return out
	}
	var score, weightSum float64
	for key, val := range v {
		w := a.weight(key)
		s := a.profile.Surprise(key, val)
		weightSum += w
		if s <= 0 {
			continue
		}
		// Discount surprise from features that have not yet been observed
		// enough times to trust. This stops a freshly-deployed agent from
		// raising confident alerts off a thin baseline; mature features
		// (>= minConfidentSamples) are unaffected.
		conf := confidence(a.profile.Samples(key))
		contribution := w * s * conf
		if contribution <= 0 {
			continue
		}
		score += contribution
		out.Reasons = append(out.Reasons, verdict.Reason{
			Feature:      key,
			Contribution: contribution,
			Detail:       explain(key, val, s),
		})
	}
	if weightSum > 0 {
		score /= weightSum
	}
	out.Score = clamp01(score)
	return out
}

// minConfidentSamples is how many observations a feature needs before Phage
// trusts its surprise fully. Below it, a feature's contribution is scaled down
// linearly, so "I have barely seen this" never reads as "this is an attack".
const minConfidentSamples = 15

func confidence(samples uint64) float64 {
	if samples >= minConfidentSamples {
		return 1
	}
	return float64(samples) / float64(minConfidentSamples)
}

func (a *Anomaly) weight(key string) float64 {
	if w, ok := a.weights[key]; ok {
		return w
	}
	return 0.1 // unknown features still count a little
}

// explain renders a human reason. It describes the deviation, never a verdict.
func explain(key string, val, surprise float64) string {
	switch key {
	case feature.FeatExecPair:
		return "a program was spawned in a parent->child combination never seen on this host"
	case feature.FeatExecInteractive:
		if val == 0 {
			return "program launched by a service with no interactive session"
		}
	case feature.FeatNetEgressComm:
		return "an outbound connection from a program that has never egressed on this host"
	case feature.FeatNetEgressPair:
		return "an outbound connection to a destination port this program never uses"
	case feature.FeatNetEgressInteractive:
		if val == 0 {
			return "outbound connection from a process with no interactive session"
		}
	case feature.FeatRaiseNoSession:
		if val == 1 {
			return "raised to root with no login session behind it (never seen on this host)"
		}
	case feature.FeatRaisedToRoot:
		if val == 1 {
			return "an unprivileged process raised itself to root"
		}
	case feature.FeatInteractiveOrigin:
		if val == 0 {
			return "privilege change with no interactive session behind it"
		}
	case feature.FeatGainedRoot:
		if val == 1 {
			return "process gained root"
		}
	}
	return fmt.Sprintf("%s=%g is unusual for this host (surprise %.2f)", key, val, surprise)
}

func clamp01(f float64) float64 {
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	default:
		return f
	}
}
