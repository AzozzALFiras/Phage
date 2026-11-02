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
			feature.FeatRaisedToRoot:      0.7, // unprivileged -> root is the sharpest signal
			feature.FeatInteractiveOrigin: 0.6, // ...especially with no login session behind it
			feature.FeatParentComm:        0.4, // an unusual parent for a root transition
			feature.FeatGainedRoot:        0.2,
			feature.FeatHasTTY:            0.2,
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
		contribution := w * s
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

func (a *Anomaly) weight(key string) float64 {
	if w, ok := a.weights[key]; ok {
		return w
	}
	return 0.1 // unknown features still count a little
}

// explain renders a human reason. It describes the deviation, never a verdict.
func explain(key string, val, surprise float64) string {
	switch key {
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
