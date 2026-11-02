package behavioral

import (
	"strings"
	"testing"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
)

// trainNormal teaches the profile what this host's normal looks like: root is
// only ever reached inside an interactive login, never by an unprivileged
// process with no session.
func trainNormal(p *baseline.Profile, n int) {
	normal := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      0,
		feature.FeatRaiseNoSession:    0,
		feature.FeatInteractiveOrigin: 1,
		feature.FeatHasTTY:            1,
		feature.FeatLineageDepth:      2,
		feature.FeatParentComm:        111,
	}
	for i := 0; i < n; i++ {
		for k, v := range normal {
			p.Observe(k, v)
		}
	}
}

func TestAttackScoresHighWithReason(t *testing.T) {
	p := baseline.NewProfile()
	trainNormal(p, 100)
	a := New(p)

	attack := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      1,
		feature.FeatRaiseNoSession:    1, // never seen in training
		feature.FeatInteractiveOrigin: 0, // never seen in training
		feature.FeatHasTTY:            0,
		feature.FeatLineageDepth:      4,
		feature.FeatParentComm:        999, // unknown parent
	}
	v := a.Score(attack)
	if v.Score < 0.7 {
		t.Fatalf("attack score = %.2f, want >= 0.7", v.Score)
	}
	joined := ""
	for _, r := range v.Reasons {
		joined += r.Detail + " | "
	}
	if !strings.Contains(joined, "no login session") {
		t.Errorf("expected a 'no login session' reason, got: %s", joined)
	}
}

func TestNormalScoresLow(t *testing.T) {
	p := baseline.NewProfile()
	trainNormal(p, 100)
	a := New(p)

	normal := feature.Vector{
		feature.FeatGainedRoot:        1,
		feature.FeatRaisedToRoot:      0,
		feature.FeatRaiseNoSession:    0,
		feature.FeatInteractiveOrigin: 1,
		feature.FeatHasTTY:            1,
		feature.FeatLineageDepth:      2,
		feature.FeatParentComm:        111,
	}
	if v := a.Score(normal); v.Score > 0.2 {
		t.Fatalf("normal score = %.2f, want <= 0.2", v.Score)
	}
}

func TestEmptyBaselineIsNeutral(t *testing.T) {
	// With nothing learned, Surprise is 0 everywhere, so no false positives.
	a := New(baseline.NewProfile())
	v := a.Score(feature.Vector{feature.FeatRaiseNoSession: 1})
	if v.Score != 0 {
		t.Fatalf("empty-baseline score = %.2f, want 0", v.Score)
	}
}
