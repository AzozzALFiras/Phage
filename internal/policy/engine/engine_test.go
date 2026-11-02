package engine

import (
	"testing"

	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

func TestDecideRespectsMode(t *testing.T) {
	high := verdict.Verdict{Score: 0.95}
	mid := verdict.Verdict{Score: 0.5}
	low := verdict.Verdict{Score: 0.1}

	cases := []struct {
		mode mode.Mode
		v    verdict.Verdict
		want action.Type
	}{
		{mode.Learn, high, action.None},     // learn never acts, however high the score
		{mode.Alert, high, action.Notify},   // alert notifies but never contains
		{mode.Alert, low, action.None},      // below notify threshold
		{mode.Enforce, high, action.Freeze}, // only enforce contains
		{mode.Enforce, mid, action.Notify},  // mid score: notify, not contain
		{mode.Enforce, low, action.None},
	}
	for _, c := range cases {
		got := New(c.mode).Decide(c.v, 1).Type
		if got != c.want {
			t.Errorf("mode=%v score=%.2f: got %v, want %v", c.mode, c.v.Score, got, c.want)
		}
	}
}

func TestDecideUsesTunedThresholds(t *testing.T) {
	// A stricter contain threshold must change the outcome for the same score.
	v := verdict.Verdict{Score: 0.85}
	if got := New(mode.Enforce).Decide(v, 1).Type; got != action.Freeze {
		t.Fatalf("default contain 0.8: score 0.85 should freeze, got %v", got)
	}
	strict := NewWithThresholds(mode.Enforce, Thresholds{Notify: 0.4, Contain: 0.9})
	if got := strict.Decide(v, 1).Type; got != action.Notify {
		t.Fatalf("contain 0.9: score 0.85 should only notify, got %v", got)
	}
}
