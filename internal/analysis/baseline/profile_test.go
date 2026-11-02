package baseline

import "testing"

func TestSurpriseIsNoveltyNotRarity(t *testing.T) {
	// A high-cardinality feature: 20 distinct values, each seen 10 times. Every
	// value is a small share of the 200-event total, but all are established —
	// none should be surprising. This is the regression that mattered: a
	// probability-share measure would score each ~0.95 and bury the real signal.
	p := NewProfile()
	for v := 0; v < 20; v++ {
		for i := 0; i < 10; i++ {
			p.Observe("exec.pair", float64(v))
		}
	}
	for v := 0; v < 20; v++ {
		if s := p.Surprise("exec.pair", float64(v)); s != 0 {
			t.Fatalf("established value %d: surprise = %.2f, want 0", v, s)
		}
	}
	// A value never seen is maximally surprising.
	if s := p.Surprise("exec.pair", 999); s != 1 {
		t.Fatalf("novel value: surprise = %.2f, want 1.0", s)
	}
}

func TestSurpriseRampsForWeaklySupportedValues(t *testing.T) {
	p := NewProfile()
	p.Observe("f", 1) // seen once against an otherwise-populated feature
	for i := 0; i < 50; i++ {
		p.Observe("f", 0)
	}
	// Seen only once: partially novel, between 0 and 1.
	s := p.Surprise("f", 1)
	if !(s > 0 && s < 1) {
		t.Fatalf("weakly-supported value: surprise = %.2f, want in (0,1)", s)
	}
}

func TestSurpriseNeutralUntilLearned(t *testing.T) {
	p := NewProfile()
	if s := p.Surprise("never.observed", 1); s != 0 {
		t.Fatalf("unlearned feature: surprise = %.2f, want 0 (no fabricated anomalies)", s)
	}
}
