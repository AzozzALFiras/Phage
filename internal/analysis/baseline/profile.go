// Package baseline holds the learned model of a host's normal behavior. In
// learn mode Phage only updates this profile; in alert/enforce mode it is read
// to judge new events. The profile — not a hand-written rulebook — is the
// source of truth for what "normal" means on this host.
package baseline

import "sync"

// Profile is the per-host learned behavior. This first implementation keeps a
// frequency model per feature key: how often each value has been seen. It is
// intentionally simple and will be extended (co-occurrence, decay, continuous
// distributions) — see docs/design/analysis-engine.md.
type Profile struct {
	mu     sync.RWMutex
	counts map[string]map[float64]uint64 // feature -> value -> times seen
	totals map[string]uint64             // feature -> total observations
}

// NewProfile returns an empty profile ready to learn.
func NewProfile() *Profile {
	return &Profile{
		counts: make(map[string]map[float64]uint64),
		totals: make(map[string]uint64),
	}
}

// Observe records a feature value as normal. Called only in learn mode.
func (p *Profile) Observe(key string, value float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts[key] == nil {
		p.counts[key] = make(map[float64]uint64)
	}
	p.counts[key][value]++
	p.totals[key]++
}

// Surprise returns how unexpected (0..1) a feature value is given what has been
// learned. A never-seen value against a well-sampled feature is maximally
// surprising; an unsampled feature is neutral (0) until it has been learned, so
// an empty baseline never fabricates anomalies.
func (p *Profile) Surprise(key string, value float64) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	total := p.totals[key]
	if total == 0 {
		return 0
	}
	seen := p.counts[key][value]
	prob := float64(seen) / float64(total)
	return 1 - prob
}

// Samples reports how many observations back a feature. Callers use it to tell
// "confidently normal" from "not yet learned".
func (p *Profile) Samples(key string) uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.totals[key]
}
