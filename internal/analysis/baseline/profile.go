// Package baseline holds the learned model of a host's normal behavior. In
// learn mode Phage only updates this profile; in alert/enforce mode it is read
// to judge new events. The profile — not a hand-written rulebook — is the
// source of truth for what "normal" means on this host.
package baseline

import (
	"strconv"
	"sync"
)

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

// Snapshot is the serialisable form of a Profile. Feature values are keyed by
// their decimal string so the counts survive JSON (which has no float keys).
type Snapshot struct {
	Counts map[string]map[string]uint64 `json:"counts"`
	Totals map[string]uint64            `json:"totals"`
}

// Export returns a serialisable copy of the learned state.
func (p *Profile) Export() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := Snapshot{
		Counts: make(map[string]map[string]uint64, len(p.counts)),
		Totals: make(map[string]uint64, len(p.totals)),
	}
	for key, byVal := range p.counts {
		m := make(map[string]uint64, len(byVal))
		for val, n := range byVal {
			m[strconv.FormatFloat(val, 'g', -1, 64)] = n
		}
		s.Counts[key] = m
	}
	for key, n := range p.totals {
		s.Totals[key] = n
	}
	return s
}

// Import replaces this profile's state with the snapshot's, in place, so any
// scorer already holding this *Profile sees the loaded data.
func (p *Profile) Import(s Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts = make(map[string]map[float64]uint64, len(s.Counts))
	p.totals = make(map[string]uint64, len(s.Totals))
	for key, byVal := range s.Counts {
		m := make(map[float64]uint64, len(byVal))
		for valStr, n := range byVal {
			v, err := strconv.ParseFloat(valStr, 64)
			if err != nil {
				continue
			}
			m[v] = n
		}
		p.counts[key] = m
	}
	for key, n := range s.Totals {
		p.totals[key] = n
	}
}
