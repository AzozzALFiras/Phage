// Package engine turns an explainable Verdict into an Action given the current
// operating Mode. Detection lives upstream in the scorer; this layer only
// decides how forcefully to respond. It is deliberately small and auditable:
// the thresholds are data, not buried logic.
package engine

import (
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

// Thresholds map an anomaly score to a response intent. They are config-driven
// so operators tune aggressiveness without touching code.
type Thresholds struct {
	Notify  float64 // at/above this score, raise an alert
	Contain float64 // at/above this score, contain (enforce mode only)
}

// DefaultThresholds are conservative on purpose.
func DefaultThresholds() Thresholds {
	return Thresholds{Notify: 0.4, Contain: 0.8}
}

// Engine decides responses for a given mode.
type Engine struct {
	Mode       mode.Mode
	Thresholds Thresholds
}

// New returns an Engine for a mode with default thresholds.
func New(m mode.Mode) *Engine {
	return &Engine{Mode: m, Thresholds: DefaultThresholds()}
}

// Decide maps a verdict to an action under the current mode. The default
// containment is Freeze, not Kill: freezing is reversible, so a false positive
// can be released instead of leaving a dead process behind.
func (e *Engine) Decide(v verdict.Verdict, pid int32) action.Action {
	reason := e.reason(v)

	switch e.Mode {
	case mode.Learn:
		return action.Action{Type: action.None, PID: pid, Reason: reason}

	case mode.Alert:
		if v.Score >= e.Thresholds.Notify {
			return action.Action{Type: action.Notify, PID: pid, Reason: reason}
		}

	case mode.Enforce:
		switch {
		case v.Score >= e.Thresholds.Contain:
			return action.Action{Type: action.Freeze, PID: pid, Reason: reason}
		case v.Score >= e.Thresholds.Notify:
			return action.Action{Type: action.Notify, PID: pid, Reason: reason}
		}
	}

	return action.Action{Type: action.None, PID: pid, Reason: reason}
}

func (e *Engine) reason(v verdict.Verdict) string {
	if top := v.Top(); top.Detail != "" {
		return top.Detail
	}
	return "no anomalous features"
}
