// Package mode defines Phage's operating posture. Every deployment starts in
// Learn, graduates to Alert once the baseline is trusted, and only then to
// Enforce. This ladder is the single most important guard against false
// positives — an immature baseline can never act.
package mode

import "fmt"

// Mode is the agent's current posture.
type Mode uint8

const (
	Learn   Mode = iota // observe only; update the baseline, never act
	Alert               // score and notify; still never act
	Enforce             // score, notify, and contain
)

func (m Mode) String() string {
	switch m {
	case Learn:
		return "learn"
	case Alert:
		return "alert"
	case Enforce:
		return "enforce"
	default:
		return "unknown"
	}
}

// Parse converts a config string into a Mode.
func Parse(s string) (Mode, error) {
	switch s {
	case "learn":
		return Learn, nil
	case "alert":
		return Alert, nil
	case "enforce":
		return Enforce, nil
	default:
		return Learn, fmt.Errorf("unknown mode %q (want learn|alert|enforce)", s)
	}
}
