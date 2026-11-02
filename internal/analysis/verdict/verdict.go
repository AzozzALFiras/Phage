// Package verdict is the explainable output of the analysis pipeline: a score
// plus the human-readable reasons behind it. Explainability is a first-class
// requirement, not an afterthought — an auto-response nobody can explain is one
// nobody will trust in enforce mode.
package verdict

// Reason explains one contribution to the score.
type Reason struct {
	Feature      string  // feature key from internal/analysis/feature
	Contribution float64 // how much this pushed the score up
	Detail       string  // human sentence, e.g. "root gained with no interactive session"
}

// Verdict is produced per event by a Scorer. Score is normalised to 0.0
// (normal) .. 1.0 (certainly anomalous). The policy layer, not this package,
// turns a score into an action.
type Verdict struct {
	Score   float64
	Reasons []Reason
}

// Top returns the most significant reason, or a zero Reason if there are none.
func (v Verdict) Top() Reason {
	var top Reason
	for _, r := range v.Reasons {
		if r.Contribution > top.Contribution {
			top = r
		}
	}
	return top
}
