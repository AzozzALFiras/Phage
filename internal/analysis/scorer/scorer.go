// Package scorer defines the behavioral-model seam. A Scorer maps a feature
// Vector to an explainable Verdict. This is the single extension point for
// "intelligence": today a statistical anomaly model, tomorrow ML. The contract
// never changes — features in, explainable verdict out — so everything around
// it stays stable.
package scorer

import (
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
)

// Scorer judges how anomalous a feature Vector is for this host.
type Scorer interface {
	Score(feature.Vector) verdict.Verdict
}
