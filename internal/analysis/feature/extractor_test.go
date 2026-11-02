package feature

import (
	"testing"

	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// A reverse shell and a benign egress to the same program differ only in the
// program and the port; the extractor must key on both so the baseline can tell
// "nginx talks to 443" from "sh talks to 4444".
func TestNetworkExtractKeysOnCommAndPort(t *testing.T) {
	shell := model.Event{
		Comm: "sh",
		Net:  model.NetConn{DestIP: "203.0.113.5", DestPort: 4444, Family: 2},
	}
	v := Network{}.Extract(shell)

	for _, k := range []string{FeatNetEgressComm, FeatNetEgressPort, FeatNetEgressPair, FeatNetEgressInteractive} {
		if _, ok := v[k]; !ok {
			t.Errorf("missing feature %q", k)
		}
	}
	if v[FeatNetEgressPort] != 4444 {
		t.Errorf("port feature = %v, want 4444", v[FeatNetEgressPort])
	}
	if v[FeatNetEgressInteractive] != 0 {
		t.Errorf("interactive = %v, want 0 (no session behind a reverse shell)", v[FeatNetEgressInteractive])
	}

	// Same program, different port, must be a different pair id — otherwise a
	// program's known port would mask a callback to an unknown one.
	other := model.Event{Comm: "sh", Net: model.NetConn{DestPort: 443}}
	if (Network{}).Extract(other)[FeatNetEgressPair] == v[FeatNetEgressPair] {
		t.Error("pair id should differ when the destination port differs")
	}
	// Same port, different program, must also differ.
	diff := model.Event{Comm: "nginx", Net: model.NetConn{DestPort: 4444}}
	if (Network{}).Extract(diff)[FeatNetEgressPair] == v[FeatNetEgressPair] {
		t.Error("pair id should differ when the program differs")
	}
}
