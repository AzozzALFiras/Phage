package response

import (
	"testing"

	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/response/action"
)

func TestDecideProportionality(t *testing.T) {
	th := Thresholds{Notify: 0.4, Contain: 0.8}
	svc := Context{Interactive: false, RaisedToRoot: false}
	root := Context{Interactive: false, RaisedToRoot: true}

	cases := []struct {
		name  string
		k     kind.Kind
		score float64
		m     mode.Mode
		ctx   Context
		want  action.Type
	}{
		{"learn never acts", kind.Connect, 1.0, mode.Learn, svc, action.None},
		{"below notify = none", kind.Exec, 0.2, mode.Enforce, svc, action.None},
		{"mid score = notify", kind.Connect, 0.6, mode.Enforce, svc, action.Notify},
		{"alert mode never contains", kind.Connect, 1.0, mode.Alert, svc, action.Notify},
		{"egress contains via isolate", kind.Connect, 1.0, mode.Enforce, svc, action.Isolate},
		{"no-session root freezes", kind.CredsChange, 0.9, mode.Enforce, root, action.Freeze},
		{"in-session root only notifies", kind.CredsChange, 0.9, mode.Enforce, Context{Interactive: true, RaisedToRoot: true}, action.Notify},
		{"honeytoken freezes", kind.Honeytoken, 1.0, mode.Enforce, svc, action.Freeze},
		{"self-defense freezes", kind.SelfDefense, 1.0, mode.Enforce, svc, action.Freeze},
		{"file write notifies (healed separately)", kind.FileWrite, 0.9, mode.Enforce, svc, action.Notify},
		{"exec notifies (FP-prone)", kind.Exec, 0.95, mode.Enforce, svc, action.Notify},
		{"enable notifies (pre-exploit)", kind.Enable, 0.9, mode.Enforce, svc, action.Notify},
	}
	for _, c := range cases {
		if got := Decide(c.k, c.score, c.m, th, c.ctx); got != c.want {
			t.Errorf("%s: Decide = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRungOrdering(t *testing.T) {
	if !(Rung(action.None) < Rung(action.Notify) &&
		Rung(action.Notify) < Rung(action.Isolate) &&
		Rung(action.Isolate) < Rung(action.Freeze)) {
		t.Fatal("rung ordering is wrong")
	}
}
