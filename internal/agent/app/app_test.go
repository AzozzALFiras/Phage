package app

import (
	"testing"

	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// These tests lock in the containment safety contract. They exist because
// enforce mode once froze SSH logins and locked a server out; the guardrail
// below must never regress.
func TestContainmentSafe(t *testing.T) {
	// A genuine no-session escalation: unprivileged uid now holds root euid,
	// no login behind it, ordinary service process.
	escalation := model.Event{
		Comm: "rootshell", ParentComm: "sh",
		Creds:   model.Credentials{UID: 999, EUID: 0},
		Session: model.Session{Interactive: false, LoginUID: -1},
	}
	if ok, _ := containmentSafe(escalation); !ok {
		t.Error("a no-session root escalation should be containable")
	}

	cases := []struct {
		name string
		ev   model.Event
	}{
		{"interactive admin path", model.Event{
			Comm: "rootshell", Creds: model.Credentials{UID: 1000, EUID: 0},
			Session: model.Session{Interactive: true, LoginUID: 1000},
		}},
		{"sshd child (control plane)", model.Event{
			Comm: "bash", ParentComm: "sshd", Creds: model.Credentials{UID: 1000, EUID: 0},
		}},
		{"systemd itself", model.Event{
			Comm: "systemd", Creds: model.Credentials{UID: 0, EUID: 0},
		}},
		{"exec anomaly, no actual escalation", model.Event{
			Comm: "nc", ParentComm: "node", Creds: model.Credentials{UID: 999, EUID: 999},
		}},
	}
	for _, c := range cases {
		if ok, _ := containmentSafe(c.ev); ok {
			t.Errorf("%s: must NOT be containable", c.name)
		}
	}
}
