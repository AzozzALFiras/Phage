// Package action describes what Phage does in response to a verdict. Actions
// are declarative descriptors; the actuators (internal/response/contain and
// internal/response/notify) know how to apply them. Separating "what" from
// "how" keeps every enforcement decision auditable.
package action

// Type enumerates the responses Phage can take, ordered from least to most
// forceful.
type Type string

const (
	None    Type = "none"    // learn mode, or benign
	Notify  Type = "notify"  // raise an alert, take no action on the process
	Freeze  Type = "freeze"  // cgroup-freeze the process tree (reversible)
	Kill    Type = "kill"    // terminate the process (irreversible)
	Isolate Type = "isolate" // cut the process/host network (future)
)

// Action is a decided response bound to a target process. Reason carries the
// verdict's explanation so the audit log always says *why*.
type Action struct {
	Type   Type
	PID    int32
	Reason string
}
