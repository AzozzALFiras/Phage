// Package kind enumerates the categories of low-level events Phage observes.
// Keeping the vocabulary in its own package stops the rest of the system from
// depending on the raw eBPF wire format.
package kind

// Kind is the category of an observed event.
type Kind string

const (
	Unknown     Kind = "unknown"
	Exec        Kind = "exec"         // execve / execveat
	CredsChange Kind = "creds_change" // commit_creds / setuid family
	CapSet      Kind = "capset"       // capability changes
	SSHAuth     Kind = "ssh_auth"     // sshd authentication outcome
	SessionOpen Kind = "session_open" // login / PAM session start
)

func (k Kind) String() string { return string(k) }
