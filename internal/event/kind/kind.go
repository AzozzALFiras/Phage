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
	Connect     Kind = "connect"      // outbound TCP connection (egress)
	FileWrite   Kind = "file_write"   // write-open of a persistence/credential file
	Enable      Kind = "enable"       // high-risk kernel-enabling op (userns/bpf/io_uring/uffd)
	SelfDefense Kind = "self_defense" // tamper attempt against the agent (signal/ptrace)
	Honeytoken  Kind = "honeytoken"   // a process opened a planted decoy file
	SSHAuth     Kind = "ssh_auth"     // sshd authentication outcome
	SessionOpen Kind = "session_open" // login / PAM session start
)

func (k Kind) String() string { return string(k) }
