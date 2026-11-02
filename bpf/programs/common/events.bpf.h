/* events.bpf.h — the shared event layout between the eBPF programs and the
 * userspace decoder (internal/sensor/decode). Keep the two in sync: the ring
 * buffer carries these raw bytes, so only fixed-size fields are allowed.
 */
#ifndef PHAGE_EVENTS_BPF_H
#define PHAGE_EVENTS_BPF_H

#define PHAGE_COMM_LEN 16

enum phage_event_kind {
	PHAGE_EVT_UNKNOWN      = 0,
	PHAGE_EVT_EXEC         = 1,
	PHAGE_EVT_CREDS_CHANGE = 2,
	PHAGE_EVT_CAPSET       = 3,
};

/* One privilege-relevant event as captured in-kernel. Userspace enriches it
 * with lineage, session and container context before analysis. */
struct phage_event {
	__u64 id;                   /* pid_tgid at capture time */
	__u64 ts_ns;                /* bpf_ktime_get_ns */
	__u32 kind;                 /* enum phage_event_kind */
	__u32 pid;
	__u32 ppid;
	__u32 uid;                  /* current real uid */
	__u32 euid;                 /* current effective uid */
	__u32 new_euid;             /* creds_change: the euid being committed */
	__u32 loginuid;             /* audit login uid; 0xFFFFFFFF if no login session */
	__u32 _pad;                 /* keep cap_eff 8-byte aligned; mirrored in Go */
	__u64 cap_eff;              /* effective capability set */
	char  comm[PHAGE_COMM_LEN];
};

#endif /* PHAGE_EVENTS_BPF_H */
