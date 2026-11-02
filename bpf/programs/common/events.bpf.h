/* events.bpf.h — the shared event layout between the eBPF programs and the
 * userspace decoder (internal/sensor/decode). Keep the two in sync: the ring
 * buffer carries these raw bytes, so only fixed-size fields are allowed.
 */
#ifndef PHAGE_EVENTS_BPF_H
#define PHAGE_EVENTS_BPF_H

#define PHAGE_COMM_LEN 16
#define PHAGE_PATH_LEN 160

enum phage_event_kind {
	PHAGE_EVT_UNKNOWN      = 0,
	PHAGE_EVT_EXEC         = 1,
	PHAGE_EVT_CREDS_CHANGE = 2,
	PHAGE_EVT_CAPSET       = 3,
	PHAGE_EVT_CONNECT      = 4, /* outbound TCP connection (egress) */
	PHAGE_EVT_FILE         = 5, /* write-open of a persistence/credential file */
};

/* One privilege-relevant event as captured in-kernel. Userspace enriches it
 * with lineage, session and container context before analysis.
 *
 * The layout is a fixed 272 bytes with no implicit padding, so userspace can
 * decode it with a single fixed-size read. If you change a field, keep the
 * total an 8-byte multiple and update the Go mirror in internal/sensor/decode
 * (its layout test guards the contract). */
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
	__u8  daddr[16];            /* connect: destination IP, network order (v4 in first 4 bytes) */
	__u16 dport;                /* connect: destination port, host order */
	__u16 family;               /* connect: AF_INET (2) or AF_INET6 (10) */
	__u32 _pad2;                /* round the record to 112 bytes; mirrored in Go */
	char  comm[PHAGE_COMM_LEN];  /* this process (new image name after exec) */
	char  pcomm[PHAGE_COMM_LEN]; /* immediate parent's comm (race-free, from kernel) */
	char  path[PHAGE_PATH_LEN];  /* file event: resolved write path (bpf_d_path), truncated */
};

#endif /* PHAGE_EVENTS_BPF_H */
