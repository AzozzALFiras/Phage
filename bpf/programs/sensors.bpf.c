// SPDX-License-Identifier: GPL-2.0
/*
 * sensors.bpf.c — Phage's kernel sensor set, compiled as a single object so all
 * programs share one ring buffer map (userspace then has one reader).
 *
 *   on_commit_creds : privilege transitions — a process becoming root.
 *   on_sched_exec   : process executions — a service spawning a shell is the
 *                     universal effect of RCE (PHP/Node/command injection/
 *                     SQLi->OS), caught as a never-before-seen parent->child pair.
 *   on_tcp_connect  : outbound connections — a reverse shell or C2 beacon is the
 *                     universal effect of a foothold phoning home, caught as a
 *                     program that has no history of egressing suddenly dialing out.
 *   on_file_open    : write-opens of persistence/credential files — a webshell
 *                     dropped into the web root, a key appended to
 *                     authorized_keys, a cron job planted. The universal effect
 *                     of an attacker digging in, caught as a program writing an
 *                     artifact class it has never written on this host.
 *
 * Author anywhere; build + attach on Linux with CO-RE (needs kernel BTF). See
 * docs/guides/development.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "common/events.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Address families. These live in UAPI headers, not in kernel BTF, so the
 * CO-RE object has to define them itself. */
#define AF_INET  2
#define AF_INET6 10

/* FMODE_WRITE lives in a kernel header (include/linux/fs.h), not in BTF, so the
 * CO-RE object defines it itself. It is set on any file opened for writing. */
#define FMODE_WRITE 0x2

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} phage_events SEC(".maps");

/* fill_common captures the context every sensor shares. loginuid and the parent
 * comm are read here, in-kernel, so they cannot race a short-lived process. */
static __always_inline void fill_common(struct phage_event *e,
					struct task_struct *task, __u32 kind)
{
	__u64 id = bpf_get_current_pid_tgid();

	e->id = id;
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = id >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->euid = 0;
	e->new_euid = 0;
	e->loginuid = BPF_CORE_READ(task, loginuid.val);
	e->cap_eff = 0;
	e->flags = 0;
	/* network fields default to zero; only on_tcp_connect fills them. */
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->dport = 0;
	e->family = 0;
	e->_pad2 = 0;
	/* path defaults to empty; only on_file_open fills it. The whole field must
	 * be zeroed: a ring-buffer slot is uninitialised memory, so leaving it would
	 * leak kernel stack bytes to userspace. */
	__builtin_memset(e->path, 0, sizeof(e->path));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	BPF_CORE_READ_STR_INTO(&e->pcomm, task, real_parent, comm);
}

/* commit_creds is the one chokepoint every privilege change passes through. */
SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct phage_event *e = bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_CREDS_CHANGE);
	e->new_euid = BPF_CORE_READ(new, euid.val);
	/* kernel_cap_t became a single u64 `val` in Linux 6.3. */
	e->cap_eff = BPF_CORE_READ(new, cap_effective.val);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* sched_process_exec fires after a successful execve; current comm is already
 * the new image. We record it with its parent so userspace can judge whether
 * this parent->child execution is normal for the host. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_sched_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct phage_event *e = bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_EXEC);
	/* mirror the current euid so the raise check still applies to setuid execs */
	e->new_euid = BPF_CORE_READ(task, cred, euid.val);
	/* Fileless execution: an executed image with no directory entry
	 * (i_nlink == 0) — a memfd or a deleted-then-run binary. Legitimate programs
	 * run from linked files, so nlink 0 is a sharp signal of in-memory execution
	 * that disk-based scanners miss, and it holds even if the attacker names the
	 * memfd after a trusted program. */
	if (BPF_CORE_READ(bprm, file, f_inode, __i_nlink) == 0)
		e->flags |= 1;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* tcp_connect is the single chokepoint for TCP active opens (both IPv4 and
 * IPv6 reach it once the destination is set). We read the destination before
 * reserving a ring-buffer slot so filtered connections cost nothing downstream;
 * loopback is dropped in-kernel to keep the hot path and the baseline clean. */
SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	__u8 daddr[16] = {};
	if (family == AF_INET) {
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		/* skc_daddr is network order; its first octet is the low byte. */
		if ((d & 0xff) == 127) /* 127.0.0.0/8 loopback */
			return 0;
		__builtin_memcpy(daddr, &d, sizeof(d));
	} else {
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	struct phage_event *e = bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_CONNECT);
	__builtin_memcpy(e->daddr, daddr, sizeof(e->daddr));
	e->dport = bpf_ntohs(dport);
	e->family = family;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* has_prefix compares a compile-time-constant prefix against the start of the
 * resolved path. n is constant, so the loop fully unrolls to fixed-index loads
 * the verifier accepts without bounds tracking. */
static __always_inline int has_prefix(const char *s, const char *pfx, int n)
{
#pragma unroll
	for (int i = 0; i < n; i++)
		if (s[i] != pfx[i])
			return 0;
	return 1;
}

/* watched_path narrows the firehose of file opens to the directories where
 * persistence and credential tampering actually land. This is a *scoping*
 * filter — the kernel equivalent of choosing to hook tcp_connect for egress —
 * NOT a detection rule: whether a given program writing here is malicious is
 * decided later, by the learned baseline. Over-inclusion only means more for the
 * baseline to learn; the precise artifact class is assigned in userspace. */
static __always_inline int watched_path(const char *p)
{
	return has_prefix(p, "/etc/cron", 9) ||
	       has_prefix(p, "/var/spool/cron", 15) ||
	       has_prefix(p, "/etc/systemd/", 13) ||
	       has_prefix(p, "/run/systemd/system", 19) ||
	       has_prefix(p, "/etc/init.d/", 12) ||
	       has_prefix(p, "/etc/rc", 7) ||
	       has_prefix(p, "/etc/profile", 12) ||
	       has_prefix(p, "/etc/ld.so.", 11) ||
	       has_prefix(p, "/etc/passwd", 11) ||
	       has_prefix(p, "/etc/shadow", 11) ||
	       has_prefix(p, "/etc/sudoers", 12) ||
	       has_prefix(p, "/root/", 6) ||
	       has_prefix(p, "/home/", 6) ||
	       has_prefix(p, "/var/www/", 9) ||
	       has_prefix(p, "/srv/", 5) ||
	       has_prefix(p, "/usr/share/nginx/", 17) ||
	       has_prefix(p, "/usr/local/apache", 17) ||
	       has_prefix(p, "/var/lib/tomcat", 15);
}

/* security_file_open is the LSM chokepoint every file open passes through, and
 * it is on the kernel's allowlist for bpf_d_path(), which resolves the file's
 * full path. We gate on write intent (FMODE_WRITE) and on the path landing in a
 * watched tree, so ordinary reads and ordinary writes cost one path resolution
 * and nothing downstream. The resolved path is categorised in userspace; here we
 * only decide whether the event is worth emitting at all. */
SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	unsigned int mode = BPF_CORE_READ(file, f_mode);
	if (!(mode & FMODE_WRITE))
		return 0;

	char buf[256];
	/* f_path is const in this kernel's BTF; bpf_d_path takes a mutable pointer.
	 * The cast only drops the qualifier — the CO-RE field offset still applies. */
	long len = bpf_d_path((struct path *)&file->f_path, buf, sizeof(buf));
	if (len < 0)
		return 0;
	if (!watched_path(buf))
		return 0;

	struct phage_event *e = bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_FILE);
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), buf);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
