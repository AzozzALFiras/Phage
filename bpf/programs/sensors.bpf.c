// SPDX-License-Identifier: GPL-2.0
/*
 * sensors.bpf.c — Phage's kernel sensor set, compiled as a single object so all
 * programs share one ring buffer map (userspace then has one reader).
 *
 *   on_commit_creds : privilege transitions — a process becoming root.
 *   on_sched_exec   : process executions — a service spawning a shell is the
 *                     universal effect of RCE (PHP/Node/command injection/
 *                     SQLi->OS), caught as a never-before-seen parent->child pair.
 *
 * Author anywhere; build + attach on Linux with CO-RE (needs kernel BTF). See
 * docs/guides/development.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common/events.bpf.h"

char LICENSE[] SEC("license") = "GPL";

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
	e->_pad = 0;
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
	bpf_ringbuf_submit(e, 0);
	return 0;
}
