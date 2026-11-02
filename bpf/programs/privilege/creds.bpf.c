// SPDX-License-Identifier: GPL-2.0
/*
 * creds.bpf.c — observes credential transitions: the exact moment a process
 * changes its privileges or becomes root. This is the primary sensor for
 * Phage's privilege-escalation module.
 *
 * Why commit_creds: every privilege change in the kernel is finalised here,
 * whatever syscall or exploit triggered it. Hooking this one function means a
 * transition to root cannot slip past us by using a different code path.
 *
 * STATUS: CO-RE skeleton. Builds on Linux with clang + libbpf against a kernel
 * exposing BTF (CONFIG_DEBUG_INFO_BTF=y). It does NOT build on macOS — author
 * here, compile and attach on the Linux target. See docs/guides/development.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "../common/events.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring buffer carrying phage_event records to userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} phage_events SEC(".maps");

/*
 * commit_creds(struct cred *new) is called as the new credential set is
 * committed to the task. We read the effective uid being installed; userspace
 * decides — against the learned baseline — whether this transition is normal.
 * The eBPF program itself makes no judgement.
 */
SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct phage_event *e =
		bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e)
		return 0; /* buffer full: drop rather than block the kernel */

	__u64 id = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->id = id;
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = PHAGE_EVT_CREDS_CHANGE;
	e->pid = id >> 32;
	e->ppid = 0; /* filled by userspace enrichment from /proc or a task map */
	e->uid = (__u32)uid_gid;
	e->euid = 0; /* current euid; refined in userspace */
	e->new_euid = BPF_CORE_READ(new, euid.val);
	/* kernel_cap_t became a single u64 `val` in Linux 6.3; older kernels used
	 * cap[2]. We target modern BTF kernels, so read `val` directly. */
	e->cap_eff = BPF_CORE_READ(new, cap_effective.val);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
