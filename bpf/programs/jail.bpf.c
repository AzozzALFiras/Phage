// SPDX-License-Identifier: GPL-2.0
/*
 * jail.bpf.c — the "learn" half of auto-jail (M3), kept in its own object so it
 * is loaded only by `phage-jail profile`, never by the detection daemon. It
 * attaches to the raw syscall-entry tracepoint and records, for ONE target
 * service (identified by cgroup id), which syscall numbers it makes. Userspace
 * turns that set into a least-privilege seccomp profile.
 *
 * It is a profiling tool, not an always-on sensor: sys_enter is the hottest
 * tracepoint in the kernel, so we gate on the target cgroup as the very first
 * thing and do nothing for every other process on the box.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define NR_SYSCALLS 1024 /* margin over the current x86_64 max (~471) */

/* target_cgid[0] is the cgroup v2 id to profile; userspace sets it before the
 * program matters. 0 (the default) profiles nothing, so a mis-wired run is a
 * no-op rather than a firehose. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_cgid SEC(".maps");

/* syscalls_seen[nr] counts invocations of syscall nr by the target cgroup. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NR_SYSCALLS);
	__type(key, __u32);
	__type(value, __u64);
} syscalls_seen SEC(".maps");

SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id)
{
	__u32 zero = 0;
	__u64 *target = bpf_map_lookup_elem(&target_cgid, &zero);
	if (!target || *target == 0)
		return 0;
	if (bpf_get_current_cgroup_id() != *target)
		return 0;

	if (id < 0 || id >= NR_SYSCALLS)
		return 0;
	__u32 key = (__u32)id;
	__u64 *count = bpf_map_lookup_elem(&syscalls_seen, &key);
	if (count)
		__sync_fetch_and_add(count, 1);
	return 0;
}
