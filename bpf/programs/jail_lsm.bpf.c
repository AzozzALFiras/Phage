// SPDX-License-Identifier: GPL-2.0
/*
 * jail_lsm.bpf.c — eBPF-LSM enforcement for auto-jail (M3). Where seccomp cannot
 * stop a service's own post-startup execve (systemd needs execve to start it,
 * and seccomp can't tell startup from later), an LSM hook can: it runs on the
 * exec itself and can deny it per cgroup.
 *
 * This is "exec-lock": a cgroup listed in exec_locked may not execve ANY new
 * program. Applied to a service AFTER it has finished starting, it means an
 * exploited service — a webshell, an injected command — cannot spawn sh, bash,
 * curl, or anything else. The service keeps running; it just can't launch new
 * programs, which a long-lived daemon never needs to do anyway.
 *
 * Safety: default-allow. Only a cgroup explicitly added to exec_locked by
 * userspace is affected, so sshd, systemd, and everything else are untouched,
 * and detaching the program (closing the link) lifts enforcement instantly.
 *
 * Requires a kernel booted with BPF LSM active (bpf in /sys/kernel/security/lsm).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

/* exec_locked holds the cgroup v2 ids under exec-lock (value 1 = locked). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} exec_locked SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_guard, struct linux_binprm *bprm, int ret)
{
	/* Respect a denial from an earlier LSM in the stack; never turn a deny
	 * into an allow. */
	if (ret != 0)
		return ret;

	__u64 cg = bpf_get_current_cgroup_id();
	__u8 *locked = bpf_map_lookup_elem(&exec_locked, &cg);
	if (locked && *locked)
		return -EPERM;
	return 0;
}
