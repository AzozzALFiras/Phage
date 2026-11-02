// SPDX-License-Identifier: GPL-2.0
/*
 * jail_lsm.bpf.c — eBPF-LSM enforcement for auto-jail (M3). Where seccomp cannot
 * stop a service's own post-startup execve (systemd needs execve to start it,
 * and seccomp can't tell startup from later), an LSM hook can: it runs on the
 * exec itself and can allow or deny it per cgroup.
 *
 * Per cgroup it has a mode (same learn -> enforce ladder as detection):
 *   LEARN   — record every program the service execs (by executable inode),
 *             allow all. Run while the service does its normal work.
 *   ENFORCE — allow only the programs learned; deny anything new with EPERM.
 *             An ENFORCE cgroup with an empty allow-set is a strict exec-lock
 *             (no new program at all), which is the right policy for a service
 *             that never execs after startup.
 *
 * So an exploited service can launch only the handful of helpers it legitimately
 * uses, never sh/bash/curl it has never run — learned per service, not guessed.
 *
 * Safety: default-allow. Only a cgroup given a mode by userspace is affected, so
 * sshd/systemd are untouched, and detaching the program lifts everything.
 * Requires a kernel booted with the BPF LSM active (bpf in the active LSM list).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define JAIL_OFF     0
#define JAIL_LEARN   1
#define JAIL_ENFORCE 2

/* jail_mode: cgroup v2 id -> mode (see JAIL_*). Absent/OFF means not jailed. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} jail_mode SEC(".maps");

/* allowed_exec: (cgroup id, FNV-1a hash of the executable path) -> 1. The set
 * of programs each jailed service may execve, filled in LEARN and consulted in
 * ENFORCE. We key on the PATH, not the inode: coreutils/busybox ship as a single
 * multi-call binary where date, id, sleep, cat, ... are all hardlinks to one
 * inode, so an inode key would let "allow date" silently allow "id". The path
 * (bprm->filename) distinguishes the hardlinks. */
struct exec_key {
	__u64 cgid;
	__u64 path_hash;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct exec_key);
	__type(value, __u8);
} allowed_exec SEC(".maps");

#define PATH_BUF_LEN 256
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME  1099511628211ULL

/* path_hash reads the executable path the caller passed to execve and hashes it
 * (FNV-1a 64-bit). Reading into a fixed buffer and breaking on NUL keeps the
 * loop bounded for the verifier. */
static __always_inline __u64 path_hash(struct linux_binprm *bprm)
{
	char buf[PATH_BUF_LEN] = {};
	const char *fn = BPF_CORE_READ(bprm, filename);
	long n = bpf_probe_read_kernel_str(buf, sizeof(buf), fn);
	if (n <= 0)
		return 0;

	__u64 h = FNV_OFFSET;
	for (int i = 0; i < PATH_BUF_LEN; i++) {
		if (buf[i] == 0)
			break;
		h ^= (__u64)(unsigned char)buf[i];
		h *= FNV_PRIME;
	}
	return h;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_guard, struct linux_binprm *bprm, int ret)
{
	/* Respect a denial from an earlier LSM; never turn a deny into an allow. */
	if (ret != 0)
		return ret;

	__u64 cg = bpf_get_current_cgroup_id();
	__u8 *mode = bpf_map_lookup_elem(&jail_mode, &cg);
	if (!mode || *mode == JAIL_OFF)
		return 0;

	struct exec_key k = {};
	k.cgid = cg;
	k.path_hash = path_hash(bprm);

	if (*mode == JAIL_LEARN) {
		__u8 one = 1;
		bpf_map_update_elem(&allowed_exec, &k, &one, BPF_ANY);
		return 0;
	}

	/* ENFORCE */
	if (bpf_map_lookup_elem(&allowed_exec, &k))
		return 0;
	return -EPERM;
}
