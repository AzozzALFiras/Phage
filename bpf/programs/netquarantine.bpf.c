// SPDX-License-Identifier: GPL-2.0
/*
 * netquarantine.bpf.c — per-process network quarantine (the reversible response
 * rung between "alert" and "freeze"). Attached to a dedicated cgroup that a
 * suspect process has been moved into, these cgroup/connect hooks DENY new
 * outbound connections (loopback excepted), so a reverse shell or C2 beacon
 * cannot dial out — while the process keeps running, so forensics survive and an
 * operator can inspect it. Detaching (release) restores connectivity.
 *
 * Separate object, attached per-cgroup by userspace; it governs only the cgroup
 * it is attached to, never the whole host.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* return 1 = allow the connect, 0 = deny (connect() returns EPERM). */

SEC("cgroup/connect4")
int netq_connect4(struct bpf_sock_addr *ctx)
{
	__u32 d = ctx->user_ip4; /* destination, network byte order */
	if (d == 0)
		return 1;            /* unspecified */
	if ((d & 0xff) == 127)
		return 1;            /* 127.0.0.0/8 loopback */
	return 0;                    /* deny egress */
}

SEC("cgroup/connect6")
int netq_connect6(struct bpf_sock_addr *ctx)
{
	/* allow ::1 (loopback): first three words 0, last == htonl(1) */
	if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
	    ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1))
		return 1;
	return 0; /* deny egress */
}
