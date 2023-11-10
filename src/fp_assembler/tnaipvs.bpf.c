// Used xdp-tutorial/packet01-parsing/xdp_prog_kern.c as a template
/* SPDX-License-Identifier: GPL-2.0 */
//#include <linux/bpf.h>
#define NULL 0
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define AF_INET 2

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#include <string.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;

	struct bpf_ip_vs_lookup params = {
		.in = 0
	};
	int len;
	int rc;
	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type, nxthdr;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	/* could handle ETH_P_IPV6 but we don't right now */
	if (nh_type != ETH_P_IP) {
		bpf_printk("wrong packet type? actual=%x expected=%x v6=%x\n", nh_type, ETH_P_IP, ETH_P_IPV6);
		goto out;
	}

	//nxthdr = parse_iphdr(&nh, data_end, &iphdr);

	bpf_printk("...");

out:
	return action;
}

char _license[] SEC("license") = "GPL";
