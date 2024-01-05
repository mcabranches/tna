/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/parsing_helpers.h"

#define NULL 0
#define AF_INET 2
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

#define TC_ACT_OK 0

#define DEST_IP 0x201010a

#define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
({ \
    char __fmt[] = fmt; \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})
#else
#define bpf_debug(fmt, ...) \
({ \
    while (0); \
})
#endif

// Update the checksum
static inline __u16 incr_check_l(__u16 old_check, __u32 old, __u32 new)
{ /* see RFC's 1624, 1141 and 1071 for incremental checksum updates */
	__u32 l;
	old_check = ~(old_check);
	old = ~old;
	l = (__u32)old_check + (old>>16) + (old&0xffff)
		+ (new>>16) + (new&0xffff);
	return (~( (__u16)(l>>16) + (l&0xffff) ));
}

SEC("action")
int tc_ingress(struct __sk_buff *ctx)
{
    // raw data ptrs
    void *data     = (void *)(__u64)ctx->data;
    void *data_end = (void *)(__u64)ctx->data_end;

    // default action
    __u32 action = TC_ACT_OK;

    // headers
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;

    // keep track of next headers and header data
    struct hdr_cursor nh;
    int nh_type, nxthdr;
    int len;

    // used to do fib lookup to get updated mac address
    struct bpf_fib_lookup fib_params = {};
    int rc;

    /*
    // Used to lookup ip addr
    struct bpf_ip_vs_lookup params = {
        .in = 0
    };
    */

    // Start next header cursor position at data start
    nh.pos = (void *)(__u64)ctx->data;

    // Check that ethernet type is ipv4
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type != bpf_htons(ETH_P_IP)) {
        bpf_debug("Not IPv4? %x, but expected %x\n", ctx->protocol, bpf_htons(ETH_P_IP));
        goto out;
    }

    nxthdr = parse_iphdr(&nh, data_end, &iphdr);
    if (nxthdr != IPPROTO_TCP) {
        bpf_debug("Not TCP? %x, but expected %x\n", nxthdr, IPPROTO_TCP);
        goto out;
    }

    len = parse_tcphdr(&nh, data_end, &tcphdr);
    if (len < 0) {
        bpf_debug("Failed to parse TCP header? len=%x\n", len);
        goto out;
    }

    /*
    // TODO: perform lookup
    params.source_port = tcphdr->source;
    params.dest_port = tcphdr->dest;
    bpf_ip_vs_lookup(data, &params, sizeof(params), iphdr);	
    if (!params.in) {
        bpf_debug("Lookup failed? sport=%x, dport=%x\n", tcphdr->source, tcphdr->dest);
        goto out;
    }
    bpf_debug("Lookup succeeded, dest: %x\n", params.in);
    */

    // Rewrite the destination IP address to be the returned destination.
	iphdr->check = incr_check_l(iphdr->check, iphdr->daddr, DEST_IP);
	bpf_debug("Forward IP check = %x, %x, %x\n", (__u16)iphdr->check, iphdr->daddr, DEST_IP);
	tcphdr->check = incr_check_l(tcphdr->check, iphdr->daddr, DEST_IP);
	bpf_debug("Forward TCP check = %x, %x, %x\n", tcphdr->check, iphdr->daddr, DEST_IP);
	iphdr->daddr = DEST_IP;

    fib_params.family	= AF_INET;
	fib_params.tos		= iphdr->tos;
	fib_params.l4_protocol	= iphdr->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= bpf_ntohs(iphdr->tot_len);
	fib_params.ipv4_src	= iphdr->saddr;
	fib_params.ipv4_dst	= iphdr->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    bpf_debug("Got IPv4 TCP packet\n");
out:
    return action;
}

char __license[] SEC("license") = "GPL";