/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/parsing_helpers.h"

#define NULL        0
#define ETH_ALEN    6
#define AF_INET     2
#define ETH_P_IP    0x0800 /* Internet Protocol packet */

#define TC_ACT_OK   0
#define TC_ACT_SHOT	2

#define ORIG_DEST_IP 0x201010a // IP addr on local host that's part of src network
#define NEW_DEST_IP 0x0201a8c0 // IP addr of sink 1

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

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

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

SEC("simple")
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

    // Start next header cursor position at data start
    nh.pos = (void *)(__u64)ctx->data;

    // Check that ethernet type is ipv4
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type != bpf_htons(ETH_P_IP)) {
        //bpf_debug("Not IPv4? %x, but expected %x\n", ctx->protocol, bpf_htons(ETH_P_IP));
        goto out;
    }

    nxthdr = parse_iphdr(&nh, data_end, &iphdr);
    if (nxthdr != IPPROTO_TCP) {
        //bpf_debug("Not TCP? %x, but expected %x\n", nxthdr, IPPROTO_TCP);
        goto out;
    }

    len = parse_tcphdr(&nh, data_end, &tcphdr);
    if (len < 0) {
        bpf_debug("Failed to parse TCP header? len=%x\n", len);
        goto out;
    }

    if (iphdr->daddr != ORIG_DEST_IP) {
        bpf_debug("Packet is not sent to server, expected (10.10.1.2 == %x) but dest ip = %x\n", ORIG_DEST_IP, iphdr->daddr);
        goto out;
    }

    // Rewrite the destination IP address to be the new destination.
	iphdr->check = incr_check_l(iphdr->check, iphdr->daddr, NEW_DEST_IP);
	//bpf_debug("Forward IP check = %x, %x, %x\n", (__u16)iphdr->check, iphdr->daddr, NEW_DEST_IP);
	tcphdr->check = incr_check_l(tcphdr->check, iphdr->daddr, NEW_DEST_IP);
	//bpf_debug("Forward TCP check = %x, %x, %x\n", tcphdr->check, iphdr->daddr, NEW_DEST_IP);
	iphdr->daddr = NEW_DEST_IP;

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
    //bpf_debug("fib lookup returned %x, expected %x\n", rc, BPF_FIB_LKUP_RET_SUCCESS);

	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         // lookup successful
		// No need to check nh_type since we only care about IPv4 here.
		if(iphdr + 1 < data_end) {
			ip_decrease_ttl(iphdr);
		}

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_peer(fib_params.ifindex, 0); // TODO: bpf_redirect_peer...? or bpf_redirect_neigh...?
        bpf_debug("Redirected packet: action=%x", action);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    // dest is blackholed; can be dropped
	case BPF_FIB_LKUP_RET_UNREACHABLE:  // dest is unreachable; can be dropped
	case BPF_FIB_LKUP_RET_PROHIBIT:     // dest not allowed; can be dropped
        bpf_debug("dropping packet based on fib return: %x\n", rc);
		action = TC_ACT_SHOT;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    // packet is not forwarded
	case BPF_FIB_LKUP_RET_FWD_DISABLED: // fwding is not enabled on ingress
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   // fwd requires encapsulation
	case BPF_FIB_LKUP_RET_NO_NEIGH:     // no neighbor entry for nh
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  // fragmentation required to fwd
		// PASS 
        bpf_debug("passing packet based on fib return: %x\n", rc);
		break;
	}
out:
    return action;
}

char __license[] SEC("license") = "GPL";