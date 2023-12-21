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

// ip address of the load balancer, 10.1.1.2
#define LB_IP_ADDR 0x201010a

//#define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
({ \
 	char __fmt[] = fmt; \
	bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})
#else
#define bpf_debug(fmt, ...) \
({ \
 	while(0); \
})
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#include <string.h>

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

	// we only support ipv4 right now
	if (nh_type != bpf_htons(ETH_P_IP)) {
		bpf_debug("Packet is not of type ETH_P_IP\n");
		goto out;
	}
	bpf_debug("Packet is of type ETH_P_IP\n");
	

	// Parse the next header - we support only TCP and UDP
	nxthdr = parse_iphdr(&nh, data_end, &iphdr);
	bpf_debug("Packet type? nxthdr=%x IPPROTO_TCP=%x\n", nxthdr, IPPROTO_TCP);
	if (nxthdr == IPPROTO_TCP) {
		bpf_debug("Packet is of type IPPROTO_TCP\n");

		// Parse the TCP header
		len = parse_tcphdr(&nh, data_end, &tcphdr);
		if(len < 0) {
			bpf_debug("Malformed TCP header? This shouldn't happen??\n");
			goto out;
		}

		// Populate the parameter and perform the lookup
		params.source_port = tcphdr->source;
		params.dest_port = tcphdr->dest;
		bpf_ip_vs_lookup(ctx, &params, sizeof(params), iphdr);	
		if (!params.in) {
			bpf_debug("bpf_ip_vs_lookup failed??\n");
			goto out;
		}
		bpf_debug("Lookup returned destination: %x\n", params.in);

		if (params.in != iphdr->saddr) {
			// Rewrite the destination IP address to be the returned destination.
			iphdr->check = incr_check_l(iphdr->check, iphdr->daddr, params.in);
			bpf_debug("Forward IP check = %x, %x, %x\n", (__u16)iphdr->check, iphdr->daddr, params.in);
			tcphdr->check = incr_check_l(tcphdr->check, iphdr->daddr, params.in);
			bpf_debug("Forward TCP check = %x, %x, %x\n", tcphdr->check, iphdr->daddr, params.in);
			iphdr->daddr = params.in;
		} else {
			// If the source is the current machine.... ??
			bpf_debug("Destination is source??: %x -> %x; Ignoring for now...\n", iphdr->saddr, LB_IP_ADDR);

			/*
			iphdr->check = incr_check_l(iphdr->check, iphdr->saddr, LB_IP_ADDR);
			bpf_debug("Back IP check = %x, %x, %x\n", iphdr->check, iphdr->saddr, LB_IP_ADDR);
			tcphdr->check = incr_check_l(tcphdr->check, iphdr->saddr, LB_IP_ADDR);
			bpf_debug("Back TCP check = %x, %x, %x\n", tcphdr->check, iphdr->saddr, LB_IP_ADDR);
			iphdr->saddr = LB_IP_ADDR;
			*/
		}
	} else {
		// Not TCP
		goto out;
	}

	// TODO: some support for UDP? But not tested currently.
	/*
	} else if (nxthdr == IPPROTO_UDP) {
			len = parse_udphdr(&nh, data_end, &udphdr);
			if(len < 0)
				goto out;

			params.source_port = udphdr->source;
			params.dest_port = udphdr->dest;
			bpf_ip_vs_lookup(ctx, &params, sizeof(params), iphdr);
			
			if(!params.in)
				goto out;
			bpf_debug("Dest: %x\n", params.in);
			
			if(params.in == iphdr->saddr) {
				iphdr->check = incr_check_l(iphdr->check, iphdr->saddr, LB_IP_ADDR);
				bpf_debug("Back IP check = %x, %x, %x\n", iphdr->check, iphdr->saddr, LB_IP_ADDR);
				udphdr->check = incr_check_l(udphdr->check, iphdr->saddr, LB_IP_ADDR);
				bpf_debug("Back TCP check = %x, %x, %x\n", udphdr->check, iphdr->saddr, LB_IP_ADDR);
				iphdr->saddr = LB_IP_ADDR;
			}
			else {
				iphdr->check = incr_check_l(iphdr->check, iphdr->daddr, params.in);
				bpf_debug("Forward IP check = %x, %x, %x\n", (__u16)iphdr->check, iphdr->daddr, params.in);
				udphdr->check = incr_check_l(udphdr->check, iphdr->daddr, params.in);
				bpf_debug("Forward TCP check = %x, %x, %x\n", udphdr->check, iphdr->daddr, params.in);
				iphdr->daddr = params.in;
			}
	*/

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
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		// No need ot check nh_type since we only care about IPv4 here.
		//if (nh_type == ETH_P_IP){
		if(iphdr + 1 < data_end) {
			ip_decrease_ttl(iphdr);
		}
		//}
		//else
		//	goto out;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect(fib_params.ifindex, 0);

		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	return action;
}

char _license[] SEC("license") = "GPL";
