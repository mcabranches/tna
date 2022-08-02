#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "rewrite_helpers.h"

#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_P_IP        0x0800                /* Internet Protocol packet        */

/* trace is written to /sys/kernel/debug/tracing/trace_pipe */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })


struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 20);
	__type(key, int);
	__type(value, int);
} tx_port SEC(".maps");


/* based on include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}


SEC("xdpfdb")
int xdp_br_main_0(struct xdp_md* ctx) {

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = NULL;
	struct bpf_fdb_lookup fdb_params = {0};
	struct collect_vlans vlans = {0};

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	fdb_params.ifindex = ctx->ingress_ifindex;
	/* Start parsing */
	/* need to disable vlan offloads for VLANs to work... "sudo ethtool -K <device> rxvlan off 
	 * TNA should call this only if valan filtering is enabled on a bridge. 
	 * Otherwise parse_ethhdr should be called 
	 */
	nh_type = parse_ethhdr_vlan(&nh, data_end, &eth, &vlans);

	fdb_params.vid = vlans.id[0];

	if (eth) {
		bpf_fdb_lookup(ctx, &fdb_params, sizeof(fdb_params), eth->h_source, eth->h_dest);
	}

	if (fdb_params.egress_ifindex > 0 && fdb_params.flags == 1) {
		//Is it possible to see if the port is untagged via the helper?
		if (fdb_params.egress_ifindex == 5)
			vlan_tag_pop(ctx, eth);
		return bpf_redirect_map(&tx_port, fdb_params.egress_ifindex, 0);
	}

	if (fdb_params.flags == 0) {
		return XDP_PASS;
	}

	if (fdb_params.flags == 2) {
		return XDP_DROP;
	}

	//add for L3 forwarding
	if (fdb_params.flags == 3) {
		bpf_debug("Needs routing\n");
		if (nh_type == bpf_htons(ETH_P_IP)) {
			struct vlan_hdr *vlh;
			int rc;
			struct iphdr *iph;
			iph = nh.pos;
			if (iph + 1 > data_end)
				return XDP_DROP;
			struct bpf_fib_lookup fib_params;
			__builtin_memset(&fib_params, 0, sizeof(fib_params));
			if (iph->ttl <= 1)
				return XDP_PASS;
			
			fib_params.family	= AF_INET;
			fib_params.tos		= iph->tos;
			fib_params.l4_protocol	= iph->protocol;
			fib_params.sport	= 0;
			fib_params.dport	= 0;
			fib_params.tot_len	= bpf_ntohs(iph->tot_len);
			fib_params.ipv4_src	= iph->saddr;
			fib_params.ipv4_dst	= iph->daddr;

			fib_params.ifindex = ctx->ingress_ifindex;

			rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	
			if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
				/* Verify egress index has been configured as TX-port.
		 		* (Note: User can still have inserted an egress ifindex that
		 		* doesn't support XDP xmit, which will result in packet drops).
		 		*
		 		* Note: lookup in devmap supported since 0cdbb4b09a0.
		 		* If not supported will fail with:
		 		*  cannot pass map_type 14 into func bpf_map_lookup_elem#1:
		 		*/

				//if (!bpf_map_lookup_elem(&tx_port, &fib_params.ifindex))
				//	return XDP_PASS;

				ip_decrease_ttl(iph);

				__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
				__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

				vlh = (void *)(eth + 1);

				if (vlh + 1 > data_end)
					return XDP_DROP;

				vlh->h_vlan_TCI = bpf_htons(fib_params.h_vlan_TCI);
				fdb_params.vid = fib_params.h_vlan_TCI;

				bpf_fdb_lookup(ctx, &fdb_params, sizeof(fdb_params), eth->h_source, eth->h_dest);
				bpf_debug("ifindex: %i\n", fdb_params.egress_ifindex);
				bpf_debug("fdb_params.flags: %i\n", fdb_params.egress_ifindex);



				if (fdb_params.egress_ifindex > 0 && fdb_params.flags == 1) {
					//Is it possible see if the port is untagged via the helper?
					if (fdb_params.egress_ifindex == 5)
						vlan_tag_pop(ctx, eth);

					return bpf_redirect_map(&tx_port, fdb_params.egress_ifindex, 0);
				}
			}
		}
	}
	
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";