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


struct tna_meta_t {
    struct ethhdr *eth;
	struct iphdr *iph;
	struct vlan_hdr *vlh;
    struct bpf_fib_lookup fib_params;
    struct bpf_fdb_lookup fdb_params;
	struct bpf_ipt_lookup ipt_params;
};

/* based on include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int l3_br_fwd_fpm(struct xdp_md* ctx, struct tna_meta_t* tna_meta)
{
	int rc;
	struct bpf_fib_lookup fib_params = {0};

	
	//bpf_ipt_lookup(ctx, NULL, sizeof(struct bpf_ipt_lookup), 0);


	fib_params.family	= AF_INET;
	fib_params.tos		= tna_meta->iph->tos;
	fib_params.l4_protocol	= tna_meta->iph->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= bpf_ntohs(tna_meta->iph->tot_len);
	fib_params.ipv4_src	= tna_meta->iph->saddr;
	fib_params.ipv4_dst	= tna_meta->iph->daddr;

	fib_params.ifindex = ctx->ingress_ifindex;
		
	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		ip_decrease_ttl(tna_meta->iph);

		__builtin_memcpy(tna_meta->eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(tna_meta->eth->h_source, fib_params.smac, ETH_ALEN);

		tna_meta->vlh->h_vlan_TCI = bpf_htons(fib_params.h_vlan_TCI);
		tna_meta->fdb_params.vid = fib_params.h_vlan_TCI;

		bpf_fdb_lookup(ctx, &tna_meta->fdb_params, sizeof(tna_meta->fdb_params), tna_meta->eth->h_source, tna_meta->eth->h_dest);

		//bpf_ipt_lookup tests
		bpf_debug("Executing\n");
		tna_meta->ipt_params.ifindex = fib_params.ifindex;
		tna_meta->ipt_params.egress_ifindex = tna_meta->fdb_params.egress_ifindex;
		bpf_ipt_lookup(ctx, &tna_meta->ipt_params, sizeof(struct bpf_ipt_lookup), tna_meta->iph);

		bpf_debug("verdict: %i\n", tna_meta->ipt_params.verdict);
		if (tna_meta->ipt_params.verdict == 255)
			return XDP_DROP;

		if (tna_meta->fdb_params.egress_ifindex > 0) {
			bpf_debug("ifindex: %i", tna_meta->fdb_params.egress_ifindex);
			return bpf_redirect_map(&tx_port, tna_meta->fdb_params.egress_ifindex, 0);
		}
	}
	return XDP_PASS;
}

static __always_inline int l2_br_fwd_fpm(struct xdp_md* ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    struct tna_meta_t tna_meta = {0};
    //tna_meta.fdb_params;
    tna_meta.eth = NULL;
    tna_meta.iph = NULL;
    tna_meta.vlh = NULL;
	struct collect_vlans vlans = {0};
 

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	tna_meta.fdb_params.ifindex = ctx->ingress_ifindex;
	/* Start parsing */
	/* need to disable vlan offloads for VLANs to work... "sudo ethtool -K <device> rxvlan off 
	 * TNA should call this only if valan filtering is enabled on a bridge. 
	 * Otherwise parse_ethhdr should be called 
	 */
	nh_type = parse_ethhdr_vlan(&nh, data_end, &tna_meta.eth, &vlans);
	
	tna_meta.fdb_params.vid = vlans.id[0];

	if (tna_meta.eth) {
		bpf_fdb_lookup(ctx, &tna_meta.fdb_params, sizeof(tna_meta.fdb_params), tna_meta.eth->h_source, tna_meta.eth->h_dest);
	}

	if (tna_meta.fdb_params.egress_ifindex > 0 && tna_meta.fdb_params.flags == 1) {
		//Is it possible to see if the port is untagged via the helper?
		if (tna_meta.fdb_params.egress_ifindex == 5)
			vlan_tag_pop(ctx, tna_meta.eth);
		return bpf_redirect_map(&tx_port, tna_meta.fdb_params.egress_ifindex, 0);
	}

	if (tna_meta.fdb_params.flags == 0) { //STP learning
		return XDP_PASS;
	}

	if (tna_meta.fdb_params.flags == 2) { //STP blocked
		return XDP_DROP;
	}

	//This should only be deployed if bridge vlan interfaces have IP addresses configured on them
	if (tna_meta.fdb_params.flags == 3 && nh_type == bpf_htons(ETH_P_IP)) {
		bpf_debug("Needs routing\n");
		tna_meta.iph = nh.pos;

		if (tna_meta.iph + 1 > data_end)
			return XDP_DROP;

		tna_meta.vlh = (void *)(tna_meta.eth + 1);

		if (tna_meta.vlh + 1 > data_end)
			return XDP_DROP;
    

		return l3_br_fwd_fpm(ctx, &tna_meta);
	}
	return XDP_PASS;
}
