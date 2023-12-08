#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "rewrite_helpers.h"

#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_P_IP        0x0800                /* Internet Protocol packet        */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 1

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


/* based on include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = (__u32)iph->check;

	check += (__u32)bpf_htons(0x0100);
	iph->check = (__sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

SEC("TNAFPM")

int tnartr(struct __sk_buff *ctx)
{
	int rc;
	void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct tna_meta_t tna_meta = {0};
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

	tna_meta.vlh = (void *)(tna_meta.eth + 1);

	if (tna_meta.vlh + 1 > data_end)
						return TC_ACT_SHOT;
			
	tna_meta.fdb_params.vid = 0;
	struct bpf_fib_lookup fib_params = {0};

	tna_meta.iph = nh.pos;

	if (tna_meta.iph + 1 > data_end)
						return TC_ACT_SHOT;
		

	fib_params.family	= AF_INET;
	fib_params.tos		= tna_meta.iph->tos;
	fib_params.l4_protocol	= tna_meta.iph->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= bpf_ntohs(tna_meta.iph->tot_len);
	fib_params.ipv4_src	= tna_meta.iph->saddr;
	fib_params.ipv4_dst	= tna_meta.iph->daddr;

	fib_params.ifindex = ctx->ingress_ifindex;
		
	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		
		ip_decrease_ttl(tna_meta.iph);

		if (!(tna_meta.eth)) {
			//bpf_debug("Here4");
									return TC_ACT_SHOT;
			 
		}

	 	__builtin_memcpy(tna_meta.eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(tna_meta.eth->h_source, fib_params.smac, ETH_ALEN);
		
    	//#bridge/vlan dependent
					 	tna_meta.fdb_params.vid = fib_params.h_vlan_TCI;

		tna_meta.fdb_params.ifindex = fib_params.ifindex;
        
	 	bpf_fdb_lookup(ctx, &tna_meta.fdb_params, sizeof(tna_meta.fdb_params), tna_meta.eth->h_source, tna_meta.eth->h_dest);
				
        //end of bridge/vlan dependent

        //bridge dependent 
	 	if (tna_meta.fdb_params.egress_ifindex > 0)
	 		return bpf_redirect(tna_meta.fdb_params.egress_ifindex, 0);
	}
    //end of bridge dependent

    //need to add a non bridge dependent redirect (pure l3)
			return TC_ACT_OK;
		
} 

char _license[] SEC("license") = "GPL";