#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "rewrite_helpers.h"

#define AF_INET		2	/* Internet IP Protocol 	*/
#define ETH_P_IP        0x0800                /* Internet Protocol packet        */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

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

	


SEC("TNAFPM")
int tnabr(struct xdp_md* ctx)

{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct tna_meta_t tna_meta = {0};
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
		//if (tna_meta.fdb_params.egress_ifindex == 5)
		//	vlan_tag_pop(ctx, tna_meta.eth);
					return bpf_redirect_map(&tx_port, tna_meta.fdb_params.egress_ifindex, 0);
					}

	if (tna_meta.fdb_params.flags == 0) { //STP learning
				return XDP_PASS;
					}

	if (tna_meta.fdb_params.flags == 2) { //STP blocked
				return XDP_DROP;
					}

	
		return XDP_PASS;
		}

char _license[] SEC("license") = "GPL";
