#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"


/* trace is written to /sys/kernel/debug/tracing/trace_pipe */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })

//struct bpf_map_def SEC("maps") tx_port = {
//	.type = BPF_MAP_TYPE_DEVMAP,
//	.key_size = sizeof(int),
//	.value_size = sizeof(int),
//	.max_entries = 10,
//};

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 20);
	__type(key, int);
	__type(value, int);
} tx_port SEC(".maps");


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
		bpf_debug("XDP forward\n");
		return bpf_redirect_map(&tx_port, fdb_params.egress_ifindex, 0);
	}

	if (fdb_params.flags == 0) {
		return XDP_PASS;
	}

	if (fdb_params.flags == 2) {
		return XDP_DROP;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
