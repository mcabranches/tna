#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "rewrite_helpers.h"

//#include <iproute2/bpf_elf.h>

#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_JUMP		0x10000000

#define ETH_HLEN        14                /* Total octets in header.         */

/* trace is written to /sys/kernel/debug/tracing/trace_pipe */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })

struct tna_meta_t {
	struct ethhdr *eth;
	struct iphdr *iph;
	struct vlan_hdr *vlh;
	struct bpf_fib_lookup fib_params;
	struct bpf_fdb_lookup fdb_params;
	struct bpf_ipt_lookup ipt_params;
};

__attribute__((section("ingress"), used))
int accept(struct __sk_buff *skb) {
	int rc = TC_ACT_OK;
	void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
	struct tna_meta_t tna_meta = {0};
    tna_meta.eth = NULL;

    if (data_end < data + ETH_HLEN)
        return TC_ACT_OK;
	
	struct ethhdr *eth = data;

	tna_meta.eth = eth;

	tna_meta.fdb_params.ifindex = skb->ingress_ifindex;

	if (tna_meta.eth) {
		bpf_fdb_lookup(skb, &tna_meta.fdb_params, sizeof(tna_meta.fdb_params), tna_meta.eth->h_source, tna_meta.eth->h_dest);
	}

	//bpf_debug("ingress_ifindex: %i\n", tna_meta.fdb_params.ifindex);

	//bpf_debug("egress_ifindex: %i\n", tna_meta.fdb_params.egress_ifindex);

	if (tna_meta.fdb_params.egress_ifindex > 0) {
		rc = bpf_redirect_peer(tna_meta.fdb_params.egress_ifindex, 0);
	}
	//rc = bpf_redirect_peer(26, 0);

	//bpf_debug("rc: %i\n", rc);

	return rc;

    //return TC_ACT_OK;
	//int ret;
	//bpf_debug("ingress ifindex: %i\n", skb->ingress_ifindex);
	//if (skb->ingress_ifindex == 8) {
		//bpf_debug("Here1\n");
	//	return bpf_redirect(10, 0);
	//}
		
	//if (skb->ingress_ifindex == 10) {
		//bpf_debug("Here2\n");
	//	return bpf_redirect(8, 0);
	//}

    //return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
