#include "tnafp.bpf.h"


SEC("xdptna")
int xdp_tna_main_0(struct xdp_md* ctx) {

	bpf_tail_call(ctx, &jmp_table, ctx->ingress_ifindex);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

