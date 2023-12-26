#include "tnafp.tc.bpf.h"


SEC("tc")
int tc_tna_main_0(struct __sk_buff *ctx) {

	bpf_tail_call(ctx, &jmp_table, ctx->ingress_ifindex);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

