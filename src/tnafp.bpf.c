#include "tnafp.bpf.h"

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

SEC("xdptc")
int xdp_tna_main_0(struct __sk_buff *skb) {

	bpf_tail_call(skb, &jmp_table, 0);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

