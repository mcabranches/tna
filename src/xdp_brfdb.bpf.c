#include "xdp_brfdb.bpf.h"


SEC("xdpfdb")
int xdp_br_main_0(struct xdp_md* ctx) {

	return l2_br_fwd_fpm(ctx);
}

char _license[] SEC("license") = "GPL";