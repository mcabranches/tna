#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


/* trace is written to /sys/kernel/debug/tracing/trace_pipe */
/*#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
*/
SEC("xdp")
int xdp_pass_main(struct xdp_md* ctx) {

    //bpf_debug("Return XDP_PASS\n");

    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
