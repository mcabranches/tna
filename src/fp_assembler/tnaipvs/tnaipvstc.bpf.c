/* SPDX-License-Identifier: GPL-2.0 */

#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define NULL 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */

#define TC_ACT_OK 0

#define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
({ \
    char __fmt[] = fmt; \
    bpf_trace_printk(__fmt, sizeof(__fmt), ##__VA_ARGS__); \
})
#else
#define bpf_debug(fmt, ...) \
({ \
    while (0); \
})
#endif

SEC("action")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    if (ctx->protocol != bpf_htons(ETH_P_IP)) {
        bpf_debug("Not IPv4? %x, but expected %x\n", ctx->protocol, bpf_htons(ETH_P_IP));
        return TC_ACT_OK;
    }

    l2 = data;
    if ((void *)(l2 + 1) > data_end) {
        bpf_debug("Failed data lengths for l2\n");
        return TC_ACT_OK;
    }

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end) {
        bpf_debug("Failed data length for l3\n");
        return TC_ACT_OK;
    }

    bpf_debug("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";