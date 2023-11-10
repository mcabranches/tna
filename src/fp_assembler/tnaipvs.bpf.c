// Used xdp-tutorial/packet01-parsing/xdp_prog_kern.c as a template
/* SPDX-License-Identifier: GPL-2.0 */
//#include <linux/bpf.h>
#define NULL 0
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define AF_INET 2

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#include <string.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

SEC("xdp_packet_parser")
int xdp_prog_simple(struct xdp_md *ctx)
{
        bpf_printk("...");
        return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
