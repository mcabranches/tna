#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "parsing_helpers.h"
#include "rewrite_helpers.h"


#define TC_ACT_UNSPEC   (-1)
#define TC_ACT_OK               0
#define TC_ACT_RECLASSIFY       1
#define TC_ACT_SHOT             2
#define TC_ACT_PIPE             3
#define TC_ACT_STOLEN           4
#define TC_ACT_QUEUED           5
#define TC_ACT_REPEAT           6
#define TC_ACT_REDIRECT         7
#define TC_ACT_JUMP             0x10000000

#define ETH_HLEN        14                /* Total octets in header.         */
#define AF_INET         2       /* Internet IP Protocol         */
#define ETH_P_IP        0x0800                /* Internet Protocol packet 
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

/* based on include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
        __u32 check = (__u32)iph->check;

        check += (__u32)bpf_htons(0x0100);
        iph->check = (__sum16)(check + (check >= 0xFFFF));
        return --iph->ttl;
}


static __always_inline int tnabr(struct __sk_buff *skb, struct tna_meta_t* tna_meta)
{

        int rc;
        //int nh_type;

        //tna_meta->fdb_params.ifindex = skb->ingress_ifindex;


        if (tna_meta->eth) {
                bpf_fdb_lookup(skb, &tna_meta->fdb_params, sizeof(tna_meta->fdb_params), tna_meta->eth->h_source, tna_meta->eth->h_dest);
        }

        if (tna_meta->fdb_params.egress_ifindex > 0 && tna_meta->fdb_params.flags == 1) {
                //Is it possible to see if the port is untagged via the helper?
                //if (tna_meta.fdb_params.egress_ifindex == 5)
                //      vlan_tag_pop(ctx, tna_meta.eth);
                return bpf_redirect_peer(tna_meta->fdb_params.egress_ifindex, 0);
        }

        if (tna_meta->fdb_params.flags == 0) { //STP learning
                return TC_ACT_OK;;
        }

        if (tna_meta->fdb_params.flags == 2) { //STP blocked
                return TC_ACT_SHOT;
        }

            //This should only be deployed if bridge vlan interfaces have IP addresses configured on them
    //Logic for detecting this goes in the "service introspection"
        /* if (tna_meta->fdb_params.flags == 3 && nh_type == bpf_htons(ETH_P_IP)) {
                //bpf_debug("Needs routing\n");
                tna_meta->iph = nh.pos;

                if (tna_meta->iph + 1 > data_end)
                        return XDP_DROP;

                tna_meta->vlh = (void *)(tna_meta->eth + 1);

                if (tna_meta->vlh + 1 > data_end)
                        return XDP_DROP;*/
    

                //return tnartr(skb, &tna_meta);
        //}


    return TC_ACT_OK;
}


__attribute__((section("ingress"), used))
int accept(struct __sk_buff *skb)
{
                //int rc = TC_ACT_OK;
        int rc;
        void *data = (void*)(long)skb->data;
        void *data_end = (void*)(long)skb->data_end;
        struct collect_vlans vlans = {0};
        struct tna_meta_t tna_meta = {0};
        tna_meta.eth = NULL;
        tna_meta.iph = NULL;
        tna_meta.vlh = NULL;

        /* These keep track of the next header type and iterator pointer */
        struct hdr_cursor nh;
        int nh_type;

        nh.pos = data;

        nh_type = parse_ethhdr_vlan(&nh, data_end, &tna_meta.eth, &vlans);

        if (!tna_meta.eth)
            return TC_ACT_SHOT;

        tna_meta.iph = nh.pos;

        if (tna_meta.iph + 1 > data_end)
            return TC_ACT_SHOT;

        tna_meta.fdb_params.vid = vlans.id[0];

        struct bpf_fib_lookup fib_params = {0};

        fib_params.family       = AF_INET;
        fib_params.tos          = tna_meta.iph->tos;
        fib_params.l4_protocol  = tna_meta.iph->protocol;
        fib_params.sport        = 0;
        fib_params.dport        = 0;
        fib_params.tot_len      = bpf_ntohs(tna_meta.iph->tot_len);
        fib_params.ipv4_src     = tna_meta.iph->saddr;
        fib_params.ipv4_dst     = tna_meta.iph->daddr;

        fib_params.ifindex = skb->ingress_ifindex;

        rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), 0);

        
        if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
                        //bpf_debug("Here2\n");
                ip_decrease_ttl(tna_meta.iph);

                __builtin_memcpy(tna_meta.eth->h_dest, fib_params.dmac, ETH_ALEN);
                __builtin_memcpy(tna_meta.eth->h_source, fib_params.smac, ETH_ALEN);

        //#bridge/vlan dependent
                //tna_meta->vlh->h_vlan_TCI = bpf_htons(fib_params.h_vlan_TCI);
                //tna_meta->fdb_params.vid = fib_params.h_vlan_TCI;

        
                //bpf_fdb_lookup(skb, tna_meta.fdb_params, sizeof(tna_meta.fdb_params), tna_meta.eth->h_source, tna_meta->eth->h_dest);
        //#end of bridge/vlan dependent

        //        {% if "tnaipt" in fpms['tnartr'] %}
         //   {% include "tnaipt.fpm" %} 
        //{% endif %}

        //#bridge dependent 
                if (tna_meta.fdb_params.egress_ifindex > 0)
                        //return bpf_redirect_peer(tna_meta->fdb_params.egress_ifindex, 0);
                        return tnabr(skb, &tna_meta);

                }
        //#end of bridge dependent
        //need to add a non bridge dependent redirect (pure l3)
        
        return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";