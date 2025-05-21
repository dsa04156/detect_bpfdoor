#include "common.h"
#include <linux/if_ether.h>   // ETH_P_IP, struct ethhdr
#include <linux/ip.h>         // struct iphdr
#include <linux/udp.h>        // struct udphdr, IPPROTO_UDP
#include <linux/tcp.h>        // struct tcphdr, IPPROTO_TCP
#include <linux/in.h>         // AF_INET
#include <linux/pkt_cls.h>    // TC_ACT_OK
#include <bpf/bpf_helpers.h>

SEC("classifier")
int tc_record(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr  ip;
    struct pkt_md md = {};
    __u32 offset = 0;

    // 1) Ethernet header
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // 2) IP header
    offset = sizeof(eth);
    if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return TC_ACT_OK;
    md.src_ip = ip.saddr;
    md.dst_ip = ip.daddr;
    md.proto  = ip.protocol;

    // 3) L4 header
    offset += ip.ihl * 4;
    if (md.proto == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
            goto out;
        md.src_port = tcp.source;
        md.dst_port = tcp.dest;
    } else if (md.proto == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
            goto out;
        md.src_port = udp.source;
        md.dst_port = udp.dest;
    }

out:
    // 4) Compute ID and emit rec_event
    {
        // __u32 src_h   = bpf_ntohl(md.src_ip);
        // __u32 dst_h   = bpf_ntohl(md.dst_ip);
        // __u16 sport_h = bpf_ntohs(md.src_port);
        // __u16 dport_h = bpf_ntohs(md.dst_port);
        // __u32 id      = src_h ^ dst_h ^ sport_h ^ dport_h ^ ((__u32)md.proto << 16);
        __u32 dst_h   = bpf_ntohl(md.dst_ip);
        __u16 dport_h = bpf_ntohs(md.dst_port);
        __u32 id      = (dst_h << 16) | dport_h;
        
        struct rec_event evt = {
            .id = id,
            .md = md,
        };
        // Store in map and emit to user-space
        bpf_map_update_elem(&record_map, &id, &evt, BPF_ANY);
        bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";