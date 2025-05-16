// ~/BPFDoor/experiments/xpd_test/xdp_record_fixed.c
#include "common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct pkt_md {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

SEC("xdp")
int xdp_record(struct xdp_md *ctx) {
   bpf_printk("XDP_RECORD ENTRY: data=%llx end=%llx\n",
              (unsigned long long)ctx->data,
              (unsigned long long)ctx->data_end);

    // 64-bit 오프셋으로 읽어 옵니다
    __u64 data_off     = ctx->data;
    __u64 data_end_off = ctx->data_end;
    void *data     = (void *)(long)data_off;
    void *data_end = (void *)(long)data_end_off;

    struct ethhdr *eth = data;
    struct iphdr  *ip;
    struct pkt_md  md = {};

    // Ethernet + IPv4 bounds check
    if ((void*)(eth + 1) > data_end)                     return XDP_PASS;
    if (eth->h_proto  != __constant_htons(ETH_P_IP))     return XDP_PASS;

    // IP header
    ip = (void*)eth + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)                     return XDP_PASS;

    md.src_ip = ip->saddr;
    md.dst_ip = ip->daddr;
    md.proto  = ip->protocol;

    // L4 header parse
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + ip->ihl * 4;
        if ((void*)(udp + 1) > data_end)                 goto out;
        md.src_port = udp->source;
        md.dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
        if ((void*)(tcp + 1) > data_end)                 goto out;
        md.src_port = tcp->source;
        md.dst_port = tcp->dest;
    }

out:
   // 디버그: src/dst IP
    bpf_printk("XDP_REC OUT IP: src=%x dst=%x\n",
              md.src_ip, md.dst_ip, 0);
//    // 디버그: 포트/프로토콜 (raw network-order)
    // bpf_printk("XDP_REC OUT L4: sport=%u dport=%u proto=%u\n",
    //           md.src_port,
    //           md.dst_port,
    //           md.proto);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &md, sizeof(md));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
