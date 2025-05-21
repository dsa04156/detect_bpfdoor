#include "common.h"
#include <linux/if_link.h>    // XDP_FLAGS_* definitions
#include <linux/if_ether.h>   // ETH_P_IP, struct ethhdr
#include <linux/ip.h>         // struct iphdr
#include <linux/udp.h>        // struct udphdr, IPPROTO_UDP
#include <linux/tcp.h>        // struct tcphdr, IPPROTO_TCP
#include <linux/in.h>         // AF_INET


SEC("xdp")
int xdp_record(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip;
    struct pkt_md  md = {};

    /* Ethernet + IPv4 검사 */
    if ((void*)(eth + 1) > data_end)               return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    /* IP 헤더 파싱 */
    ip = (void*)eth + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)               return XDP_PASS;
    md.src_ip = ip->saddr;
    md.dst_ip = ip->daddr;
    md.proto  = ip->protocol;

    /* L4 헤더 파싱 */
    if (md.proto == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + ip->ihl * 4;
        if ((void*)(udp + 1) > data_end)          goto out;
        md.src_port = udp->source;
        md.dst_port = udp->dest;
    } else if (md.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
        if ((void*)(tcp + 1) > data_end)          goto out;
        md.src_port = tcp->source;
        md.dst_port = tcp->dest;
    }

out:
    /* 네트워크 바이트 오더 → 호스트 바이트 오더 변환 후 ID 생성 */
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
        /* 첫 레이어 정보 맵에 기록 */
        bpf_map_update_elem(&record_map, &id, &evt, BPF_ANY);
        /* 유저스페이스로 ID+메타데이터 전송 */
        bpf_perf_event_output(ctx, &events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
