// sock_record.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>  // struct ethhdr, ETH_P_IP
#include <linux/ip.h>        // struct iphdr
#include <linux/udp.h>       // struct udphdr, IPPROTO_UDP
#include <linux/tcp.h>       // struct tcphdr, IPPROTO_TCP
#include <linux/in.h>        // IPPROTO_* constants

// perf 이벤트 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} events SEC(".maps");

// 공통 패킷 메타데이터 구조체
struct pkt_md {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

SEC("socket")
int sock_record(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr  ip;
    struct pkt_md md = {};
    __u32 offset = 0;

    // 이더넷 헤더 읽기
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return 0;

    // IP 헤더 읽기
    offset = sizeof(eth);
    if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0)
        return 0;
    md.src_ip = ip.saddr;
    md.dst_ip = ip.daddr;
    md.proto  = ip.protocol;

    // L4 헤더 읽기
    offset += ip.ihl * 4;
    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_skb_load_bytes(skb, offset, &tcp, sizeof(tcp)) < 0)
            goto out;
        md.src_port = tcp.source;
        md.dst_port = tcp.dest;
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_skb_load_bytes(skb, offset, &udp, sizeof(udp)) < 0)
            goto out;
        md.src_port = udp.source;
        md.dst_port = udp.dest;
    }

out:
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &md, sizeof(md));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
