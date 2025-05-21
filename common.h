#ifndef COMMON_H
#define COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   // bpf_ntohl(), bpf_ntohs()

// 네트워크 바이트 오더로 저장되는 패킷 메타데이터
struct pkt_md {
    __u32 src_ip;    // IPv4 source address
    __u32 dst_ip;    // IPv4 destination address
    __u16 src_port;  // L4 source port
    __u16 dst_port;  // L4 destination port
    __u8  proto;     // IP protocol (TCP=6, UDP=17, etc.)
};

// 호스트 바이트 오더 ID + 메타데이터
struct rec_event {
    __u32 id;        // computed in host byte order
    struct pkt_md md;
};

// 첫 레이어 기록용 해시 맵: key=packet ID, value=rec_event
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct rec_event));
    __uint(max_entries, 1024);
} record_map SEC(".maps");

// 유저스페이스 전달용 perf 이벤트 배열
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} events SEC(".maps");

#endif // COMMON_H
