// ctrl_probe_v2_ip_filtered.c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <bpf/bpf_endian.h>   // bpf_htons(), bpf_htonl(), bpf_ntohl()
#include <linux/types.h>      // __be32, __be16

// 부족한 상수 직접 정의
#ifndef AF_INET
#define AF_INET            2
#endif
#ifndef AF_PACKET
#define AF_PACKET         17
#endif
#ifndef SOCK_RAW
#define SOCK_RAW           3
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET         1
#endif
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER  26
#endif
#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF     50
#endif
#ifndef BPF_PROG_ATTACH
#define BPF_PROG_ATTACH    8
#endif
#ifndef BPF_PROG_DETACH
#define BPF_PROG_DETACH    9
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
struct ctrl_event {
    __u32 id;
    __u32 code;
    __u8  proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));   /* 항상 4바이트 */
    __uint(max_entries, 64);
} ctrl_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));   // IPv4 주소 (NBO)
    __uint(value_size, sizeof(__u8));  // 그냥 존재 여부용
    __uint(max_entries, 128);
} whitelist_ips SEC(".maps");

struct trace_event_raw_sys_enter {
    __u64 pad[2];    // <— 반드시 두 칸
    __u64 args[6];   // 여기에 syscall 인수 6개가 들어온다
};


// 이벤트 코드 정의
// 1: PF_PACKET RAW socket open
// 2: SO_ATTACH_{FILTER,BPF}
// 3: execve bash
// 4: execve nc
// 5: connect to TARGET_IP
// 6: sendto to TARGET_IP
// 7: bpf syscall attach/detach
// 8: nf_register_net_hook
#define EVT_SOCKET_RAW_OPEN      1
#define EVT_SOCKOPT_ATTACH_BPF   2
#define EVT_EXECVE_BASH          3
#define EVT_EXECVE_NC            4
#define EVT_SYSCALL_CONNECT      5
#define EVT_SYSCALL_SENDTO       6
#define EVT_BPF_PROG_ATTACH_DET  7
#define EVT_NETFILTER_HOOK       8

// 공용 sockaddr_in 구조체 (tracepoint 로 넘어오는 구조체와 동일 레이아웃)
struct bpf_sockaddr_in {
    __be16 sin_family;
    __be16 sin_port;
    __be32 sin_addr;
};

// 호스트 바이트 오더 상수
#define TARGET_IP_HOST  0xC0A86401U  // 192.168.100.1

// 1) PF_PACKET RAW socket 생성 탐지
SEC("tracepoint/syscalls/sys_enter_socket")
int on_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    int domain = (int)ctx->args[0];
    int type   = (int)ctx->args[1];
    if (domain == AF_PACKET && type == SOCK_RAW) {
        struct ctrl_event evt = {
            .id   = 0,
            .code = EVT_SOCKET_RAW_OPEN,
        };
        bpf_perf_event_output(ctx, &ctrl_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}
// 2) 소켓 필터 attach 탐지
SEC("tracepoint/syscalls/sys_enter_setsockopt")
int on_sys_enter_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    int level   = (int)ctx->args[1];
    int optname = (int)ctx->args[2];
    if (level == SOL_SOCKET &&
       (optname == SO_ATTACH_FILTER || optname == SO_ATTACH_BPF)) {
        struct ctrl_event evt = {
            .id   = 0,
            .code = EVT_SOCKOPT_ATTACH_BPF,
        };
        bpf_perf_event_output(ctx, &ctrl_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}
// 3) execve 호출 탐지 (bash 또는 nc)
SEC("tracepoint/syscalls/sys_enter_execve")
int on_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    char filename[48];
    int len;
    if (bpf_probe_read_user_str(filename, sizeof(filename), (void*)ctx->args[0]) <= 0)
        return 0;
    for (len = 0; len < 47 && filename[len]; len++);
    // 끝이 "bash"인지
    if (len >= 4 &&
        filename[len-4]=='b' &&
        filename[len-3]=='a' &&
        filename[len-2]=='s' &&
        filename[len-1]=='h') {
        struct ctrl_event evt = {
            .id   = 0,
            .code = EVT_EXECVE_BASH,
        };
        bpf_perf_event_output(ctx, &ctrl_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return 0;
    }
    // 끝이 "nc"인지
    if (len >= 2 &&
        filename[len-2]=='n' &&
        filename[len-1]=='c') {
        struct ctrl_event evt = {
            .id   = 0,
            .code = EVT_EXECVE_NC,
        };
        bpf_perf_event_output(ctx, &ctrl_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}

// 4) connect 호출 탐지: IPv4 + 대상 호스트 IP 한정
SEC("tracepoint/syscalls/sys_enter_connect")
int on_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    int fd        = (int)ctx->args[0];
    void *user_sa = (void *)(long)ctx->args[1];
    int addrlen   = (int)ctx->args[2];

    /* 1) 엔트리 로그 */
    // bpf_printk("[DEBUG] connect entry: fd=%d user_sa=%p addrlen=%d\n",
    //            fd, user_sa, addrlen);

    /* sockaddr_in 크기 검증 */
    if (addrlen < sizeof(struct bpf_sockaddr_in))
        return 0;

    /* 사용자 공간에서 sockaddr 읽기 */
    struct bpf_sockaddr_in sa = {};
    int ret = bpf_probe_read_user(&sa, sizeof(sa), user_sa);
    // bpf_printk("[DEBUG] connect read_user ret=%d sin_family=0x%x\n",
    //            ret, sa.sin_family);
    if (ret < 0)
        return 0;

    /* AF_INET 여부 확인 (네트워크 바이트 오더) */
    if (sa.sin_family != AF_INET) {
        // bpf_printk("[DEBUG] skip: family 0x%x != AF_INET(0x%x)\n",
        //            sa.sin_family, bpf_htons(AF_INET));
        return 0;
    }

    /* 타겟 호스트 IP (네트워크 바이트 오더) */
    __be32 tgt_nbo = bpf_htonl(TARGET_IP_HOST);
    // bpf_printk("[DEBUG] tgt_nbo=0x%08x sa.sin_addr=0x%08x\n",
    //            tgt_nbo, sa.sin_addr);

    /* 화이트리스트 조회 (키는 네트워크 바이트 오더 IP) */
    __u8 *ok = bpf_map_lookup_elem(&whitelist_ips, &sa.sin_addr);
    if (ok) {
        // bpf_printk("[DEBUG] %pI4 is whitelisted (skip)\n", &sa.sin_addr);
        return 0;
    }

    __u32 dst_h   = bpf_ntohl(sa.sin_addr);
    __u16 dport_h = bpf_ntohs(sa.sin_port);
    __u32 id      = (dst_h << 16) | dport_h;

    if (dport_h == 53 || dport_h == 67 || dport_h == 68 ||
    dport_h == 123 || dport_h == 514 || dport_h == 5353 || dport_h == 5355 ||
    dport_h == 137 || dport_h == 138 || dport_h == 139) {
    return 0;
    }
    if (dport_h == 443 || dport_h == 80 || dport_h == 53 || dport_h == 123) {
    // HTTPS, HTTP, DNS, NTP 제외
    return 0;
    }
    // 127.0.0.0/8 루프백
    if ((dst_h >> 24) == 127)
        // 10.0.2.0/24 같은 가상 NAT
        if ((dst_h & 0xFF000000) == 0x0A000000)
            return 0;
    // __u32 code = EVT_SYSCALL_CONNECT;
    struct ctrl_event evt = {
        .id   = id,
        .code = EVT_SYSCALL_CONNECT,
        .proto = 6,  // TCP
    };
    // bpf_printk("[DETECT] connect to %pI4:%d\n", &sa.sin_addr, dport_h); 

    bpf_perf_event_output(ctx, &ctrl_events,
        BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}


// 5) sendto 호출 탐지: IPv4 + 대상 호스트 IP 한정
SEC("tracepoint/syscalls/sys_enter_sendto")
int on_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    void *user_sa = (void*)ctx->args[4];
    if (!user_sa)
        return 0;

    __u64 addrlen = ctx->args[5];
    struct bpf_sockaddr_in sa = {};
    __u32 copy_len = addrlen < sizeof(sa) ? addrlen : sizeof(sa);
    int ret = bpf_probe_read_user(&sa, copy_len, user_sa);
    if (ret < 0)
        return 0;

    if (sa.sin_family != AF_INET)
        return 0;

    __u32 dst_h = bpf_ntohl(sa.sin_addr);
    if ((dst_h >> 24) == 127)
        return 0;
    if ((dst_h & 0xFF000000) == 0x0A000000)
        return 0;
    if (dst_h != TARGET_IP_HOST)
        return 0;

    // 포트가 0이면 ICMP로 간주
    int proto = (sa.sin_port == 0) ? IPPROTO_ICMP : IPPROTO_UDP;

    // ICMP는 탐지 제외
    if (proto == IPPROTO_ICMP)
        return 0;

    __u32 id = (dst_h << 16) | bpf_ntohs(sa.sin_port);

    struct ctrl_event evt = {
        .id    = id,
        .code  = EVT_SYSCALL_SENDTO,
        .proto = proto,  // 실제 값 반영
    };

    bpf_printk("[DETECT] sendto to %pI4 (proto=%d)\n", &sa.sin_addr, proto);
    bpf_perf_event_output(ctx, &ctrl_events,
                          BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// 6) bpf() syscall 탐지: attach/detach 명령만
SEC("tracepoint/syscalls/sys_enter_bpf")
int on_sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    int cmd = (int)ctx->args[0];
    if (cmd == BPF_PROG_ATTACH || cmd == BPF_PROG_DETACH) {
        struct ctrl_event evt = {
            .id   = 0,
            .code = EVT_BPF_PROG_ATTACH_DET,
        };
        bpf_perf_event_output(ctx, &ctrl_events,
                              BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    return 0;
}
// 7) Netfilter hook 등록 탐지
SEC("kprobe/nf_register_net_hook")
int kprobe__nf_register_net_hook(struct pt_regs *ctx) {
    struct ctrl_event evt = {
        .id   = 0,
        .code = EVT_NETFILTER_HOOK,
    };
    bpf_perf_event_output(ctx, &ctrl_events,
                          BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";