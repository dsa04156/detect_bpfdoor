// read_record_debug_test.c (XDP 오류 수정)
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h> 
#include <linux/if_ether.h>  
#include <linux/if_link.h>  
#include <bpf/libbpf.h>
// #include <bpf/bpf.h> // bpf_set_link_xdp_fd 등이 여기에 선언되어 있을 수 있으나, libbpf.h가 우선
#include <linux/bpf.h>   // <--- XDP_FLAGS_SKB_MODE 등을 위해 추가
#include <signal.h>
#include <stdbool.h> 
#include <string.h>  

#ifndef SO_DETACH_BPF 
#define SO_DETACH_BPF 27
#endif
#define IP1             0xC0A86401  // 192.168.100.1 (호스트 오더)
#define IP2             0xC0A86402  // 192.168.100.2
#define IPBCAST_SUBNET  0xC0A864FF  // 192.168.100.255
#define MAX_CTRL_PROGS  8
static int num_ctrl_links = 0;
static struct bpf_link *ctrl_links[MAX_CTRL_PROGS];

static struct bpf_object *obj_xdp = NULL;
static struct bpf_object *obj_tc = NULL;
static struct bpf_object *obj_sock = NULL;
static struct bpf_object *obj_ctrl = NULL;

static int xdp_prog_fd = -1;
static int sock_prog_fd = -1;
static int ifindex = 0;      
static int raw_fd = -1;      

static struct bpf_tc_hook g_tc_ingress_hook; 
static bool g_tc_hook_is_active = false; 

static volatile bool exiting = false; 

static bool shell_started         = false;
static bool reverse_shell_connect = false;
static bool reverse_shell_data    = false;

#define EVT_SOCKET_RAW_OPEN      1
#define EVT_SOCKOPT_ATTACH_BPF   2
#define EVT_EXECVE_BASH          3
#define EVT_EXECVE_NC            4
#define EVT_SYSCALL_CONNECT      5
#define EVT_SYSCALL_SENDTO       6
#define EVT_BPF_PROG_ATTACH_DET  7
#define EVT_NETFILTER_HOOK       8

struct ctrl_event {
    uint32_t id;
    uint32_t code;
    __u8  proto;
};

#define MAX_IDS  (1<<20)   // 예: 2^20 엔트리만 추적
static __u8 mask_map[MAX_IDS];

void cleanup(int sig) {
    int err;
    exiting = true; 
    printf("\nCleaning up BPF resources (signal: %d)...\n", sig);

    // 1) XDP 제거
    if (ifindex > 0) { // xdp_prog_fd 유무와 관계없이 인터페이스에 연결된 XDP 제거 시도
        printf("Detaching XDP program from ifindex %d...\n", ifindex);
        // bpf_set_link_xdp_fd의 세 번째 인자는 flags, 제거 시 보통 0
        if (bpf_set_link_xdp_fd(ifindex, -1, 0) < 0) { 
             if (errno != ENOENT) { // ENOENT는 이미 없다는 의미일 수 있음
                fprintf(stderr, "Warning: Failed to detach XDP program cleanly: %s\n", strerror(errno));
             }
        } else {
            printf("XDP program detached.\n");
        }
    }

    // 2) TC Ingress 제거
    if (g_tc_hook_is_active && g_tc_ingress_hook.ifindex > 0) {
        printf("Destroying TC Ingress hook for ifindex %d...\n", g_tc_ingress_hook.ifindex);
        err = bpf_tc_hook_destroy(&g_tc_ingress_hook);
        if (err && err != -ENOENT) {
            fprintf(stderr, "ERROR: bpf_tc_hook_destroy for INGRESS failed: %s\n", strerror(-err));
        } else if (err == 0) {
            printf("TC Ingress hook destroyed successfully.\n");
        } else { 
            printf("TC Ingress hook for ifindex %d was already gone or not managed by this instance.\n", g_tc_ingress_hook.ifindex);
        }
    }

    // 3) SOCK 필터 제거
    if (raw_fd >= 0) { 
        if (sock_prog_fd >= 0) { 
            printf("Detaching BPF socket filter from raw_fd %d...\n", raw_fd);
            if (setsockopt(raw_fd, SOL_SOCKET, SO_DETACH_BPF, &sock_prog_fd, sizeof(sock_prog_fd)) < 0) {
                fprintf(stderr, "Warning: SO_DETACH_BPF for sock_prog_fd failed: %s\n", strerror(errno));
            }
        }
        printf("Closing raw_fd %d...\n", raw_fd);
        close(raw_fd);
        raw_fd = -1; 
    }

    // 4) 컨트롤-플레인 링크 해제
    printf("Destroying %d control-plane BPF links...\n", num_ctrl_links);
    for (int i = 0; i < num_ctrl_links; i++) {
        if (ctrl_links[i]) {
            bpf_link__destroy(ctrl_links[i]);
        }
    }
    num_ctrl_links = 0;

    // 5) BPF 오브젝트들 닫기
    if (obj_xdp) bpf_object__close(obj_xdp);
    if (obj_tc) bpf_object__close(obj_tc);
    if (obj_sock) bpf_object__close(obj_sock);
    if (obj_ctrl) bpf_object__close(obj_ctrl);
    printf("BPF objects closed.\n");

    printf("Cleanup finished. Exiting program.\n");
    exit(0);
}

struct pkt_md { 
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
};

struct rec_event {
    uint32_t    id;
    struct pkt_md md;
};

static void *trace_pipe_reader(void *arg) {
    (void)arg;
    int fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY); 
    if (fd < 0) {
        perror("open trace_pipe");
        return NULL;
    }
    char buf[1024]; 
    printf("Trace pipe reader started...\n");
    while (!exiting) { 
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            // 컨트롤-플레인 로그 파싱
            if (strstr(buf, "[DETECT] execve:") && (strstr(buf, "/bin/sh") || strstr(buf, "bash") || strstr(buf, "nc"))) {
                shell_started = true;
            }
            if (strstr(buf, "[DETECT] connect to") && strstr(buf, ":4444")) {
                reverse_shell_connect = true;
            }
            if (strstr(buf, "[DETECT] sendto to") && strstr(buf, ":4444")) {
                reverse_shell_data = true;
            }
        } else if (n == 0) { 
            // printf("Trace pipe EOF.\n"); // Usually trace_pipe doesn't EOF
        } else { 
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) { 
                usleep(100000); 
                continue;
            }
            perror("read trace_pipe");
            break;
        }
    }
    close(fd);
    printf("Trace pipe reader finished.\n");
    return NULL;
}

static void handle_xdp(void *ctx, int cpu, void *data, __u32 sz) {
    // struct pkt_md *m = data;
    struct rec_event *e = data;
    struct pkt_md    *m = &e->md;
    uint32_t src = ntohl(m->src_ip);
    uint32_t dst = ntohl(m->dst_ip);
    // printf("[XDP]  %s:%u -> %s:%u proto=%u\n",
    //        s, ntohs(m->src_port), d, ntohs(m->dst_port), m->proto);
    // if (!((src == IP1 && dst == IP2) ||
    //       (src == IP2 && dst == IP1) ||
    //       (src == IP1 && dst == IPBCAST_SUBNET)))
    //     return;
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    printf("[XDP]  %s:%u -> %s:%u proto=%u (id=%u)\n",
           s, ntohs(m->src_port), d, ntohs(m->dst_port), m->proto, e->id);

    __u32 id = e->id;
    if (id < MAX_IDS)
        mask_map[id] |= 1 << 0;   // layer 0 = XDP

}

static void handle_tc(void *ctx, int cpu, void *data, __u32 sz) {
    struct rec_event *e = data;
    struct pkt_md    *m = &e->md;

    // 호스트 바이트 오더 비교용
    uint32_t src = ntohl(m->src_ip);
    uint32_t dst = ntohl(m->dst_ip);

    // 192.168.100.1 <-> 192.168.100.2 유니캐스트 & 브로드캐스트 허용
    // if (!((src == IP1 && dst == IP2) ||
    //       (src == IP2 && dst == IP1) ||
    //       (src == IP1 && dst == IPBCAST_SUBNET)))
    //     return;

    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    printf("[TC ]  %s:%u -> %s:%u proto=%u (id=%u)\n",
           s, ntohs(m->src_port),
           d, ntohs(m->dst_port),
           m->proto,
           e->id);

    __u32 id = e->id;
    if (id < MAX_IDS)
        mask_map[id] |= 1 << 1;   // layer 1 = TC
}

static void handle_sock(void *ctx, int cpu, void *data, __u32 sz) {
    struct rec_event *e = data;
    struct pkt_md    *m = &e->md;

    uint32_t src = ntohl(m->src_ip);
    uint32_t dst = ntohl(m->dst_ip);

    if (!((src == IP1 && dst == IP2) ||
          (src == IP2 && dst == IP1) ||
          (src == IP1 && dst == IPBCAST_SUBNET)))
        return;

    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    printf("[SOCK] %s:%u -> %s:%u proto=%u (id=%u)\n",
           s, ntohs(m->src_port),
           d, ntohs(m->dst_port),
           m->proto,
           e->id);

    __u32 id = e->id;
    if (id < MAX_IDS)
        mask_map[id] |= 1 << 2;   // layer 2 = SOCK
}
static bool is_benign_traffic(uint8_t proto, uint16_t dport) {
    if (proto == 1) return true;  // ICMP
    if (dport == 53 || dport == 67 || dport == 68) return true;  // DNS, DHCP
    if (dport == 123 || dport == 514) return true;               // NTP, syslog
    if (dport == 5353 || dport == 5355) return true;             // mDNS, LLMNR
    if (dport == 137 || dport == 138 || dport == 139) return true; // NetBIOS
    return false;
}

static void handle_ctrl(void *ctx, int cpu, void *data, __u32 sz) {
    struct ctrl_event *e = data;
    uint32_t full_id = e->id;
    uint32_t idx     = full_id & (MAX_IDS - 1);
    uint32_t dport   = full_id & 0xFFFF;
    uint32_t code    = e->code;
    uint8_t  proto   = e->proto;

    if (full_id == 0)
        return;
    if (code != EVT_SYSCALL_CONNECT && code != EVT_SYSCALL_SENDTO)
        return;

    uint8_t m = mask_map[idx];
    const char *msg = (code == EVT_SYSCALL_CONNECT) ? "SYSCALL_CONNECT"
                      : (code == EVT_SYSCALL_SENDTO)  ? "SYSCALL_SENDTO"
                      : "UNKNOWN";

    printf("[CTRL] cpu=%d event=%s (code=%u) id=%u proto=%u dport=%u\n",
           cpu, msg, code, full_id, proto, dport);

    // === 불일치 기반 분기 시작 ===
    if ((m & 0x07) == 0) {
        if (is_benign_traffic(proto, dport)) {
            printf("[INFO ] likely benign syscall-only flow: id=%u proto=%u dport=%u\n",
                   full_id, proto, dport);
        } else {
            printf("[ALERT] totally invisible syscall: id=%u proto=%u dport=%u\n",
                   full_id, proto, dport);
        }
    } else if (proto != 1 && !(m & ((1 << 0) | (1 << 1)))) {
        printf("[ALERT] syscall bypassed packet layers: id=%u proto=%u dport=%u mask=0x%02x\n",
               full_id, proto, dport, m);
    } else if (proto != 1 && !(m & (1 << 2))) {
        printf("[ALERT] syscall without socket layer: id=%u proto=%u dport=%u mask=0x%02x\n",
               full_id, proto, dport, m);
    } else {
        printf("[OK   ] full or partial match: id=%u proto=%u dport=%u mask=0x%02x\n",
               full_id, proto, dport, m);
    }

    mask_map[idx] = 0;
}





static void handle_lost(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "[LOST] %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) { 
    struct bpf_program *prog_ctrl_iter; 
    struct bpf_link    *link_ctrl_item; 
    int err;

    struct bpf_program *prog; 
    struct perf_buffer *pb_xdp = NULL, *pb_tc = NULL, *pb_sock = NULL; 
    struct perf_buffer_opts opts_xdp = {}, opts_tc = {}, opts_sock = {};
    int map_fd_xdp, map_fd_tc, map_fd_sock; 

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // libbpf_set_print(LIBBPF_PRINT_WARN); // 주석 처리 또는 콜백 방식으로 변경

    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit");
        return 1;
    }

    pthread_t tid = 0; // 초기화
    if (pthread_create(&tid, NULL, trace_pipe_reader, NULL)) {
        fprintf(stderr, "failed to start trace_pipe reader\n");
        return 1;
    }

    obj_ctrl = bpf_object__open_file("ctrl_probe_v2.o", NULL);
    if (libbpf_get_error(obj_ctrl)) {
        fprintf(stderr, "ERROR: opening ctrl_probe_v2.o: %s\n", strerror(-libbpf_get_error(obj_ctrl)));
        return EXIT_FAILURE; 
    }
    if ((err = bpf_object__load(obj_ctrl))) {
        fprintf(stderr, "ERROR: loading ctrl_probe_v2.o: %d (%s)\n", err, strerror(-err));
        bpf_object__close(obj_ctrl); obj_ctrl = NULL;
        return EXIT_FAILURE;
    }

    int map_fd_wh = bpf_map__fd(
        bpf_object__find_map_by_name(obj_ctrl, "whitelist_ips"));
    if (map_fd_wh < 0) {
        fprintf(stderr, "ERROR: finding 'whitelist_ips' map\n");
        return EXIT_FAILURE;
    }

    /* ★3) 0.0.0.0 등록 (모든 IP 허용) ★ */
    __u32 key_any = 0x00000000;
    __u8  val     = 1;
    if (bpf_map_update_elem(map_fd_wh, &key_any, &val, BPF_ANY) != 0) {
        perror("whitelist_ips add 0.0.0.0");
    }

    /* ★4) 자기 호스트 IP 등록 (192.168.100.1 → 0xC0A86401) ★ */
    // __u32 key_host = htonl(0xC0A86401);
    // if (bpf_map_update_elem(map_fd_wh, &key_host, &val, BPF_ANY) != 0) {
    //     perror("whitelist_ips add host-ip");
    // }

    bpf_object__for_each_program(prog_ctrl_iter, obj_ctrl) {
        link_ctrl_item = bpf_program__attach(prog_ctrl_iter); 
        if (libbpf_get_error(link_ctrl_item)) {
            fprintf(stderr, "ERROR: attaching ctrl prog '%s': %s\n",
                    bpf_program__name(prog_ctrl_iter), strerror(-libbpf_get_error(link_ctrl_item)));
        } else {
            if (num_ctrl_links < MAX_CTRL_PROGS) {
                ctrl_links[num_ctrl_links++] = link_ctrl_item;
                printf("Attached control-plane program: %s\n", bpf_program__name(prog_ctrl_iter));
            } else {
                fprintf(stderr, "Warning: MAX_CTRL_PROGS limit reached, couldn't store link for %s\n", bpf_program__name(prog_ctrl_iter));
                bpf_link__destroy(link_ctrl_item); 
            }
        }
    }
    
   struct perf_buffer *pb_ctrl;
   struct perf_buffer_opts opts_ctrl = {};
   int map_fd_ctrl = bpf_map__fd(
       bpf_object__find_map_by_name(obj_ctrl, "ctrl_events"));
   if (map_fd_ctrl < 0) {
       fprintf(stderr, "ERROR: finding 'ctrl_events' map\n");
       return 1;
   }
   opts_ctrl.sample_cb = handle_ctrl;
   opts_ctrl.lost_cb   = handle_lost;
   pb_ctrl = perf_buffer__new(map_fd_ctrl, 8, &opts_ctrl);
   if (libbpf_get_error(pb_ctrl) || !pb_ctrl) {
       fprintf(stderr, "ERROR: perf_buffer__new for CTRL failed\n");
       return 1;
   }


    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: if_nametoindex for '%s': %s\n", ifname, strerror(errno));
        goto app_cleanup_ctrl_only; 
    }
    printf("Using interface '%s' (ifindex %d)\n", ifname, ifindex);

    obj_xdp = bpf_object__open_file("xdp_record_fixed.o", NULL); 
    if (libbpf_get_error(obj_xdp)) { fprintf(stderr, "ERROR: opening xdp_record_fixed.o: %s\n", strerror(-libbpf_get_error(obj_xdp))); goto app_cleanup; }
    if ((err = bpf_object__load(obj_xdp))) { fprintf(stderr, "ERROR: loading xdp_record_fixed.o: %d (%s)\n", err, strerror(-err)); goto app_cleanup; }
    
    prog = bpf_object__find_program_by_name(obj_xdp, "xdp_record"); 
    if (!prog) { fprintf(stderr, "ERROR: finding program 'xdp_record' in xdp_record_fixed.o\n"); goto app_cleanup; }
    xdp_prog_fd = bpf_program__fd(prog); 
    
    // bpf_xdp_attach 대신 bpf_set_link_xdp_fd 사용
    // 플래그 인자: 0 (기본), XDP_FLAGS_SKB_MODE, XDP_FLAGS_DRV_MODE 등
    // XDP_FLAGS_SKB_MODE를 사용하려면 <linux/bpf.h>가 포함되어야 함 (이미 추가됨)
    if ((err = bpf_set_link_xdp_fd(ifindex, xdp_prog_fd, XDP_FLAGS_SKB_MODE))) { // SKB 모드로 명시적 지정
        fprintf(stderr, "ERROR: attaching XDP prog (bpf_set_link_xdp_fd) to ifindex %d: %d (%s)\n", ifindex, err, strerror(-err)); goto app_cleanup;
    }
    printf("XDP program 'xdp_record' attached to ifindex %d using bpf_set_link_xdp_fd.\n", ifindex);

    map_fd_xdp = bpf_map__fd(bpf_object__find_map_by_name(obj_xdp, "events"));
    if (map_fd_xdp < 0) { fprintf(stderr, "ERROR: finding 'events' map in xdp_record_fixed.o (err %d)\n", map_fd_xdp); goto app_cleanup; }
    opts_xdp.sample_cb = handle_xdp;
    opts_xdp.lost_cb   = handle_lost; 
    pb_xdp = perf_buffer__new(map_fd_xdp, 8, &opts_xdp); 
    if (libbpf_get_error(pb_xdp) || !pb_xdp) {
        fprintf(stderr, "ERROR: perf_buffer__new for XDP failed: %s\n", strerror(-libbpf_get_error(pb_xdp))); goto app_cleanup;
    }

    obj_tc = bpf_object__open_file("tc_record_fixed.o", NULL); 
    if (libbpf_get_error(obj_tc)) { fprintf(stderr, "ERROR: opening tc_record_fixed.o: %s\n", strerror(-libbpf_get_error(obj_tc))); goto app_cleanup; }
    if ((err = bpf_object__load(obj_tc))) { fprintf(stderr, "ERROR: loading tc_record_fixed.o: %d (%s)\n", err, strerror(-err)); goto app_cleanup; }
    
    prog = bpf_object__find_program_by_name(obj_tc, "tc_record"); 
    if (!prog) { fprintf(stderr, "ERROR: finding program 'tc_record' in tc_record_fixed.o\n"); goto app_cleanup; }
    int current_tc_prog_fd = bpf_program__fd(prog); 

    memset(&g_tc_ingress_hook, 0, sizeof(g_tc_ingress_hook));
    g_tc_ingress_hook.sz = sizeof(g_tc_ingress_hook);
    g_tc_ingress_hook.ifindex = ifindex;
    g_tc_ingress_hook.attach_point = BPF_TC_INGRESS; 

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_opts_var, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS); // 변수명 변경
    err = bpf_tc_hook_create(&tc_hook_opts_var); 
    if (err && err != -EEXIST) {
        fprintf(stderr, "ERROR: bpf_tc_hook_create for INGRESS failed: %s (if 'clsact' qdisc missing, run 'sudo tc qdisc add dev %s clsact')\n", strerror(-err), ifname);
        goto app_cleanup;
    }
    memcpy(&g_tc_ingress_hook, &tc_hook_opts_var, sizeof(struct bpf_tc_hook));
    g_tc_hook_is_active = true; 
    if (err == 0) printf("TC Ingress hook created for ifindex %d.\n", ifindex);
    else printf("TC Ingress hook for ifindex %d already exists.\n", ifindex);
    
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_prog_opts, .prog_fd = current_tc_prog_fd, .flags = BPF_TC_F_REPLACE);
    err = bpf_tc_attach(&g_tc_ingress_hook, &tc_prog_opts);
    if (err) {
        fprintf(stderr, "ERROR: bpf_tc_attach for INGRESS failed: %s\n", strerror(-err));
        goto app_cleanup;
    }
    printf("TC Ingress program 'tc_record' attached successfully to ifindex %d.\n", ifindex);

    map_fd_tc = bpf_map__fd(bpf_object__find_map_by_name(obj_tc, "events"));
    if (map_fd_tc < 0) { fprintf(stderr, "ERROR: finding 'events' map in tc_record_fixed.o (err %d)\n", map_fd_tc); goto app_cleanup; }
    opts_tc.sample_cb = handle_tc;
    opts_tc.lost_cb   = handle_lost;
    pb_tc = perf_buffer__new(map_fd_tc, 8, &opts_tc);
    if (libbpf_get_error(pb_tc) || !pb_tc) {
        fprintf(stderr, "ERROR: perf_buffer__new for TC failed: %s\n", strerror(-libbpf_get_error(pb_tc))); goto app_cleanup;
    }

    obj_sock = bpf_object__open_file("sock_record_fixed.o", NULL); 
    if (libbpf_get_error(obj_sock)) { fprintf(stderr, "ERROR: opening sock_record_fixed.o: %s\n", strerror(-libbpf_get_error(obj_sock))); goto app_cleanup; }
    if ((err = bpf_object__load(obj_sock))) { fprintf(stderr, "ERROR: loading sock_record_fixed.o: %d (%s)\n", err, strerror(-err)); goto app_cleanup; }
    
    prog = bpf_object__find_program_by_name(obj_sock, "sock_record"); 
    if (!prog) { fprintf(stderr, "ERROR: finding 'sock_record' in sock_record_fixed.o\n"); goto app_cleanup; }
    sock_prog_fd = bpf_program__fd(prog); 
    
    raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if (raw_fd < 0) { perror("socket for SOCK_RAW"); goto app_cleanup; }
    printf("Raw socket for SOCK_FILTER created (fd: %d)\n", raw_fd);
    
    if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_BPF, &sock_prog_fd, sizeof(sock_prog_fd)) < 0) {
        perror("SO_ATTACH_BPF to raw_fd failed"); goto app_cleanup;
    }
    printf("Socket filter program 'sock_record' attached to raw_fd %d.\n", raw_fd);

    map_fd_sock = bpf_map__fd(bpf_object__find_map_by_name(obj_sock, "events"));
    if (map_fd_sock < 0) { fprintf(stderr, "ERROR: finding 'events' map in sock_record_fixed.o (err %d)\n", map_fd_sock); goto app_cleanup; }
    opts_sock.sample_cb = handle_sock;
    opts_sock.lost_cb   = handle_lost;
    pb_sock = perf_buffer__new(map_fd_sock, 8, &opts_sock);
    if (libbpf_get_error(pb_sock) || !pb_sock) {
        fprintf(stderr, "ERROR: perf_buffer__new for SOCK failed: %s\n", strerror(-libbpf_get_error(pb_sock))); goto app_cleanup;
    }
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    printf("Listening for XDP, TC ingress, SOCK & control-plane events on %s...\n", ifname);
    while (!exiting) { 
        if (pb_xdp) perf_buffer__poll(pb_xdp, 100); 
        if (pb_tc) perf_buffer__poll(pb_tc, 10); 
        if (pb_sock) perf_buffer__poll(pb_sock, 10);
        if (pb_ctrl) perf_buffer__poll(pb_ctrl, 10);

    }

app_cleanup_ctrl_only: 
    if (!g_tc_hook_is_active && !obj_xdp && !obj_sock) { 
        printf("Cleaning up control-plane probes only...\n");
        for (int i = 0; i < num_ctrl_links; i++) {
            if (ctrl_links[i]) bpf_link__destroy(ctrl_links[i]);
        }
        if (obj_ctrl) bpf_object__close(obj_ctrl);
        if (tid) pthread_join(tid, NULL); 
        return EXIT_FAILURE; 
    }

app_cleanup: 
    if (!exiting) {
         printf("Error occurred, initiating cleanup...\n");
         cleanup(0); 
    }
    if (tid) pthread_join(tid, NULL); 
    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS; 
}
