// read_record_debug.c
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct pkt_md {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

static void handle_xdp(void *ctx, int cpu, void *data, __u32 sz) {
    struct pkt_md *m = data; char s[16], d[16];
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    printf("[XDP]  %s:%u → %s:%u proto=%u\n",
           s, ntohs(m->src_port), d, ntohs(m->dst_port), m->proto);
}

static void handle_tc(void *ctx, int cpu, void *data, __u32 sz) {
    struct pkt_md *m = data; char s[16], d[16];
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    printf("[TC ]  %s:%u → %s:%u proto=%u\n",
           s, ntohs(m->src_port), d, ntohs(m->dst_port), m->proto);
}

static void handle_sock(void *ctx, int cpu, void *data, __u32 sz) {
    struct pkt_md *m = data; char s[16], d[16];
    
    inet_ntop(AF_INET, &m->src_ip, s, sizeof(s));
    inet_ntop(AF_INET, &m->dst_ip, d, sizeof(d));
    if (strcmp(s, "192.168.100.2") != 0 && strcmp(d, "192.168.100.2") != 0)
        return;

    printf("[SOCK] %s:%u → %s:%u proto=%u\n",
           s, ntohs(m->src_port), d, ntohs(m->dst_port), m->proto);
    fprintf(stderr, "-------------------------------------------------\n");

}

static void handle_lost(void *ctx, int cpu, __u64 cnt) {
    fprintf(stderr, "[LOST] %llu events on CPU %d\n", cnt, cpu);
}

int main(void) {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
        perror("setrlimit");
        return 1;
    }

    int ifindex = if_nametoindex("enp0s8");
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct perf_buffer *pb_xdp, *pb_tc, *pb_sock;
    struct perf_buffer_opts opts_xdp = {}, opts_tc = {}, opts_sock = {};
    int map_fd, prog_fd, raw_fd, err;

    // --- 1) XDP 프로브 ---
    obj = bpf_object__open_file("xdp_record.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: open xdp_record.o: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "ERROR: load xdp_record.o: %d\n", err);
        return 1;
    }
    prog = bpf_object__find_program_by_name(obj, "xdp_record");
    prog_fd = bpf_program__fd(prog);
    if ((err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0))) {
        fprintf(stderr, "ERROR: attach XDP: %d\n", err);
        return 1;
    }
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    opts_xdp.sample_cb = handle_xdp;
    opts_xdp.lost_cb   = handle_lost;
    pb_xdp = perf_buffer__new(map_fd, 8, &opts_xdp);
    if (libbpf_get_error(pb_xdp) || !pb_xdp) {
        fprintf(stderr, "ERROR: perf_buffer XDP: %ld\n",
                libbpf_get_error(pb_xdp));
        return 1;
    }

    // --- 2) TC ingress 프로브 ---
    obj = bpf_object__open_file("tc_record.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: open tc_record.o: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "ERROR: load tc_record.o: %d\n", err);
        return 1;
    }
    prog = bpf_object__find_program_by_name(obj, "tc_record");
    prog_fd = bpf_program__fd(prog);
    // TC attach via libbpf
    {
        struct bpf_tc_hook hook = {
            .sz           = sizeof(hook),
            .ifindex      = ifindex,
            .attach_point = BPF_TC_INGRESS,
        };
        struct bpf_tc_opts opts = {
            .sz    = sizeof(opts),
            .prog_fd = prog_fd,
            .flags = BPF_TC_F_REPLACE,
        };
        bpf_tc_hook_create(&hook);
        bpf_tc_attach(&hook, &opts);
    }
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    opts_tc.sample_cb = handle_tc;
    opts_tc.lost_cb   = handle_lost;
    pb_tc = perf_buffer__new(map_fd, 8, &opts_tc);
    if (libbpf_get_error(pb_tc) || !pb_tc) {
        fprintf(stderr, "ERROR: perf_buffer TC: %ld\n",
                libbpf_get_error(pb_tc));
        return 1;
    }

    // --- 3) Socket Filter 프로브 ---
    obj = bpf_object__open_file("sock_record.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: open sock_record.o: %s\n",
                strerror(-libbpf_get_error(obj)));
        return 1;
    }
    if ((err = bpf_object__load(obj))) {
        fprintf(stderr, "ERROR: load sock_record.o: %d\n", err);
        return 1;
    }
    prog = bpf_object__find_program_by_name(obj, "sock_record");
    prog_fd = bpf_program__fd(prog);
    raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_fd < 0) {
        perror("socket");
        return 1;
    }
    if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF");
        return 1;
    }
    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    opts_sock.sample_cb = handle_sock;
    opts_sock.lost_cb   = handle_lost;
    pb_sock = perf_buffer__new(map_fd, 8, &opts_sock);
    if (libbpf_get_error(pb_sock) || !pb_sock) {
        fprintf(stderr, "ERROR: perf_buffer SOCK: %ld\n",
                libbpf_get_error(pb_sock));
        return 1;
    }

    printf("Listening for XDP, TC ingress & SOCK packets on enp0s8...\n");
    while (1) {
        perf_buffer__poll(pb_xdp,  100);
        perf_buffer__poll(pb_tc,   0);
        perf_buffer__poll(pb_sock, 0);
    }

    return 0;
}
