// common.h
#ifndef COMMON_H
#define COMMON_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// user‐space로 이벤트를 전달할 perf map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} events SEC(".maps");

#endif // COMMON_H
