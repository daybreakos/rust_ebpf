#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct datarec {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_stats_prog(struct xdp_md *ctx) {
    __u32 key = 0;
    struct datarec *rec;

    /* Bounds checking for the verifier */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data + 1 > data_end) 
        return XDP_PASS;

    __u64 pkt_sz = data_end - data;

    rec = bpf_map_lookup_elem(&pkt_count, &key);
    if (rec) {
        rec->packets++;
        rec->bytes += pkt_sz;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


// basic version :
// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
//
// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, u64);
// } pkt_count SEC(".maps");
//
// SEC("xdp")
// int xdp_stats_prog(struct xdp_md *ctx) {
//     u32 key = 0;
//     u64 *value;
//
//     // Direct packet access bounds checking
//     void *data_end = (void *)(long)ctx->data_end;
//     void *data = (void *)(long)ctx->data;
//     if (data + 14 > data_end) return XDP_PASS;
//
//     value = bpf_map_lookup_elem(&pkt_count, &key);
//     if (value) {
//         *value += 1;
//     }
//
//     return XDP_PASS;
// }
//
// char LICENSE[] SEC("license") = "GPL";
