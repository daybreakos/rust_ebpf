#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "pps_stats.skel.h"

struct datarec {
    __u64 packets;
    __u64 bytes;
};

static volatile bool keep_running = true;
void sig_handler(int sig) { keep_running = false; }

int main(int argc, char **argv) {
    struct pps_stats_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int ifindex, err;
    const char *ifname;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", ifname);
        return 1;
    }

    skel = pps_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load eBPF skeleton\n");
        return 1;
    }

    /* 1. Attachment Logic */
    link = bpf_program__attach_xdp(skel->progs.xdp_stats_prog, ifindex);
    if (link) {
        printf(">>> Running in Mode: NATIVE (Driver)\n");
    } else {
        printf("Native mode failed. Attempting Generic (SKB) fallback...\n");
        err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_stats_prog), 
                             XDP_FLAGS_SKB_MODE, NULL);
        if (err < 0) {
            fprintf(stderr, "Error: Failed to attach XDP: %d\n", err);
            goto cleanup; // Safe to jump now; no VLAs in this scope yet
        }
        printf(">>> Running in Mode: GENERIC (SKB)\n");
    }

    /* 2. PROTECTED SCOPE for Stats Logic 
     * This allows us to use VLAs without breaking the goto cleanup logic.
     */
    {
        int nr_cpus = libbpf_num_possible_cpus();
        struct datarec values[nr_cpus]; // VLA defined here
        __u64 prev_pkts = 0, prev_bytes = 0;
        int map_fd = bpf_map__fd(skel->maps.pkt_count);

        signal(SIGINT, sig_handler);
        printf("Monitoring %s... (Ctrl+C to stop)\n", ifname);
        printf("%-12s | %-12s | %-12s | %-12s\n", "PPS", "Mbps", "Avg Size", "Total Pkts");
        printf("------------------------------------------------------------------\n");

        while (keep_running) {
            __u32 key = 0;
            __u64 total_pkts = 0, total_bytes = 0;

            if (bpf_map_lookup_elem(map_fd, &key, values) != 0) {
                fprintf(stderr, "Map lookup failed\n");
                break;
            }

            for (int i = 0; i < nr_cpus; i++) {
                total_pkts += values[i].packets;
                total_bytes += values[i].bytes;
            }

            __u64 delta_pkts = total_pkts - prev_pkts;
            __u64 delta_bytes = total_bytes - prev_bytes;
            __u64 avg_size = (delta_pkts > 0) ? (delta_bytes / delta_pkts) : 0;
            double mbps = (delta_bytes * 8.0) / 1000000.0;

            printf("%-12llu | %-12.2f | %-12llu | %-12llu\n", 
                   delta_pkts, mbps, avg_size, total_pkts);

            prev_pkts = total_pkts;
            prev_bytes = total_bytes;
            sleep(1);
        }
    }

cleanup:
    if (link) bpf_link__destroy(link);
    else bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    
    pps_stats_bpf__destroy(skel);
    printf("\nGracefully detached. System clean.\n");
    return 0;
}

// version 2
// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <signal.h>
// #include <net/if.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
// #include "pps_stats.skel.h"
//
// // Define the same struct as in the BPF code
// struct datarec {
//     __u64 packets;
//     __u64 bytes;
// };
//
// static volatile bool keep_running = true;
// void sig_handler(int sig) { keep_running = false; }
//
// int main(int argc, char **argv) {
//     struct pps_stats_bpf *skel;
//     struct bpf_link *link = NULL;
//     int ifindex, nr_cpus = libbpf_num_possible_cpus();
//     struct datarec values[nr_cpus];
//     __u64 prev_pkts = 0, prev_bytes = 0;
//
//     if (argc < 2) { printf("Usage: %s <iface>\n", argv[0]); return 1; }
//     ifindex = if_nametoindex(argv[1]);
//
//     skel = pps_stats_bpf__open_and_load();
//     link = bpf_program__attach_xdp(skel->progs.xdp_stats_prog, ifindex);
//     if (!link) { /* fallback logic as discussed before */ }
//
//     int map_fd = bpf_map__fd(skel->maps.pkt_count);
//     signal(SIGINT, sig_handler);
//
//     while (keep_running) {
//         __u32 key = 0;
//         __u64 total_pkts = 0, total_bytes = 0;
//
//         bpf_map_lookup_elem(map_fd, &key, values);
//         for (int i = 0; i < nr_cpus; i++) {
//             total_pkts += values[i].packets;
//             total_bytes += values[i].bytes;
//         }
//
//         __u64 pps = total_pkts - prev_pkts;
//         __u64 eps = total_bytes - prev_bytes; // Bytes per second
//         __u64 avg_size = (pps > 0) ? (eps / pps) : 0;
//
//         printf("PPS: %10llu | Mbps: %10llu | Avg Size: %llu B\n", 
//                 pps, (eps * 8) / 1000000, avg_size);
//
//         prev_pkts = total_pkts;
//         prev_bytes = total_bytes;
//         sleep(1);
//     }
//
//     bpf_link__destroy(link);
//     pps_stats_bpf__destroy(skel);
//     return 0;
// }

// // Basic version:
// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <signal.h>
// #include <net/if.h>
// #include <linux/if_link.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
//
// #include "pps_stats.skel.h" 
//
// static volatile bool keep_running = true;
// void sig_handler(int sig) { keep_running = false; }
//
// int main(int argc, char **argv) {
//     struct pps_stats_bpf *skel = NULL;
//     struct bpf_link *link = NULL;
//     int err, ifindex;
//     const char *ifname;
//
//     // 1. Handle Command Line Arguments
//     if (argc < 2) {
//         fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
//         fprintf(stderr, "Example: sudo %s eth0\n", argv[0]);
//         return 1;
//     }
//     ifname = argv[1];
//
//     ifindex = if_nametoindex(ifname);
//     if (ifindex == 0) {
//         fprintf(stderr, "Error: Invalid interface %s\n", ifname);
//         return 1;
//     }
//
//     // 2. Prepare CPU-specific value storage
//     int nr_cpus = libbpf_num_possible_cpus();
//     __u64 values[nr_cpus];
//     __u64 prev_total = 0;
//
//     // 3. Load and Verify BPF application
//     skel = pps_stats_bpf__open_and_load();
//     if (!skel) {
//         fprintf(stderr, "Failed to load/verify BPF skeleton\n");
//         return 1;
//     }
//
//     // 4. Modern libbpf (1.0+) Attachment Logic
//     // This attempts NATIVE (Driver) mode first automatically
//     link = bpf_program__attach_xdp(skel->progs.xdp_stats_prog, ifindex);
//
//     if (!link) {  
//         fprintf(stderr, "Native mode failed. Falling back to Generic (SKB)...\n");
//         
//         // Manual fallback to SKB mode using the low-level API
//         err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_stats_prog), 
//                              XDP_FLAGS_SKB_MODE, NULL);
//         if (err < 0) {
//             fprintf(stderr, "Error: Failed to attach XDP (even in generic mode): %d\n", err);
//             goto cleanup;
//         }
//         printf("Successfully attached to %s in GENERIC mode!\n", ifname);
//     } else {
//         printf("Successfully attached to %s in NATIVE mode!\n", ifname);
//     }
//
//     // 5. Stats Loop
//     int map_fd = bpf_map__fd(skel->maps.pkt_count);
//     signal(SIGINT, sig_handler);
//
//     printf("Monitoring PPS on %s... Press Ctrl+C to stop.\n", ifname);
//     while (keep_running) {
//         __u32 key = 0;
//         __u64 current_total = 0;
//
//         // Lookup values from ALL CPUs (Per-CPU Map)
//         err = bpf_map_lookup_elem(map_fd, &key, values);
//         if (err < 0) {
//             fprintf(stderr, "Error: Map lookup failed: %d\n", err);
//             break;
//         }
//
//         for (int i = 0; i < nr_cpus; i++) {
//             current_total += values[i];
//         }
//
//         printf("PPS: %llu\n", current_total - prev_total);
//         prev_total = current_total;
//         sleep(1);
//     }
//
// cleanup:
//     // With libbpf 1.5, bpf_link__destroy handles the XDP detach automatically
//     if (link) 
//         bpf_link__destroy(link);
//     else 
//         // If we attached via bpf_xdp_attach (Generic fallback), we detach manually
//         bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
//
//     pps_stats_bpf__destroy(skel);
//     printf("\nDetached and exited.\n");
//     return 0;
// }
