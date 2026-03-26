# PPS ( packet per second ):

PPS metric if used to check the NIC's ability for processing packets.

Bandwidth measurement ( Mbps/Gbps ) tells how much of data is moving, PPS tells you how many individual
decisions the system has to make every second. 


## PPS:

- PPS measures the throughput of a network device based on the number of individual packets it processes.

- This measurement varies with Maximum Transmission Unit (MTU) setting, for regular ethernet frames 
  (1518-1522 bytes depends on VLAN tagging), 1500 bytes for IP packets ( with 20 bytes for IP header, 20
  bytes for the TCP header and 1460 payload or Max segment size or MSS)

- Jumbo Frames when the MTU is larger than 1500 bytes which is common in high-performance data centers, throughput reduce processing overhead. 

- NIC driver handles every packet, which generally triggers an interrupt, memory allocation and routing. 

- Example:
    In a DDoS attack, small packets flood ( 64-bytes per packet) to maximize PPS, trying to overwhelm 
    the CPU's ability to "sort" before the actual bandwidth limit is even reached. 

The above point are key for writing a PPS measuring XDP is required (instead of eBPF) which runs the eBPF
code inside the network driver itself, before the kernel even creates a heavy `sk_buff` structure
allocation for the packet.

The XDP program must run in "Native" or "Offloaded" Mode. ( for driver that are generic XDP supported, pps
measurement will not give a correct reflection of performance of NIC as it relies on the kernel's stack )

XDP-Natvive/Offloaded mode driver allows has the ability to process packets before the kernel's expensive
allocation and interrupt handling, allowing decision making on the packet `XDP_DROP` or `XDP_PASS` within a
few CPU cycles. 

### PPS Measuring methods: 

Key points to keep in mind before writing XDP program.

- **`Per-cpu-map`**: Never use global HashMaps for counters, instead use `BPF_MAP_TYPE_PERCPU_ARRAY`, This
  avoids *cache line bouncing* and *CPU locking* which are performance killers for high PPS. 

- **LPM Trie for Rules**: If filtering by IP ranges (CIDRs), use `BPF_MAP_TYPE_LPM_TRIE`. It’s the most
  efficient way to look up prefix matches.

- **Code Optimization**: ( Micro efficiency layer )
    - **Bounded Loops**: eBPF verifier is strict. You must use `#pragma` unroll or ensure loops have a
      clear, constant upper bound.

    - **Direct Packet Access**: Access pkt data via `data` and `data_end` pointers. Always perform bounds
      checks before reading any byte, or the verifier will reject your code.

    - **Minimal Helper Calls**: Every call to a kernel helper (like `bpf_ktime_get_ns()`) adds overhead.
      Only use them if strictly necessary for your logic.

- User-Space Integration:
    - **Ring Buffers**: For logging "interesting" packets, use `BPF_MAP_TYPE_RINGBUF` instead of the older
      Perf Buffer. It is significantly faster and handles high-event rates better.

    - **Atomic Stats**: user-space "manager" should poll maps periodically to aggregate stats rather
      than having the eBPF program "push" data for every packet.


## Example 1: (using libbpf, CO-RE)

Project layout:
```bash 
─┬ pps
 ├── pps_stats.c
 ├── pps_stats.bpf.c
 └── Makefile
```
- eBPF program file `pps-stats.bpf.c`


```c 
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} pkt_count SEC(".maps");

SEC("xdp")
int xdp_stats_prog(struct xdp_md *ctx) {
    u32 key = 0;
    u64 *value;

    // Direct packet access bounds checking
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data + 14 > data_end) return XDP_PASS;

    value = bpf_map_lookup_elem(&pkt_count, &key);
    if (value) {
        *value += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

```
- user-space program to load and attach: `pps_stats.c`

```c 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "pps_stats.skel.h" 

static volatile bool keep_running = true;
void sig_handler(int sig) { keep_running = false; }

int main(int argc, char **argv) {
    struct pps_stats_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err, ifindex;
    const char *ifname;

    // 1. Handle Command Line Arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eth0\n", argv[0]);
        return 1;
    }
    ifname = argv[1];

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Invalid interface %s\n", ifname);
        return 1;
    }

    // 2. Prepare CPU-specific value storage
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 values[nr_cpus];
    __u64 prev_total = 0;

    // 3. Load and Verify BPF application
    skel = pps_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load/verify BPF skeleton\n");
        return 1;
    }

    // 4. Modern libbpf (1.0+) Attachment Logic
    // This attempts NATIVE (Driver) mode first automatically
    link = bpf_program__attach_xdp(skel->progs.xdp_stats_prog, ifindex);

    if (!link) {  
        fprintf(stderr, "Native mode failed. Falling back to Generic (SKB)...\n");
        
        // Manual fallback to SKB mode using the low-level API
        err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_stats_prog), 
                             XDP_FLAGS_SKB_MODE, NULL);
        if (err < 0) {
            fprintf(stderr, "Error: Failed to attach XDP (even in generic mode): %d\n", err);
            goto cleanup;
        }
        printf("Successfully attached to %s in GENERIC mode!\n", ifname);
    } else {
        printf("Successfully attached to %s in NATIVE mode!\n", ifname);
    }

    // 5. Stats Loop
    int map_fd = bpf_map__fd(skel->maps.pkt_count);
    signal(SIGINT, sig_handler);

    printf("Monitoring PPS on %s... Press Ctrl+C to stop.\n", ifname);
    while (keep_running) {
        __u32 key = 0;
        __u64 current_total = 0;

        // Lookup values from ALL CPUs (Per-CPU Map)
        err = bpf_map_lookup_elem(map_fd, &key, values);
        if (err < 0) {
            fprintf(stderr, "Error: Map lookup failed: %d\n", err);
            break;
        }

        for (int i = 0; i < nr_cpus; i++) {
            current_total += values[i];
        }

        printf("PPS: %llu\n", current_total - prev_total);
        prev_total = current_total;
        sleep(1);
    }

cleanup:
    // With libbpf 1.5, bpf_link__destroy handles the XDP detach automatically
    if (link) 
        bpf_link__destroy(link);
    else 
        // If we attached via bpf_xdp_attach (Generic fallback), we detach manually
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

    pps_stats_bpf__destroy(skel);
    printf("\nDetached and exited.\n");
    return 0;
}
```
- Makefile:

```make 
# Variables
TARGET := pps_stats
BPF_OBJ := $(TARGET).bpf.o
BPF_C := $(TARGET).bpf.c
USER_C := $(TARGET).c
SKEL := $(TARGET).skel.h

# Compilers
CLANG := clang
CC := gcc
BPFTOOL := bpftool

# Flags
# -g is essential for BTF (CO-RE) to work
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 
USER_CFLAGS := -g -O2 -Wall
LIBS := -lbpf -lelf -lz

.PHONY: all clean generate

all: $(TARGET)

# 1. Generate vmlinux.h (The kernel's type library)
vmlinux.h:
        $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF code to object file
$(BPF_OBJ): $(BPF_C) vmlinux.h
        $(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 3. Generate the Skeleton header from the BPF object
$(SKEL): $(BPF_OBJ)
        $(BPFTOOL) gen skeleton $< > $@

# 4. Build the final User-space binary
$(TARGET): $(USER_C) $(SKEL)
        $(CC) $(USER_CFLAGS) $< -o $@ $(LIBS)

clean:
        rm -f $(TARGET) $(BPF_OBJ) $(SKEL) vmlinux.h
```

- PPS Performance vs. Mode:
  What can be expected from each mode when handling 64-byte packets (the hardest test for PPS):

| Mode | Where it Runs | PPS Capacity (Estimated) | Host CPU Impact |
| :--- | :--- | :--- | :--- |
| **Generic** | Kernel Stack | ~1M - 4M PPS | Very High |
| **Native** | NIC Driver | ~10M - 30M+ PPS | Moderate |
| **Offloaded** | NIC Hardware | **Line Rate** (e.g., 148M PPS for 100G) | **Zero** |


- PPS Discrepancies:

If you run your new tool and see 10M PPS in **Native** but only 2M PPS in **Generic**, here is why:

1.  **Context Switching:** Generic XDP happens after the kernel allocates a `sk_buff` (a heavy metadata structure). This allocation is the "wall" that limits PPS.
2.  **Cache Locality:** Native XDP works with the raw DMA (Direct Memory Access) buffer. The data is "warm" in the CPU cache right as it comes off the wire.
3.  **Interrupt Storms:** In Generic mode, the CPU is bombarded with hardware interrupts. In Native mode (specifically with NAPI), the driver switches to "polling" mode, which is much more efficient for high PPS.


### Python Visualizer (visualize_pps.py):

A real-time visualize to spot "micro-bursts" or traffic patterns. This are generally invisible in a
scrolling text list.

```python 
import subprocess
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import collections

# Configuration
BINARY_PATH = "./pps_stats"  # Path to your compiled libbpf binary
WINDOW_SIZE = 60            # Seconds to show on the graph

# Data containers
times = collections.deque(maxlen=WINDOW_SIZE)
pps_values = collections.deque(maxlen=WINDOW_SIZE)

# Setup the Plot
plt.style.use('dark_background')
fig, ax = plt.subplots()
line, = ax.plot([], [], color='#00ff00', linewidth=2)
ax.set_title("Real-Time Network Throughput (PPS)")
ax.set_ylabel("Packets Per Second")
ax.set_xlabel(f"Last {WINDOW_SIZE} Seconds")
ax.grid(True, alpha=0.3)

# Start the eBPF binary as a subprocess
proc = subprocess.Popen([BINARY_PATH], stdout=subprocess.PIPE, text=True)

def init():
    ax.set_xlim(0, WINDOW_SIZE)
    ax.set_ylim(0, 1000) # Initial scale, will auto-adjust
    return line,

def update(frame):
    line_str = proc.stdout.readline()
    if "PPS:" in line_str:
        try:
            # Extract number from "PPS: 123456"
            val = int(line_str.split(":")[1].strip())
            pps_values.append(val)
            times.append(len(pps_values))
            
            # Update plot data
            line.set_data(range(len(pps_values)), list(pps_values))
            
            # Auto-scale Y axis for spikes
            if val > ax.get_ylim()[1]:
                ax.set_ylim(0, val * 1.2)
                
        except (ValueError, IndexError):
            pass
            
    return line,

# Use FuncAnimation for smooth updates
ani = FuncAnimation(fig, update, init_func=init, blit=True, interval=1000)

plt.show()
```

## Example 2: Upgrade PPS count to network analysis:

- Simple packet counter => Professional Network Analyzer, requires tracking both **Packets** and **Bytes**.

- calculating the ratio : $Average\ Packet\ Size = \frac{Total\ Bytes}{Total\ Packets}$
    
    Allows instantly to identify the *type* of traffic. 
    Example: 
    - A **64 bytes** result => usually indicates a TCP SYN flood (DDoS), 
    - And a **1500 bytes** indicates a heavy data transfer like an ISO download or backup.

- Upgrade the above logic: Kernel Code (`pps_stats.bpf.c`)

- Changing the map value from a single `u64` to a `struct` allows to keep the packet & byte counts
  synchronized.

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct stats_val {
    u64 packets;
    u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct stats_val);
} pkt_stats SEC(".maps");

SEC("xdp")
int xdp_stats_prog(struct xdp_md *ctx) {
    u32 key = 0;
    struct stats_val *val;

    // Direct access to packet pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Calculate packet length before passing/dropping
    u64 len = data_end - data;

    val = bpf_map_lookup_elem(&pkt_stats, &key);
    if (val) {
        val->packets += 1;
        val->bytes += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

- Updated User-Space Logic (`pps_stats.c` snippet)

In stats loop, logic aggregate both fields and perform the division.

```c
// Inside the while(keep_running) loop:
struct stats_val values[nr_cpus];
u64 total_pkts = 0, total_bytes = 0;

bpf_map_lookup_elem(map_fd, &key, values);
for (int i = 0; i < nr_cpus; i++) {
    total_pkts += values[i].packets;
    total_bytes += values[i].bytes;
}

u64 delta_pkts = total_pkts - prev_pkts;
u64 delta_bytes = total_bytes - prev_bytes;

// Professional Grade: Avoid division by zero
u64 avg_size = (delta_pkts > 0) ? (delta_bytes / delta_pkts) : 0;

printf("PPS: %llu | Bandwidth: %llu Mbps | Avg Pkt Size: %llu bytes\n", 
        delta_pkts, (delta_bytes * 8) / 1000000, avg_size);

prev_pkts = total_pkts;
prev_bytes = total_bytes;
```

- Interpretation:

| Avg Pkt Size | Likely Traffic Type | Action/Insight |
| :--- | :--- | :--- |
| **60 - 64 bytes** | Control Traffic (ACKs) or **DDoS Flood** | High PPS here is a major red flag for an attack. |
| **128 - 512 bytes** | DNS, VoIP, or API calls | Typical for interactive "chatty" applications. |
| **1000 - 1500 bytes** | Bulk Data (HTTP/FTP/Video) | Good throughput; indicates efficient network use. |
| **> 1500 bytes** | Jumbo Frames | Only seen in optimized Data Centers / Storage networks. |

## Example 3: Top Talkers

To track Top Talkers (the specific IP addresses generating the most PPS), we need to transition from a
simple ARRAY map to a HASH map. A Hash map allows us to use the Source IP as the key.

Note: 
Hash map with millions of IPs can be slow, to keep it "High PPS," use a LRU (Least Recently Used) Hash Map.
This ensures the kernel automatically evicts old/quiet IPs and keeps the "hottest" talkers in memory.

- Updated Kernel Code (pps_stats.bpf.c): requires parsing Ethernet header and IP header to extract src_addr:

```c 
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES 10240
#define ETH_P_IP 0x0800

struct stats_val {
    u64 packets;
    u64 bytes;
};

/* LRU Hash map: Automatically manages memory by evicting old IPs */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);   // Source IP
    __type(value, struct stats_val);
} top_talkers SEC(".maps");

SEC("xdp")
int xdp_stats_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    // Only process IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void*)(iph + 1) > data_end) return XDP_PASS;

    u32 src_ip = iph->saddr;
    u64 len = data_end - data;

    struct stats_val *val = bpf_map_lookup_elem(&top_talkers, &src_ip);
    if (val) {
        val->packets += 1;
        val->bytes += len;
    } else {
        struct stats_val new_val = {1, len};
        bpf_map_update_elem(&top_talkers, &src_ip, &new_val, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

- User-Space: Finding the "Kings" of PPS: Requires iteration through the hash map, sort the entries, and
  print the top 5.

```c 
void print_top_talkers(int map_fd) {
    u32 key = 0, next_key;
    struct stats_val value;
    
    printf("\n--- Top Talkers ---\n");
    // Note: In a real "Pro" tool, you'd pull all entries into an array and sort them.
    // Here is the basic iteration logic:
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd, &next_key, &value);
        
        unsigned char bytes[4];
        bytes[0] = next_key & 0xFF;
        bytes[1] = (next_key >> 8) & 0xFF;
        bytes[2] = (next_key >> 16) & 0xFF;
        bytes[3] = (next_key >> 24) & 0xFF;

        printf("IP: %d.%d.%d.%d | Packets: %llu\n", 
               bytes[0], bytes[1], bytes[2], bytes[3], value.packets);
        
        key = next_key;
    }
}

```
Performance Warnings:
- Map Locking: Unlike PERCPU_ARRAY, a standard LRU_HASH uses internal locking. If 20 CPU cores all try to
  update the stats for the same IP address simultaneously, you will see a massive drop in PPS capacity.

- The "Fix": For true 100M+ PPS performance, professionals use BPF_MAP_TYPE_PERCPU_HASH. This creates a
  separate hash map for every CPU core. Your user-space app then has to merge the maps from all cores to
  get the real total for each IP. It’s more complex to code but significantly faster.

---

# pps_stats with libbpf-rs : 

- check ../../libbpf-rs/ppsStats/ 

