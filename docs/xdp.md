# XDP (eXpress Data Path):


## Introduction:

`XDP` is high performance, programmable data path in the Linux Kernel. Allowing developers to attach `eBPF`
programs to the lowest possible level of the network stack. (NIC driver)

Traditional tools using `iptables`, `kprobes` operate after the kernel has already done significant work,
`XDP` intercepts packet before they are even processed by the Linux Kernel Networking sub-system.

### **Hook Point: XDP vs kprobe**

- `kprobes` (The Spectator): 
    Hooks into high-level kernel functions (e.g.,`ip_rcv`). 
    By the time a `kprobe` triggers, the kernel has already allocated an `sk_buff` (socket buffer), 
    parsed headers, and consumed significant CPU cycles. It is primarily used for observability.

- `XDP` (The Gatekeeper):
    Hooks directly into the **RX (Receive) ring buffer** of the 'NIC' driver. 
    It executes before the `sk_buff` is even allocated. It is primarily used for **packet processing**.

- Comparison:
| Feature | kprobe | XDP |
| --- | --- | --- |
| **Location** | Kernel Functions (IP Stack) | NIC Driver (RX Path) |
| **Memory Access** | Struct-based (Parsed) | Raw DMA Buffer (Unparsed) |
| **Payload** | `sk_buff` (Heavyweight) | `xdp_md` (Lightweight) |
| **Primary Use** | Debugging / Monitoring | Filtering / Load Balancing |

---

## How XDP Works: The "Raw" Advantage

When an XDP program is triggered, the kernel passes a `struct xdp_md` context. 
This structure provides two crucial pointers: `data` and `data_end`.

Because XDP has direct access to the **Raw Packet Memory**:

1. **Zero-Copy Efficiency:** 
    It can inspect and modify packets "in-place" within the driver's memory.

2. **Manual Parsing:** 
    The developer must manually cast pointers to parse headers (Ethernet → IP → TCP/UDP).

3. **Strict Verification:** 
    The eBPF Verifier ensures that every pointer access is bounds-checked against `data_end` to prevent
    kernel crashes.

---

## The 5 Verdicts (The Power of Decision)

After inspecting a packet, an XDP program returns a "verdict" that determines the packet's fate instantly:

* **`XDP_DROP`:** Discards the packet immediately. This is the fastest way to drop traffic (e.g., for DDoS protection).
* **`XDP_PASS`:** Passes the packet up to the normal Linux network stack for standard processing.
* **`XDP_TX`:** Forwards the packet back out of the *same* interface it arrived on (often after modifying headers).
* **`XDP_REDIRECT`:** Sends the packet to a different NIC or into a user-space application via `AF_XDP`.
* **`XDP_ABORTED`:** Indicates a program error; the packet is dropped and an error is logged.

---

##  Operational Modes

XDP can run in three modes depending on hardware and driver support:

1. **Offloaded:** 
    The eBPF program is loaded directly onto the NIC's NPU (Network Processing Unit).

2. **Native:** 
    The program runs inside the NIC driver's code path (High performance).

3. **Generic (SKB Mode):** 
    A software-based fallback that runs later in the stack. 
    Used for testing when the driver does not support native XDP.

---

## Summary: Why Use XDP?

XDP provides the **power to decide** the destiny of a packet at the earliest possible stage. 
By avoiding the overhead of the full Linux TCP/IP stack (specifically the `sk_buff` allocation), XDP can
achieve packet processing speeds that rival kernel-bypass solutions like DPDK, while still remaining 
within the security and management bounds of the Linux kernel.

AF_XDP to show how packets are moved from this hook into user-space applications;
----------------------

##  AF_XDP: The High-Speed Bridge to User-space

While standard XDP lives entirely inside the kernel, 
**AF_XDP** (Address Family XDP) is a specialized address family that creates a high-performance 
"express lane" between the XDP hook and a user-space application. 
It allows you to move raw packets into your app with zero-copy efficiency.

### How AF_XDP Functions

`AF_XDP` uses a shared memory area called a **UMEM**. 
This memory is mapped into both the kernel and the user-space application, eliminating the need to copy
data across the "kernel-user boundary" that slows down standard sockets.

The process works via four specialized ring buffers:

1. **Fill Ring:** 
    User-space tells the kernel which UMEM areas are ready to receive data.

2. **RX Ring:** 
    The kernel notifies user-space that a packet has arrived in a specific UMEM slot.

3. **TX Ring:** 
    User-space tells the kernel to send a packet located in a UMEM slot.

4. **Completion Ring:** 
    The kernel notifies user-space that the transmission is finished and the memory can be reused.

### The "Zero-Copy" Magic

In a standard `recv()` call, the kernel must copy data from its internal buffers into your application's buffer. With AF_XDP:

* The XDP program uses the **`XDP_REDIRECT`** verdict to point a packet at an AF_XDP socket (`XSK`).
* The hardware drops the packet directly into the **UMEM**.
* The application reads it directly from that same memory.

### AF_XDP vs. DPDK

Before AF_XDP, developers used **DPDK** (Data Plane Development Kit) for this level of speed. 
However, DPDK "steals" the network card from the kernel, meaning you lose standard tools like `tcpdump`,
`iproute2`, and the ability to use normal TCP/IP on that interface.

| Feature | Standard Sockets | DPDK | AF_XDP |
| --- | --- | --- | --- |
| **Performance** | Low (Copy heavy) | Ultra-High | Ultra-High |
| **Kernel Integration** | Full | None (Bypass) | Selective (Co-existence) |
| **Ease of Use** | Easy | Complex | Moderate |
| **Tools Support** | All tools work | No standard tools | Standard tools work |

### Summary: The Hybrid Approach

AF_XDP provides the best of both worlds. 
You can use an XDP program to filter out "trash" traffic (DDoS) at the driver level, pass "normal" 
traffic (SSH/HTTP) up to the kernel stack, and redirect "high-speed" data (Video streaming/Trading data) 
directly to your specialized user-space application.

---

## Sample C code snippet for an XDP program that redirects specific traffic to an AF_XDP socket?:
------------------------------------------------------------------------------------------------

A sample C snippet for the eBPF kernel-side program. 

This program acts as a "traffic sorter": it inspects incoming packets and redirects only **UDP** 
traffic to a specific AF_XDP socket, while letting everything else pass through to the normal Linux
networking stack.

### The Kernel-Side XDP Program (`xdp_prog.c`)

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// A map to store our AF_XDP sockets (XSKs)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64); // Matches number of hardware queues
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Check if it's an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. Parse IP Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    // 4. Power of Decision: If UDP, redirect to AF_XDP socket
    if (iph->protocol == IPPROTO_UDP) {
        __u32 key = ctx->rx_queue_index;
        // XDP_REDIRECT tells the kernel to move the packet to the XSK in the map
        return bpf_redirect_map(&xsks_map, key, 0);
    }

    // 5. Otherwise, let the kernel handle it normally
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

```

---

### How this code functions in the stack

1. **Verification:** When you load this, the eBPF verifier ensures your `data_end` checks are perfect. Notice that for every header we read, we first check if the memory actually exists.
2. **The Map Lookup:** The `xsks_map` is the bridge. In user-space, your application creates an AF_XDP socket and "registers" its file descriptor into this map at the index corresponding to the CPU/Queue ID.
3. **The Redirection:** When `bpf_redirect_map` is called, the packet "jumps" from the driver's RX ring directly into the **UMEM** shared with your user-space application.

### User-Space Counterpart (Conceptual)

In your user-space C/C++ application, you would use `libbpf` or `liburing` to:

* Allocate a large chunk of memory (the **UMEM**).
* Create an `AF_XDP` socket.
* Update the `xsks_map` so the kernel knows where to send the redirected packets.
* Poll the **RX Ring** to process packets as they arrive.

### Summary of the Flow

1. **Packet Arrives** at the NIC.
2. **XDP Program Executes** in the driver.
3. **Program Identifies UDP** and returns `XDP_REDIRECT`.
4. **Packet Lands in UMEM** (Zero-copy).
5. **User-space App** sees the update in the RX Ring and processes the data immediately.


## How to compile this using `clang` and `llvm`
-----------------------------------------------------------------------------------------------------

To compile eBPF code for XDP, you cannot use a standard GCC compiler. 
You must use **Clang** and **LLVM** because they contain the specific backend required to generate 
BPF bytecode.

### 1. The Compilation Steps

The process transforms your C code into an ELF (Executable and Linkable Format) file that contains the 
BPF instructions.

#### Step A: Generate the BPF Bytecode

```bash
clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o

```
* **`-O2`**: Optimization is **mandatory**. 
  The eBPF verifier often fails to validate unoptimized code because it generates too many jumps.

* **`-g`**: 
    Generates debug information (BTF). 
    This allows the kernel to give you better error messages if the verifier rejects your code.

* **`-target bpf`**: 
    Tells Clang not to build for x86 or ARM, but for the BPF virtual machine.

* **`-c`**: 
    Compile only (don't try to link it into a standard executable).

#### Step B: Inspect the Bytecode (Optional but recommended)

If you want to see the assembly instructions that the kernel will actually execute, you can use 
`llvm-objdump`:

```bash
llvm-objdump -d xdp_prog.o

```

---

### 2. Loading the Program

Once you have `xdp_prog.o`, you need to "attach" it to a network interface (e.g., `eth0`). 
You can do this using the `iproute2` toolset:

```bash
# Attach to eth0 in native mode
ip link set dev eth0 xdp obj xdp_prog.o sec xdp

# To remove it later
ip link set dev eth0 xdp off

```

> **Note:** 
> The `sec xdp` refers to the `SEC("xdp")` macro used in the C code, telling the loader which function in
> the file is the entry point.

---

### 3. Debugging the Verifier

If your code has a logical error (like a missing bounds check), the kernel will reject it when you try to
load it. You can see the detailed verifier log using `bpftool`:

```bash
# View kernel logs for BPF errors
journalctl -k | grep bpf

```

## Next: How AF_XDP handles the **Fill** and **Completion** rings in detail.
-------------------------------------------------------------------------------------------------------

In a standard socket, the kernel manages memory. 

In **AF_XDP**, the application provides the memory, and the "Rings" are the management system that
coordinates who owns which chunk of memory at any given time.

To make AF_XDP work, you have **four rings** (circular buffers) acting as a synchronization layer between 
your User-space app and the Kernel.

---

### 1. The Memory Foundation: UMEM

Before looking at the rings, you must understand the **UMEM**. It is a contiguous block of virtual memory divided into equal-sized **chunks** (usually 4KB).

* Think of the UMEM as a "parking lot."
* Each chunk has an "address" (its offset from the start).
* The Rings don't pass actual packet data; they pass these **addresses**.

---

### 2. The RX Path: Fill and RX Rings

This is how a packet gets from the wire into your application.

#### The Fill Ring (User → Kernel)

The application uses this ring to "hand over" empty buffers to the kernel.

* **Step:** You write the addresses of empty UMEM chunks into the Fill Ring.
* **Logic:** You are essentially saying, *"Hey Kernel, here are 16 empty parking spots you can use when a packet arrives."*
* **Crucial Point:** If the Fill Ring is empty, the kernel has nowhere to put incoming packets, and they will be dropped at the NIC.

#### The RX Ring (Kernel → User)

The kernel uses this ring to "return" filled buffers to you.

* **Step:** When a packet is redirected by your XDP program, the kernel picks an address from the Fill Ring, writes the packet data there, and then places that address into the RX Ring.
* **Logic:** The kernel is saying, *"Parking spot #4 now has a UDP packet in it. Go ahead and read it."*

---

### 3. The TX Path: TX and Completion Rings

This is how you send data out to the world.

#### The TX Ring (User → Kernel)

When you want to send a packet, you write the data into a UMEM chunk.

* **Step:** You put that chunk's address into the TX Ring.
* **Logic:** You tell the kernel, *"Please send the data sitting in parking spot #10 out to the internet."*

#### The Completion Ring (Kernel → User)

Sending data via a NIC is asynchronous. You can't reuse that memory chunk until the hardware has physically finished sending the bits.

* **Step:** Once the packet is sent, the kernel puts the address back into the Completion Ring.
* **Logic:** The kernel says, *"I'm done with spot #10. You can now overwrite it with new data or use it for the Fill Ring again."*

---

### 4. Summary Table of Ring Roles

| Ring | Direction | Purpose |
| --- | --- | --- |
| **Fill** | User → Kernel | App gives "empty" buffers to the Kernel for incoming traffic. |
| **RX** | Kernel → User | Kernel gives "full" buffers to the App to be processed. |
| **TX** | User → Kernel | App gives "full" buffers to the Kernel to be transmitted. |
| **Completion** | Kernel → User | Kernel gives "empty" buffers back to the App after transmission. |

### 5. Why this is so fast

1. **Shared Memory:** No `copy_to_user()` or `copy_from_user()`. The data stays in the same physical RAM; only the *ownership* of the address changes.
2. **Batching:** You can add 16 addresses to the Fill Ring in one go and notify the kernel with a single system call (`sendto()` or `poll()`), or zero syscalls if using "busy polling" mode.
3. **Lockless:** These rings are designed as single-producer/single-consumer (SPSC) queues, meaning they require very little CPU synchronization overhead.

---

## Performance Checklist ( optimizing this setup (like CPU pinning and Zero-copy mode requirements)):
----------------------------------------------------------------------------------------------------------

**Performance Checklist**.

If you implement the rings correctly but ignore these system-level settings, 
you will likely only get 10–20% of the potential performance.

---

### 1. Hardware & Driver "Zero-Copy" Support

Not all NIC drivers are created equal. 
To get the "True Zero-Copy" path (where the hardware DMA writes directly into your UMEM), you must
check for:

* **Native Driver Support:** 
    Ensure your driver (e.g., `i40e`, `ixgbe`, `mlx5_core`) supports the `XDP_REDIRECT` action.

* **Bind Flags:** 
  When you bind the AF_XDP socket in user-space, use the `XDP_ZEROCOPY` flag. 
  If the driver doesn't support it, the bind will fail, alerting you that you're falling back to 
  "copy mode."

### 2. CPU Pinning & SoftIRQ Alignment

Networking in Linux is heavily tied to CPU cores via **Interrupt Requests (IRQs)**.

* **Pin the App:** 
    Bind your user-space thread to a specific CPU core (e.g., Core 2) using `pthread_setaffinity_np`.

* **Align the IRQ:** 
    Ensure the NIC hardware queue's interrupt is hitting the **same core** as your application. 
    If the Kernel processes the packet on Core 1 but your app is on Core 2, the "cache miss" penalty will 
    destroy your throughput.

* **Isolate Cores:** 
    Use the `isolcpus` kernel parameter to prevent the Linux scheduler from putting other random tasks 
    on your high-speed processing cores.

### 3. Hugepages for UMEM

Standard memory pages are **4KB**. 
For a 1GB UMEM, the CPU has to manage 262,144 page table entries. 
This causes "TLB misses" (cache misses for memory addresses).

* **Optimization:** 
    Use **Hugepages** (2MB or 1GB) for your UMEM allocation. 
    This reduces the number of entries the CPU needs to track, significantly speeding up memory access.

### 4. Busy Polling

By default, the kernel "naps" and waits for an interrupt when a packet arrives. 

This adds latency.

* **Setting:** 
    Enable `SO_BUSY_POLL` on your AF_XDP socket.

* **Result:** 
    Your application will "spin" on the RX ring, checking for data constantly. 
    This consumes 100% of the CPU core but reduces latency to the absolute hardware minimum 
    (low microseconds).

### 5. Batching

Never process one packet at a time.

* **Strategy:** Always try to pull the maximum number of descriptors available from the 
  **RX Ring** (e.g., 16, 32, or 64) in a single loop iteration. 

  This spreads the "administrative cost" of updating the ring head/tail across many packets.

---

### Summary Checklist Table

| Optimization | Benefit | Difficulty |
| --- | --- | --- |
| **XDP_ZEROCOPY** | Removes CPU memory copies | High (Hardware dependent) |
| **Hugepages** | Reduces TLB misses / Memory overhead | Medium |
| **CPU Affinity** | Prevents cache thrashing | Easy |
| **Busy Polling** | Lowest possible latency | Easy |
| **Generic Mode** | **AVOID** (Use only for testing) | - |

---

## IP Command:

- `ip` command of the `iproute2` package is used to pin a program to an interface.
- In real world applications since it requires communication with the user space via **Maps** we use loader
  library like **Aya** or **libbpf**.

Above UDP-redirector into **Rust** using the **Aya** framework.

---

### 1. The Kernel-Space Program (`src/main.rs` in the eBPF crate)

In Aya, we use the `network_types` crate to handle the manual parsing we discussed.
```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, // Now explicitly imported
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

// 1. Map definition update: static mut is generally replaced by just static
// in newer Aya macros, and we use the macro to handle initialization.
#[map]
static XSK_MAP: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn xdp_sock_prog(ctx: XdpContext) -> u32 {
    match try_xdp_sock_prog(ctx) {
        Ok(ret) => ret,
        // 2. xdp_action is now accessed via the binding enum
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_sock_prog(ctx: XdpContext) -> Result<u32, ()> {
    // 3. Ethernet Header Parsing
    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };

    // Use be_to_cpu or specific EtherType constants if needed,
    // but matching the original logic:
    if unsafe { (*eth).ether_type } != u16::from(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. IP Header Parsing
    let iph = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };

    if unsafe { (*iph).proto } == IpProto::Udp {
        let index = ctx.rx_queue_index();

        // 5. XskMap redirection
        // XskMap::redirect returns a u32 representing XDP_REDIRECT or the action
        return Ok(XSK_MAP.redirect(index, 0).unwrap_or(xdp_action::XDP_PASS));
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
```
---

### 2. The User-Space Loader (`src/main.rs` in the User crate)

Aya makes loading and managing the map very "Rusty" and type-safe.

```rust
use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};

fn main() -> Result<(), anyhow::Error> {
    // 1. Load the compiled BPF bytecode
    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/xdp-example"))?;
    
    // 2. Access the XDP program and load it into the kernel
    let program: &mut Xdp = bpf.program_mut("xdp_sock_prog").unwrap().try_into()?;
    program.load()?;
    
    // 3. Attach to an interface (e.g., eth0)
    program.attach("eth0", XdpFlags::default())?;

    // 4. Access the Map to insert our AF_XDP socket FD
    let mut xsk_map = XskMap::try_from(bpf.map_mut("XSK_MAP").unwrap())?;
    
    // Example: Put a socket file descriptor into the map for queue 0
    // xsk_map.set(0, sock_fd, 0)?;

    println!("Waiting for UDP packets on eth0...");
    // Keep the program running
    loop { std::thread::park(); }
}

```

---

### 3. Key Differences in the Rust Transition

* **Safety:** 
    Rust’s `ptr_at` helper (common in Aya) makes the **Verifier's** life easier and your code cleaner 
    by centralizing the `data_end` boundary checks.

* **Aya-log:** 
    Notice the `aya_log_ebpf` usage. 
    This allows you to use `info!(ctx, "packet received")` in your kernel code and see the logs in your
    user-space terminal—a massive improvement over C's `bpf_trace_printk`.

* **Compilation:** 
    Instead of raw `clang`, you use `cargo xtask build`, which handles the LLVM backend for you
    automatically.

### Summary: Why Rust/Aya?

While `ip link` is great for simple "drop" or "pass" scripts, using **Aya** allows you to build a complex, 
production-ready system where your user-space management logic and your kernel-space packet logic stay in 
sync within a single language ecosystem.

## How the `ptr_at` helper specifically satisfies the BPF Verifier's requirement for bounds checking:
-----------------------------------------------------------------------------------------------------

In the eBPF world, the **Verifier** is a "static analyzer" that checks every possible branch of your 
code before allowing it to run. It is famously paranoid about **pointers**.

If you try to read 4 bytes from a pointer without first proving that those 4 bytes are within the 
packet's boundaries, the Verifier will kill the program with a `buffer out of bounds` error.

### 1. The Anatomy of `ptr_at`

The `ptr_at` helper is the "security guard" that convinces the Verifier your code is safe. 
Let’s look at why it works:

```rust
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();          // Start of packet
    let end = ctx.data_end();        // End of packet
    let len = mem::size_of::<T>();   // Size of the header we want to read

    // This specific comparison is what the Verifier looks for:
    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

```

### 2. How the Verifier "Sees" It

The Verifier maintains a state for every register.

1. **Initially:** 
    It knows `data` and `data_end` are valid pointers, but it doesn't know the distance between them 
    (the packet length).

2. **The Check:** 
    When the Verifier sees the `if (start + offset + len > end)` check, it updates its internal 
    "knowledge base."

3. **The Result:** 
    Inside the `Ok` branch, the Verifier now knows for a fact that the memory range 
    `[start + offset, start + offset + len]` is **strictly less than or equal to** `end`.

4. **Permission Granted:** 
    It marks that specific memory range as "safe to read."
    If you try to read `len + 1` bytes, it will stop you.

### 3. The "C" vs. "Rust" Verifier Experience

In C, you often see developers doing these checks manually at every step, which is prone to 
"off-by-one" errors that are hard to debug.

```c
/* C Style */
struct ethhdr *eth = data;
if (data + sizeof(*eth) > data_end) // Manual check
    return XDP_DROP;

```

In Rust with Aya, `ptr_at` abstracts this. 
Because it's an **inline** function (`#[inline(always)]`), the compiler merges it directly into your
logic. 
The Verifier doesn't see a function call; it sees a clean, logical boundary check followed by a pointer
access.

### 4. Common Verifier "Gotchas" in Rust

* **Variable Offsets:** 
    The Verifier hates offsets that aren't known at compile-time. 
    If your `offset` comes from a calculation (like a variable-length IP options field), you must
    perform **another** check against `data_end` after calculating that new offset.

* **Stack Limits:** 
    eBPF has a tiny stack (512 bytes). 
    If you try to copy a large packet header *onto* the stack rather than reading it via a pointer, 
    the Verifier will reject the program.

---
## Small project that counts packets per IP 

Example project to count pkts per IP and stores them in a BPF Map.

Using **Aya 0.13.x**, as the framework moved toward a much cleaner integration with standard Cargo. 
**`aya-template`** setup allows you to build using the **bpf-linker** directly via cargo profiles.

### 1. The Kernel Program (`my-project-ebpf/src/main.rs`)

In 0.13.x, the `XdpContext` and map definitions remain similar, but we ensure the use of the correct `network_types` for safety.

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static mut PKT_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn count_packets(ctx: XdpContext) -> u32 {
    match try_count_packets(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_count_packets(ctx: XdpContext) -> Result<u32, ()> {
    let eth = unsafe { ptr_at::<EthHdr>(&ctx, 0)? };
    
    if unsafe { (*eth).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let iph = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)? };
    let src_addr = unsafe { (*iph).src_addr };

    unsafe {
        // Look up or insert initial value
        if let Some(count) = PKT_COUNT.get_ptr_mut(&src_addr) {
            *count += 1;
        } else {
            let _ = PKT_COUNT.insert(&src_addr, &1, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// Global enum for XDP actions required by 0.13.x
mod xdp_action {
    pub const XDP_ABORTED: u32 = 0;
    pub const XDP_PASS: u32 = 2;
}

```

---

### 2. The User-Space Monitor (`my-project/src/main.rs`)

Aya 0.13.x emphasizes better error handling and clearer map iteration.

```rust
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use std::net::Ipv4Addr;
use std::{thread, time::Duration};
use anyhow::Context;

fn main() -> Result<(), anyhow::Error> {
    // In aya-template, the eBPF bytes are bundled differently
    // Usually, you load the file from the target directory
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/debug/my-project")?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/release/my-project")?;

    let program: &mut Xdp = bpf.program_mut("count_packets")
        .context("Failed to find program")?
        .try_into()?;
    
    program.load()?;
    // Using default flags for Native/Driver mode
    program.attach("eth0", XdpFlags::default())
        .context("Failed to attach XDP program to eth0")?;

    let mut pkt_count: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("PKT_COUNT").unwrap())?;

    println!("Monitoring IP traffic... (Ctrl+C to exit)");

    loop {
        for result in pkt_count.iter() {
            let (ip_u32, count) = result?;
            // Convert from Network Endian to Host Endian for printing
            let ip_addr = Ipv4Addr::from(u32::from_be(ip_u32));
            println!("Source IP: {:<15} | Packet Count: {}", ip_addr, count);
        }
        
        thread::sleep(Duration::from_secs(1));
        print!("{}[2J", 27 as char); 
    }
}

```

---
**Run the User-space side (requires root for XDP):**

```bash
sudo cargo run --package my-project

```

### Why this is safer in 0.13.x:

* **BTF Support:** 
    Aya 0.13.x has improved support for BPF Type Format (BTF), meaning the kernel can better verify 
    your maps and structs.

* **Direct Cargo Build:** 
    By removing `xtask`, you are using standard Rust tooling, which makes CI/CD and dependency management
    (like `network-types`) much more reliable.


## example using `PerCpuHashMap` now 

It's a small change in the code but a big change in how you read the data in user-space, 
as it returns an array of values (one for each CPU core).

Upgrading to a **`PerCpuHashMap`** is the standard way to handle high-performance traffic in eBPF.

### Why Per-CPU?

In our previous example, multiple CPU cores were trying to update the same memory location 
(`*count += 1`). 

This causes "cache line bouncing" and atomic contention, which slows down your processing.

* A **`PerCpuHashMap`** creates a separate instance of the map for every CPU core.

* Core 0 only writes to Map 0, and Core 1 only writes to Map 1.

* There is **zero contention**, making it incredibly fast.

---

### 1. The Kernel Program (`my-project-ebpf/src/main.rs`)

The code looks almost identical, but we change the type to `PerCpuHashMap`.

```rust
use aya_ebpf::maps::PerCpuHashMap;

#[map]
static mut PKT_COUNT: PerCpuHashMap<u32, u32> = PerCpuHashMap::with_max_entries(1024, 0);

#[xdp]
pub fn count_packets(ctx: XdpContext) -> u32 {
    let src_addr = /* ... same parsing logic as before ... */;

    unsafe {
        // Look up the counter for THIS specific CPU core
        if let Some(count) = PKT_COUNT.get_ptr_mut(&src_addr) {
            *count += 1;
        } else {
            // If it doesn't exist, initialize this core's slot to 1
            let _ = PKT_COUNT.insert(&src_addr, &1, 0);
        }
    }
    xdp_action::XDP_PASS
}

```

---

### 2. The User-Space Monitor (`my-project/src/main.rs`)

This is where the big change happens. 
When you query a `PerCpuHashMap` from user-space, it doesn't return a single `u32`. 
It returns a **`PerCpuValues<u32>`**, which is essentially a list of values (one per core). 
You must sum them up to get the total count.

```rust
use aya::maps::PerCpuHashMap;

// ... inside main loop ...
let mut pkt_count: PerCpuHashMap<_, u32, u32> = PerCpuHashMap::try_from(bpf.map_mut("PKT_COUNT").unwrap())?;

for result in pkt_count.iter() {
    let (ip_u32, cpu_values) = result?; // cpu_values is a PerCpuValues<u32>
    
    // Sum the values from all CPU cores
    let total_count: u32 = cpu_values.iter().sum();
    
    let ip_addr = std::net::Ipv4Addr::from(u32::from_be(ip_u32));
    println!("IP: {:<15} | Total Packets: {}", ip_addr, total_count);
}

```

---

### 3. Key Differences in Performance

| Feature | `HashMap` | `PerCpuHashMap` |
| --- | --- | --- |
| **Speed** | Fast (but scales poorly with cores) | **Ultra-Fast** (scales linearly) |
| **Memory** | Low (Single value per key) | Higher (N-cores values per key) |
| **User-space** | Simple read | Must aggregate/sum values |
| **Concurrency** | Potential race conditions | **Lock-free / Race-free** |

---

### Summary Checklist for your Aya Project

1. **Cargo.toml:** 
    Ensure `aya` and `aya-ebpf` are both at `0.13.x`.

2. **Memory:** I
    f you have a 128-core server, remember that a `PerCpuHashMap` with 1024 entries will allocate 
    `128 * 1024 * sizeof(u32)` bytes.

3. **BTF:** 
    Keep your `structs` simple to ensure the BPF Type Format allows the user-space to "see" the map 
    layout correctly.


---------

## compare xdp with dpdk:

That is a perfect real-world experiment. If you have two systems with the same Realtek (RTK) NIC, you are essentially comparing two different philosophies of "Fast Path" networking.

Here is how that battle looks under the hood:

### 1. The Architecture of the Fight

* **DPDK (The Bypass):** DPDK "unbinds" the NIC from the Linux kernel. The kernel no longer even knows the card exists. Your DPDK application owns the hardware and must provide its own drivers, memory management, and logic.
* **XDP (The Native):** The NIC stays bound to the Linux kernel. The `rtase` or `r8169` driver (common for Realtek) executes your BPF code before the packet is "wrapped" for the kernel.

### 2. Performance Comparison Table

| Metric | DPDK | XDP (Native) |
| --- | --- | --- |
| **Interrupts** | **None.** Uses 100% CPU polling (Busy Wait). | **Mixed.** Uses interrupts by default (can be tuned to Busy Poll). |
| **Memory** | **Hugepages.** Requires manual memory management. | **Kernel Pages.** Easier, but can be upgraded to Hugepages via AF_XDP. |
| **Packet Latency** | **Lowest.** Zero kernel overhead. | **Near-Low.** Tiny overhead for the driver hook. |
| **Safety** | **Low.** A crash in DPDK can crash the whole process/hardware state. | **High.** The BPF Verifier ensures the kernel stays safe. |
| **Tooling** | No `tcpdump`, no `iptables`, no `ip route`. | `tcpdump` and standard Linux networking still work. |

### 3. The "Realtek" Reality Check

Since you mentioned **Realtek (rtk)** specifically, there is a catch you need to be aware of:

* **Driver Support:** Realtek drivers in the Linux kernel are notorious for being "Generic."
* **XDP Native Mode:** Some older Realtek chips do not support "Native XDP." In that case, Aya will fall back to **Generic XDP**, which is much slower because it runs *after* the kernel allocates the packet structure.
* **DPDK Support:** DPDK relies on PMDs (Poll Mode Drivers). You must check if your specific RTK model has a PMD (like `librte_pmd_r8169`). If it doesn't, you'll have to use `libpcap` mode, which defeats the purpose of DPDK.

### 4. How to conduct your Theory Test

To make the comparison fair, you should measure **Throughput (Mpps - Million Packets Per Second)** and **CPU Cycles per Packet**.

1. **Baseline:** Measure standard Linux kernel performance (Standard Sockets).
2. **XDP Test:** Load your Aya counter program. Measure how many packets you can drop (`XDP_DROP`) vs. pass.
3. **DPDK Test:** Run a simple `testpmd` application.
4. **The AF_XDP Wildcard:** For a true 1:1 match, compare DPDK against **AF_XDP**. AF_XDP is the only XDP mode that matches DPDK's ability to move data into user-space for complex processing.

### 5. The Winner?

* **Use DPDK if:** You are building a specialized appliance (like a high-end router or firewall) and you want to squeeze out every single nanosecond of performance, and you don't care about standard Linux networking.
* **Use XDP/Aya if:** You want 90-95% of DPDK performance but still want to be able to SSH into the box, use `ip route`, and have the safety of the BPF Verifier.

---

### Final Thought: Global Variables in Aya 0.13.x

Since you are testing, you can use **BPF Global Variables** to toggle your test logic without reloading the program. You could have a `static mut MODE: u32 = 0;` in your eBPF code. User-space can then flip that bit to switch from `XDP_PASS` to `XDP_DROP` mid-test to see the immediate impact on CPU usage.

**Would you like to see how to define and use one of those Global Variables in your Aya project?**

--------------------------------------------------------------------------------------------------------
In **Aya 0.13.x**, Global Variables are a game-changer for your Realtek performance testing. Traditionally, if you wanted to change a setting (like switching from "Count Mode" to "Drop Mode"), you had to use a **Map**, which requires a system call and a lookup.

**Global Variables** allow your user-space Rust app to reach directly into the eBPF memory and flip a bit. It’s faster, cleaner, and uses standard Rust `static` syntax.

---

### 1. The Kernel Side (`my-project-ebpf/src/main.rs`)

You define the variable as a `#[no_mangle] static`. In eBPF, this becomes a memory-mapped value that lives in a special data section.

```rust
// This variable can be changed by your Rust app at runtime
#[no_mangle]
static mut CONF_DROP_MODE: bool = false;

#[xdp]
pub fn count_packets(ctx: XdpContext) -> u32 {
    // Access the global variable
    // Note: Since it's a global static, we access it via unsafe
    if unsafe { core::ptr::read_volatile(&CONF_DROP_MODE) } {
        return xdp_action::XDP_DROP;
    }

    // ... rest of your IP counting logic ...
    xdp_action::XDP_PASS
}

```

---

### 2. The User-Space Side (`my-project/src/main.rs`)

Aya 0.13.x provides a very intuitive way to modify these variables using the `Bpf` object.

```rust
fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/debug/my-project")?;
    
    // ... load and attach as before ...

    // To change the value while the program is running:
    let mut drop_mode = bpf.global_vars_mut().get_mut("CONF_DROP_MODE").unwrap();
    
    // Switch to DROP mode
    let val: bool = true;
    drop_mode.write_all(bytemuck::bytes_of(&val))?;
    
    println!("DDoS Protection (DROP mode) activated via Global Variable!");
    
    Ok(())
}

```

---

### 3. Why this is perfect for your RTK Benchmark

When comparing against **DPDK**, you often need to measure the "Drop Throughput" (how many packets can the card discard before the CPU saturates).

1. **Start your test:** Run the program with `CONF_DROP_MODE = false`. Measure your baseline packet count and CPU usage.
2. **Flip the switch:** Use the user-space app to set `CONF_DROP_MODE = true`.
3. **Observe:** Watch your CPU usage drop instantly as the packets are discarded at the driver level before hitting the IP stack.

---

### 4. Comparison: Global Variables vs. Maps

| Feature | BPF Map (HashMap) | BPF Global Variable |
| --- | --- | --- |
| **Lookup Cost** | High (Hash & find) | **Zero** (Direct memory access) |
| **Complexity** | High (Key/Value logic) | **Low** (Simple C-style static) |
| **Updates** | Slow (System call) | **Fast** (Memory write) |
| **Use Case** | Storing many keys (IPs) | **Configuration / Toggles** |

### Final Pro-Tip for your Realtek Test:

If your RTK card supports **Multiple Queues**, make sure you are running your Aya program on all of them. Use `bpftool net list` to verify where your XDP program is attached. If you only attach to Queue 0 but the NIC is spreading traffic to Queue 1, you will see "missing" packets in your counter!

**Would you like me to help you write a small shell script or a "Benchmark runner" in Rust that toggles these modes and logs the performance delta?**
-------------------------------------------------------------------------------------------------------
This is the "Lab Scientist" approach. Instead of manually running different commands, we can write a **Benchmark Controller** in Rust that cycles through different modes (Pass, Count, and Drop) and reports the "Performance Cost" for your Realtek card in real-time.

### 1. The Benchmark Controller (`my-project/src/main.rs`)

We will use the Global Variable we just created to orchestrate the test phases.

```rust
use aya::maps::HashMap;
use aya::Bpf;
use std::{thread, time::{Duration, Instant}};
use bytemuck;

fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/release/my-project")?;
    // ... Load and Attach logic ...

    let mut pkt_count: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("PKT_COUNT").unwrap())?;

    let modes = [
        ("BASELINE (PASS)", false), 
        ("STRESS TEST (DROP)", true)
    ];

    for (name, drop_val) in modes {
        println!("\n>>> STARTING PHASE: {}", name);
        
        // 1. Set the Global Variable mode
        {
            let mut mode_var = bpf.global_vars_mut().get_mut("CONF_DROP_MODE").unwrap();
            mode_var.write_all(bytemuck::bytes_of(&drop_val))?;
        }

        // 2. Measure for 10 seconds
        let start_time = Instant::now();
        let mut last_count = 0;

        for _ in 0..10 {
            thread::sleep(Duration::from_secs(1));
            
            // Sum all packets in the map (if using PerCpu, use .sum() logic)
            let current_total: u32 = pkt_count.iter().filter_map(|r| r.ok()).map(|(_, v)| v).sum();
            let delta = current_total - last_count;
            last_count = current_total;

            println!("   [{:?}] Packets/sec: {}", start_time.elapsed(), delta);
        }
    }

    Ok(())
}

```

---

### 2. How to Read the Results against DPDK

When you run this on your Realtek card, compare the **Packets/sec** and **CPU %** (from `top`) against the DPDK results:

* **The "Drop" Phase:** This is your **Maximum PPS (Packets Per Second)**. Since the kernel isn't doing any work, this shows the raw speed of your RTK driver + XDP. If this is much lower than DPDK, the bottleneck is the Realtek driver's XDP implementation.
* **The "Pass" Phase:** This shows the **Kernel Tax**. You will see the PPS drop because the CPU is now busy allocating `sk_buff` and running the IP stack.

---

### 3. Final Pro-Tips for Realtek (RTK) Hardware

Realtek cards (especially the 1GbE/2.5GbE consumer models) often have limited descriptor ring sizes compared to Enterprise Intel or Mellanox cards. To make the benchmark fair:

1. **Increase Ring Size:** Before running the test, try to max out the RX rings:
```bash
# Check current limits
ethtool -g eth0
# Set to max (e.g., 4096)
sudo ethtool -G eth0 rx 4096

```


2. **Disable "Generic" Fallback:** If you want to ensure you are testing the **driver's** speed and not the kernel's helper, force Native mode in your Rust code:
```rust
// This will error out if the RTK driver doesn't support Native XDP
program.attach("eth0", XdpFlags::SKB_MODE ^ XdpFlags::default())?; 

```


(Note: `XdpFlags::DRV_MODE` is the explicit flag for Native).
3. **Check for "OOM" Drops:** If your RTK card is struggling, check `ethtool -S eth0`. Look for `rx_no_buffer_count` or similar errors. This tells you the hardware is dropping packets before XDP even gets them.

---

### What's next for your project?

You now have a full-stack eBPF application: **Kernel code** with manual header parsing, **Maps** for state, **Global Variables** for control, and a **User-space Controller** for benchmarking.

**Would you like me to explain how to export these metrics to Prometheus/Grafana so you can see the performance curves visually?**
--------------------------------------------------------------------------------------------------------

To take your Realtek vs. DPDK benchmark to a professional level, you need to move beyond `println!` and into **Time-Series Visualization**. Using **Prometheus** for data collection and **Grafana** for the dashboard allows you to see exactly when the "cliff" happens as packet rates increase.

### 1. The Metrics Architecture

We will use the **`prometheus`** and **`warp`** (or `axum`) crates in your Rust user-space app to create an HTTP endpoint (usually at `:9100/metrics`).

* **Kernel:** Counts packets in the `PerCpuHashMap`.
* **User-space:** Periodically reads the map, sums the values, and updates a Prometheus `Counter`.
* **Prometheus:** Scrapes your app every few seconds.
* **Grafana:** Queries Prometheus to draw the PPS (Packets Per Second) graph.

---

### 2. Updating the User-Space App (`my-project/src/main.rs`)

Add these dependencies to your `Cargo.toml`:

```toml
prometheus = "0.13"
lazy_static = "1.4"
warp = "0.3"

```

Then, integrate the exporter into your monitor:

```rust
use prometheus::{opts, register_counter_vec, CounterVec, Encoder, TextEncoder};
use lazy_static::lazy_static;

lazy_static! {
    // We create a counter that labels packets by "mode" (Drop vs Pass)
    static ref XDP_PACKETS: CounterVec = register_counter_vec!(
        opts!("xdp_packet_count", "Total packets processed by XDP"),
        &["mode", "ip_addr"]
    ).unwrap();
}

// Function to start the metrics server
async fn start_metrics_server() {
    let metrics_route = warp::path("metrics").map(|| {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        buffer
    });
    warp::serve(metrics_route).run(([0, 0, 0, 0], 9100)).await;
}

```

---

### 3. The Monitoring Loop

In your main loop, instead of just printing, you update the Prometheus counter:

```rust
loop {
    for result in pkt_count.iter() {
        let (ip_u32, cpu_values) = result?;
        let total: u32 = cpu_values.iter().sum();
        let ip_addr = std::net::Ipv4Addr::from(u32::from_be(ip_u32)).to_string();

        // Update the Prometheus metric
        XDP_PACKETS.with_label_values(&["pass", &ip_addr]).inc_by(total as f64);
    }
    thread::sleep(Duration::from_secs(1));
}

```

---

### 4. Visualizing in Grafana

Once Prometheus is scraping your app, you can use a **PromQL** query in Grafana to see the real-time throughput:

**Query to see PPS per IP:**
`irate(xdp_packet_count[1m])`

### 5. Comparing RTK vs. DPDK in Grafana

The best part of this setup is the "Overlay."

1. Run your **Aya/XDP** test for 5 minutes.
2. Switch to your **DPDK** test (if it also has a Prometheus exporter).
3. In Grafana, you can overlay the two time periods.
* If the **XDP** line is "jagged" while the **DPDK** line is "smooth," it indicates that the Linux kernel's interrupt handling is causing jitter on your Realtek card.
* If the **XDP** line flatlines at a lower PPS than DPDK, you've found the hardware-driver bottleneck.



---

### Summary of the Lab Setup

| Component | Role |
| --- | --- |
| **Realtek NIC** | The hardware under test. |
| **Aya (Kernel)** | High-speed packet filter/counter. |
| **Aya (User)** | Map aggregator & Prometheus Exporter. |
| **Prometheus** | The time-series database. |
| **Grafana** | The visual evidence of performance. |

**Would you like me to help you write the Prometheus configuration file (`prometheus.yml`) to make sure it scrapes your Rust app correctly?**
-----------------------------------------------------------------------------------------------
To get Prometheus to talk to your Rust app, you just need a simple configuration file. Prometheus works on a "pull" model, meaning it will reach out to your app's IP at a set interval to grab the latest numbers.

### 1. The Prometheus Configuration (`prometheus.yml`)

Create a file named `prometheus.yml` and add the following:

```yaml
global:
  scrape_interval: 1s # Set to 1s for high-resolution benchmark data

scrape_configs:
  - job_name: 'aya-xdp-bench'
    static_configs:
      - targets: ['localhost:9100'] # Point to your Rust app's metrics port

```

### 2. Running it via Docker

The fastest way to get the stack up is using Docker:

```bash
# Start Prometheus
docker run -d --name prometheus -p 9090:9090 -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus

# Start Grafana
docker run -d --name grafana -p 3000:3000 grafana/grafana

```

### 3. Summary of the Flow

1. **Your App:** Exposes raw numbers at `http://localhost:9100/metrics`.
2. **Prometheus:** Hits that URL every second and saves the data.
3. **Grafana:** Connects to `http://localhost:9090` (Prometheus) and draws the pretty lines.

---

### Final Documentation Summary

We have covered a massive amount of ground for your Realtek benchmarking project:

* **The Hook:** XDP at the driver level for raw speed.
* **The Logic:** Manual packet parsing (Ethernet -> IP) in Rust with **Aya**.
* **The State:** `PerCpuHashMap` for lock-free counting across cores.
* **The Control:** **Global Variables** to toggle "Drop Mode" instantly.
* **The Bridge:** **AF_XDP** for zero-copy user-space data transfer.
* **The Analytics:** Exporting eBPF data to **Prometheus/Grafana**.

This setup gives you a professional-grade environment to prove exactly how XDP stacks up against DPDK on your hardware.
