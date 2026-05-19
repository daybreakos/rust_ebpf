# XDP programming with Rust: ( Aya )

## Introduction: XDP : eXpress Data Path:

- eBPF: 
    - Extended Version of Berkeley Packet Filter (BPF). 
    - It is an abstract virtual machine (VM) that runs within the Linux kernel, much like the Java Virtual
      Machine (JVM) can run applications in a controlled environment. 
      
    - `eBPF` can execute user-defined programs inside a sandbox in the kernel, it is typically used to 
      enable developers to write low-level monitoring,tracing,Security or networking programs in Linux in a 
      way that ensures optimal performance and more.

- XDP: Framework that allows to perform blazingly fast packet processing with in eBPF applications. 
    To achieve this fast processing, XDP Runs a BPF program as soon as possible, immediately as  a packet is
    received by the NIC.

- XDP is a High performance, Programmable data path in linux Kernel ( introduced in kernel 4.8 ), its a 
  technique to process network packets directly at the NIC driver interface using `eBPF`.

- It offers blazingly fast packet filtering, DDoS mitigation, load balancing by dropping/forwarding packets
  before they hit the expensive, heavy network stack.

- Key Aspects:
    - Process packets at lowest point ( entry point into a system ) giving a near line rate speeds.
    - Uses eBPF technique to execute code at the NIC driver ( RX ) hook.
    - Bases on the driver support : It operates in 3 Modes:
        1. Native Mode: Runs directly in the driver ( preferred for performance )
        2. Offloading Mode: Runs on **Smart NIC HW** 
        3. Generic Mode: Fallback mode for driver without native support. 
    - XDP Programs Action Codes: 
        XDP programs return codes ( 5 Types ):

        **`XDP_DROP`**, **`XDP_PASS`**, **`XDP_TX`**, **`XDP_REDIRECT`**, **`XDP_ABORTED`**
 
    - Use Cases: 
        - Build Fast firewalls,
        - Routers,
        - DDoS Protection tools, ( Cloudflare and Meta )
        - Replacement for DPDK ( as it offers similar performance with out needing specialized HW and SW)

- Scope:

    Framework allows developers to attach eBPF programs:
    1. To low-level hooks, implemented in the network device drivers 
    2. Generic hooks that run after the device driver. 

- High performance in packet process is achieved by bypassing kernel network stack. (avoid, process context
  switches, interrupts, network layer processing ...) basically control of the NIC is transferred to an eBPF
  program ( this is key when working at higher network speeds like 10G ..)

- kernel bypass method: 
    - Requires programmer to write their own logic to match the required data path.
    - As XDP programs run before packets are parsed. The programs should implement similar logic with out
      relying on the kernel/network stack.
    i.e As XDP programs can read/write to network packet data, programs should implement how to process the
    packet, before reaching the kernel network stack. 

## How XDP differs from Kprobe

- `kprobes` (The Spectator): 

    Hooks into high-level kernel functions (e.g.,`ip_rcv` main entry point for IPv4 packets ( L3 ) ). 
    By the time a `kprobe` triggers, the kernel has already allocated an `sk_buff` (socket buffer), 
    parsed headers, and consumed significant CPU cycles. It is primarily used for observability.

- `XDP` (The Gatekeeper):

    Hooks directly into the **RX (Receive) ring buffer** of the 'NIC' driver. 
    It executes before the `sk_buff` is even allocated. It is primarily used for **packet processing**.

**Comparison:**

| Feature | kprobe | XDP |
| --- | --- | --- |
| **Location** | Kernel Functions (IP Stack) | NIC Driver (RX Path) |
| **Memory Access** | Struct-based (Parsed) | Raw DMA Buffer (Unparsed) |
| **Payload** | `sk_buff` (Heavyweight) | `xdp_md` (Lightweight) |
| **Primary Use** | Debugging / Monitoring | Filtering / Load Balancing |


## How XDP Magic Works: The "Raw" Advantage

When an XDP program is triggered, the kernel passes a `struct xdp_md` context. 
This structure provides two crucial pointers: `data` and `data_end`.

Because XDP has direct access to the **Raw Packet Memory**:

1. **Zero-Copy Efficiency:**

    Iot can inspect and modify packets "in-place" within the driver's memory.

2. **Manual Parsing:**

    The developer must manually cast pointers to parse headers (Ethernet → IP → TCP/UDP).

3. **Strict Verification:**

    The eBPF Verifier ensures that every pointer access is bounds-checked against `data_end` to prevent
    kernel crashes.

After inspect a packet, the XDP program returns a XDP Programs Action Codes which determines the packets
fate instantly:

1. **`XDP_DROP`:**

    Discards the packet immediately. This is the fastest way to drop traffic (ex: for DDoS protection).

2. **`XDP_PASS`:**

    Passes the packet up to the normal Linux network stack for standard processing.

3. **`XDP_TX`:**

    Forwards the packet back out of the *same* interface it arrived on (often after modifying headers ).

4. **`XDP_REDIRECT`:**

    Sends the packet to a different NIC or into a user-space application via `AF_XDP`. 

5. **`XDP_ABORTED`:**

    Indicates a program error; the packet is dropped and an error is logged.


## XDP Operational Modes

XDP operates at different layers of the **system depending on your hardware capabilities & driver** support.

Below are the three primary modes:

### 1. Offloaded Mode (`xdp-offload`)

The eBPF program is loaded directly onto the **(NIC)** hardware, typically an NPU or FPGA.

* **Performance:**

    The absolute highest. Packets are processed (or dropped) before they even reach the host CPU.

* **Constraint:**

    Requires specific hardware support (e.g., Netronome or certain Mellanox cards).

### 2. Native Mode (`xdp-drv`)

The program runs within the **NIC driver's** main receive path.

* **Performance:**

    Very high. It intercepts packets as soon as the driver handles the DMA (Direct Memory Access) transfer,
    before kernel allocates an `sk_buff` (the heavy metadata structure used by the Linux networking stack).

* **Constraint:**

    Requires a NIC driver that has been updated to support XDP.
    (most modern 10G+ drivers like `i40e`, `mlx5`, and `ixgbe` support this).

### 3. Generic Mode (`xdp-generic` / SKB Mode)

A **software-based fallback** provided by the kernel.

* **Performance:**

    Lowest of the three. Because it runs after the kernel has already converted the raw packet into an
    `skb` (Socket Buffer), you lose the performance gains of "early" processing.

* **Use Case:** 

    Ideal for testing XDP programs on hardware/drivers that do not yet support Native mode, or for local
    development in virtual machines.


### Comparison Summary

| Mode | Location | Performance | CPU Impact | Hardware Dependency |
| --- | --- | --- | --- | --- |
| **Offloaded** | NIC Hardware | Extreme | Zero | Very High |
| **Native** | NIC Driver | High | Low | Medium (Driver-specific) |
| **Generic** | Network Stack | Moderate | High | None (Works everywhere) |


##  How to load XDP programs:

How to force a specific mode when loading your XDP program using : 


### 1. Using `iproute2` (`ip` command)

- iproute2: This package is the "gold standard" for quick-and-dirty XDP management without writing a 
  custom loader. 
  It’s the most popular tool most SREs and Kernel engineers reach for first to verify if a mode is even 
  supported by the driver.

- The `ip` command uses specific flags to tell the kernel which XDP mode to attempt. 
  If you don't specify a flag, it defaults to **Native** (and fails if the driver doesn't support it).

| Mode | Command Flag | Description |
| --- | --- | --- |
| **Native** | `xdp` or `xdpdrv` | Attempts to load into the driver's RX path. |
| **Generic** | `xdpgeneric` | Forces the software-based SKB fallback. |
| **Offloaded** | `xdpoffload` | Attempts to load onto the NIC hardware. |

#### Common Commands

**1. Load a program in Generic mode:**

```bash
    # Useful for testing on VMs or unsupported drivers
    ip link set dev eth0 xdpgeneric obj my_prog.o sec xdp_section_name

```

**2. Load a program in Native mode:**

```bash
    # The high-performance choice for production
    ip link set dev eth0 xdpdrv obj my_prog.o

```

**3. Check which mode is currently running:**
After loading, run `ip link show dev eth0`. You will see the mode explicitly labeled in the output:

* `prog/xdp` → Native
* `prog/xdpgeneric` → Generic
* `prog/xdpoffload` → Offloaded

**4. Remove the XDP program:**

```bash
    # This works regardless of the mode it was loaded in
    ip link set dev eth0 xdp off

```

#### The "Replacement"

A common mistake when switching modes using `iproute2` is trying to load a `generic` program while a
`native` one is already attached.

If you want to **swap** programs or modes without downtime, you often need to use the `force` flag, 
or better yet, the atomic replace features supported in newer kernels:

```bash
    ip link set dev eth0 xdpgeneric obj new_prog.o replace
```

> [!NOTE]
> When using `iproute2`, the program must be compiled into an ELF object file (usually via Clang/LLVM)
> containing the BPF bytecode.

When using modern libraries like `libbpf`, `aya-rs`, or `cilium/ebpf`, you specify the operational mode 
using **Flags**. 

If you don't specify one, the kernel usually attempts **Native** mode first and may fall back to **Generic**
depending on the library's defaults.

### 2. Loading XDP in Different Frameworks

Each language ecosystem has a standard way to map the kernel's bitwise flags (like `XDP_FLAGS_SKB_MODE`) to 
high-level code.

#### 1. C (libbpf)

In C, you typically use the `bpf_xdp_attach` function. The mode is determined by the `flags` parameter.

```c
// High-level attach function
int ifindex = if_nametoindex("eth0");
int prog_fd = bpf_program__fd(prog);

// Modes: 
// 0 = Default (Native with fallback)
// XDP_FLAGS_SKB_MODE = Generic
// XDP_FLAGS_DRV_MODE = Native
// XDP_FLAGS_HW_MODE  = Offload

bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);

```

#### 2. Rust (Aya)

Aya uses a clean Enum-based approach. 
If you use `XdpFlags::default()`, it usually tries to be "smart," but you can be explicit:

```rust
use aya::programs::{Xdp, XdpFlags};

let program: &mut Xdp = bpf.program_mut("my_xdp_prog").unwrap().try_into()?;
program.load()?;

// Explicitly forcing Generic mode
program.attach(&interface, XdpFlags::SKB_MODE)?; 

// Or Native (will fail if driver doesn't support it)
program.attach(&interface, XdpFlags::DRV_MODE)?;

```

#### 3. Go (cilium/ebpf)

The Go library separates the **loading** of the program from the **attachment** to the link. 
Attaching XDP in Go often involves the `netlink` library or the `link` package in newer versions of
`cilium/ebpf`.

```go
import "github.com/cilium/ebpf/link"

// Attach the program to the interface
l, err := link.AttachXDP(link.XDPOptions{
    Program:   prog,
    Interface: iface.Index,
    // Flags define the mode:
    // link.XDPGenericMode
    // link.XDPDriverMode
    Flags:     link.XDPGenericMode, 
})

```
#### Summary of Mode Flags

If you are using the command line (like `iproute2`), these flags correspond directly to the keywords you 
type:

| Mode | Kernel Flag | `ip link` Command |
| --- | --- | --- |
| **Offloaded** | `XDP_FLAGS_HW_MODE` | `ip link set dev eth0 xdpoffload ...` |
| **Native** | `XDP_FLAGS_DRV_MODE` | `ip link set dev eth0 xdpdrv ...` |
| **Generic** | `XDP_FLAGS_SKB_MODE` | `ip link set dev eth0 xdpgeneric ...` |

> [!WARNING]
> **A Note on Performance:** If you load a program in **Generic** mode for "Packet Analytics" on a
> high-traffic 10Gbps link, your CPU usage will spike significantly because the kernel is doing the heavy
> lifting of `skb` allocation before your program even sees the packet.

## XDP Context (***)

When an XDP program is triggered, the kernel (via the NIC driver) provides a **`struct xdp_md`** context.
Think of this struct as a **metadata wrapper** that points to a raw "chunk" of memory where the packet has 
just been landed by the network hardware.

Here is the breakdown of how that context works:

### 1. The Core Purpose

The context exists to give your program access to the raw packet data without copying it. 
Instead of moving the packet into a complex data structure (like an `sk_buff`), the kernel simply hands you 
a struct containing **memory offsets**.

### 2. Key Fields in `struct xdp_md`

The most important members of the context are pointers (represented as `__u32` offsets) to the packet's 
location in memory:

* **`data`**: 

    Points to the very beginning of the network packet (usually the Ethernet header).

* **`data_end`**: 

    Points to the exact end of the packet data.

* **`data_meta`**: 

    Points to a small "headroom" area where you can store custom metadata to pass to other layers of the
    kernel.

* **`ingress_ifindex`**: 

    The ID of the network interface where the packet arrived.

### 3. Usage in C vs. Rust

The way you interact with this context depends on your language, but the underlying logic remains the same.

* **In C (libbpf):** 

    You access the struct directly. 
    You must cast the `__u32` values to pointers to perform arithmetic.

```c
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
```

* **In Rust (Aya):** 

    You use the `XdpContext` object, which provides methods that return the memory addresses.

```rust
    let start = ctx.data();
    let end = ctx.data_end();
```

### 4. The "Safety Check" Requirement

The kernel **forbids** you from reading any data using these pointers until you have proved that the access
is safe.

If you want to read an Ethernet header (14 bytes), you must explicitly write:

`if (data + 14 > data_end) return XDP_DROP;`

If you omit this check, the **eBPF Verifier** will see that you are accessing memory without a 
"boundary guard" and will refuse to load your program, protecting the kernel from crashing.

### **Summary:** 

- The `xdp_md` context is a "view" into the NIC's DMA memory. 
- Mastering XDP is essentially the art of using these context pointers to navigate the packet's layers 
  (L2, L3, L4) while satisfying the Verifier's strict safety rules.


## Verifier: ( kernel eBPF )

After we load the eBPF bytecode for execution, the code is passed through a **verifier** which is a "static
analyzer" that checks every possible branch of your code before allowing it to run. 

- The Verifier very careful to pass pointers. Example when we try to read 4 bytes from a pointer without
  first proving that those 4 bytes are within the packet boundaries, the **Verifier** will terminate the 
  program with `buffer out of bounds` error. 

- The Verifier maintains a state for every register.

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


### The "C" vs. "Rust" Verifier Experience


#### C:

When writing XDP program with "C", developer often check manually at every step which is prone to
"off-by-one" error that are harder to debug. 

```C 
    struct ethhdr *eth = data 
    if ( data + sizeof(*eth) > data_end ) // Manual Check 
        return XDP_DROP.
```

#### Rust: With Aya 

The `ptr_at` helper is the "security guard" that convinces the Verifier your code is safe. 

```rust
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();          // Start of packet
    let end = ctx.data_end();        // End of packet
    let len = mem::size_of::<T>();   // Size of the header we want to read

    // The "Golden Rule" of XDP: Never touch memory without checking bounds first!
    // This specific comparison is what the Verifier looks for:
    if start + offset + len > end {
        return Err(());
    }

    // Convert the raw address to a typed pointer
    Ok((start + offset) as *const T)
}
```
In general Rust way is to abstract this, because it's an **inline** function (`#[inline(always)]`) the
compiler merges it directly into the program logic. Which the kernel verifier sees as a clean logical
boundary check followed by a pointer access. 

Note: Common Verifier "Gotchas" in Rust
---
- Variable Offsets: kernel verifier hates if the offset is unknown at compile time. If the offset comes from
  a calculation ( variable length IP options field ) you must provide **another** check against `data_end`
  after calculating that new offset.

- Stack Limit: eBPF has a tiny stack (512 bytes ), copying a large packet header *onto* the stack rather
  then reading via a pointer, the verifier will reject the program.



## ▾ XDP Context (***) :

### 1. The Core Purpose :

The XDP Context is the "window" into the packet. 

In the kernel, this is defined as `struct xdp_md`. It doesn't contain the packet data itself; 
instead, it contains **metadata** and **pointers** that tell you where the data starts and ends in RAM.

### 2. Key Fields in `struct xdp_md` :

When your Rust function receives an `XdpContext`, it is interacting with these primary fields:

* **`data`**: A pointer to the very start of the raw packet data (usually the Ethernet header).
* **`data_end`**: A pointer to the end of the packet data.
* **`ingress_ifindex`**: The ID of the network interface where the packet arrived.

### 3. Usage in C vs. Rust : subsection

In **C**, you perform "cowboy" pointer arithmetic. 
In **Rust**, Aya provides helper methods to make this feel more "Rustic," though you are still performing 
pointer offsets under the hood.

| Feature | C (libbpf) | Rust (Aya) |
| --- | --- | --- |
| **Access** | Direct pointer casting | `ctx.data()` and `ctx.data_end()` |
| **Safety** | Manual checks required | Boundary checks enforced by Verifier |
| **Casting** | `(struct ethhdr *)data` | `unsafe { ptr.read_unaligned() }` or custom slices |

### 4. The "Safety Check" Requirement :

This is the most critical part of XDP. 
You **cannot** access a pointer without first proving to the kernel that the access is within bounds.

```rust
// RUST (Aya) Logic
let start = ctx.data();
let end = ctx.data_end();

// If we want to read 14 bytes (Ethernet header), 
// we MUST check if (start + 14) <= end
if start + 14 > end {
    return Ok(xdp_action::XDP_ABORTED);
}
```

**Summary:** The XDP Context is a bridge between the raw hardware buffer and your high-level logic.

## ▾ Verifier: ( kernel eBPF ) : 

The Verifier is a "strict judge" that reads your bytecode before it runs to ensure it won't crash the kernel.

### 1. The "C" vs. "Rust" Verifier Experience :

#### C: :

In C, the Verifier is often frustrating. You might write code that looks correct, but the compiler optimizes 
away a safety check, and the Verifier rejects the program with an opaque error like 

`R1 offset is outside of the packet`.

#### Rust: With Aya : subsubsection

Rust is a natural fit for the Verifier. Because Rust's compiler is already obsessed with memory safety and 
bounds checking, the code you write in Aya often "just works" on the first try with the Verifier.

* **Aya's Secret Sauce:** Aya uses `compiler-builtins` and specific intrinsics to ensure that the LLVM 
  output is "BPF-friendly."

---

## ▾ Note: Common Verifier "Gotchas" in Rust : section

Even with Rust, you can run into these common "rejections":

1. **Variable-Length Loops:** 

The Verifier must know exactly how many times a loop will run. 
You cannot loop based on a packet's length unless you use a constant maximum (e.g., `for i in 0..16`).

2. **Stack Limit (512 Bytes):** 

eBPF has a very small stack. 
If you define a large array inside your Rust function, the Verifier will reject it. 
Use **Maps** for large data storage.

3. **Unchecked Pointers:** 

If you forget a single `if` check before accessing a pointer, the Verifier will kill the program.

4. **Unaligned Access:** 

Some CPU architectures (and the BPF VM) are picky about reading data that isn't aligned to 4 or 8 bytes.
Aya's `read_unaligned` is your friend here.

---

## Complete architectural journey of a packet through an XDP-powered system. 

This summary connects the hardware, the driver, your Rust code, and the final kernel destination.

### 1. The Life of a Packet: From Wire to App

| Stage | Location | Action |
| --- | --- | --- |
| **Ingress** | NIC Hardware | Packet arrives as electrical/optical signals. |
| **DMA Transfer** | RX Ring Buffer | NIC writes raw bytes directly into a memory page. **No CPU involved yet.** |
| **XDP Hook** | **Driver** | Before an `sk_buff` is created, the driver triggers your **Aya/Rust** program. |
| **Processing** | BPF VM | Your code uses `XdpContext` to parse headers and apply logic (like dropping a SYN flood). |
| **Optional Meta** | Headroom | You use `adjust_meta` to write "tags" (e.g., a security score) before the packet. |
| **Verdict** | BPF VM | Your program returns `XDP_PASS`, `XDP_DROP`, `XDP_TX`, or `XDP_REDIRECT`. |
| **Kernel Entry** | IP Stack | If `PASS`, the kernel finally builds the `sk_buff` and notices your metadata. |
| **Delivery** | Socket | The packet reaches your application (e.g., Nginx or a Go service). |

---

### 2. The Architectural "Secret Sauce"

The reason this architecture is so powerful is **Context Continuity**.

1. **The Memory stays still:** 

    The packet never moves. The `XdpContext` is just a temporary "lens" through which your code views the 
    DMA memory.

2. **The Verifier is the Architect:** 

    By enforcing `ptr_at` style boundary checks, the kernel ensures that your "fast path" code can't 
    accidentally corrupt the kernel's memory or crash the system.

3. **Metadata as a Bridge:** 

    By using `data_meta`, you create a communication channel between the ultra-fast, low-level XDP layer 
    and the slower, feature-rich upper layers of Linux.

---

### 3. Final Master Class Summary

To master XDP with Rust and Aya, you have effectively mastered four domains:

* **The Hardware Handshake:** Understanding how the NIC driver provides the context.
* **The Verifier Protocol:** Writing code that "proves" its safety via boundary checks.
* **The Pointer Ladder:** Navigating L2 (Ethernet) → L3 (IP) → L4 (TCP) using offsets.
* **The Verdict System:** Deciding the fate of a packet in nanoseconds.
