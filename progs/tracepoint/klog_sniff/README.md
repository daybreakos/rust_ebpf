# tracepoint example:

Note: the project is  built on using aya-template:

Tracepoint program hooks into a specific event in the Linux kernels `printk` subsystem and 'console' 
event. ( /sys/kernel/debug/tracepoints/events/printk/console/ )

(likely `printk` or a similar diagnostic event) to log process IDs and their associated messages.

Breakdown of how the program works, from the environment setup to the memory manipulation.

---

1. Constrains on Rust ( Boilerplate and Constrains )

`eBPF` programs run inside the Linux kernel virtual machine, they operate under strict constraints:

* **`#![no_std]`**: program cannot use the Rust standard crate. ( no complex types )
* **`#![no_main]`**: There is no standard "main" function; Since the kernel triggers specific entry points.
* **`panic_handler`**: A custom, infinite-loop panic handler is required as kernel cannot "crash" gracefully
  to the terminal.

2. The Tracepoint Entry

The `#[tracepoint]` macro marks the `klog_sniff` function as the entry point.

```rust
pub fn klog_sniff(ctx: TracePointContext) -> u32 { ... }

```

When the specific kernel event occurs, the kernel passes a `TracePointContext` to this function. 
=> This context contains a "blob" of raw memory representing the event's arguments (like PID, filenames, or 
messages).

3. Handling Dynamic Data (`__data_loc`)

In kernel `tracepoints`, strings are often stored using a mechanism called **`__data_loc`**. 
Instead of the string being inside the fixed `struct`, the `struct` contains a 32-bit integer that acts as 
a "pointer" to where the string actually lives in memory.

The code performs these steps to find the message:

a. **Read PID**: It grabs the Process ID at offset 4 of the context.
b. **Read `data_loc**`: It reads the 32-bit value at offset 8.
c. **Calculate Offset**: The kernel encodes `__data_loc` such that the actual memory offset is stored in the
   lower 16 bits (`data_loc & 0xFFFF`).
d. **Pointer Arithmetic**: It adds that offset to the base pointer of the context (`ctx.as_ptr()`) to find 
   exactly where the string starts in kernel memory.

4. Safe Memory Access

Because eBPF cannot directly dereference pointers (to prevent kernel crashes), it uses a specialized 
helper:

* **`bpf_probe_read_kernel_str_bytes`**: 
    This helper function safely copies the string from kernel memory into a local buffer (`buf`) that the 
    eBPF program owns.

* **`from_utf8_unchecked`**: Since the buffer is now local, we convert the bytes to a string. 
  It's "unchecked" to save program space and complexity, assuming the kernel provides valid UTF-8/ASCII.

5. Logging

`info!` macro (from `aya-log`) sends the formatted string back to "user-space."

```rust
info!(&ctx, "PID {}: {}", pid, msg_to_print);

```

When you run the corresponding user-space application, you will see these logs appear in your terminal, 
showing which PID triggered the event and what the message was.

recap:

| Component | Purpose |
| --- | --- |
| **`TracePointContext`** | Access to the raw kernel event data. |
| **`read_at`** | Reads fixed-size fields (like PID) from the event. |
| **`0xFFFF` Mask** | Extracts the relative jump address for dynamic strings. |
| **`aya-log`** | Safely passes messages from the kernel back to your terminal. |

//-----------------------------------------------

This is Source template is generated using aya-template 

## Prerequisites

- stable rust toolchains: `rustup toolchain install stable`
- nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
- (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
- bpf-linker: `cargo install bpf-linker` 

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
// or 
RUST_LOG=info sudo -E ./target/debug/klog_sniff 
```
On a other console run: ( run as root )

`#echo "hello rust" > /dev/kmsg ` 

The log has to be caught by our program and display

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.


