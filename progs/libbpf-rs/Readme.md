# libbpf-rs : ( libbpf: Wrapper )

`libbpf-rs` is a Rust wrapper around `libbpf` 
The wrapper helps in build and develop BPF programs with standard Rust tooling:

## Introduction:

### Standard `libbpf` workflow:

First look at what `libbpf` is for and what it achieves:

- Standard workflow for any `eBPF` program ( regardless of the loader language ) follows the below
  life-cycle:
```mermaid
flowchart LR
    A[Open] --> B[Load] --> C[Verify] --> D[Attach]
```
1. hello.bpf.c: ( C code that actually runs in the kernel )
```c 
    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>

    // This defines WHERE the program attaches (a tracepoint for execve)
    SEC("tp/syscalls/sys_enter_execve")
    int handle_execve(void *ctx) {
        char msg[] = "Hello, Kernel!";
        bpf_printk("%s\n", msg);
        return 0;
    }
    char LICENSE[] SEC("license") = "GPL";
```
- The `SEC` macro tells the compiler where to put this code in the ELF binary. 

2. Compilation (C -> Bytecode)

Generate byte code that contains ELF with eBPF instructions that are for  BPF VM, 
```bash 
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hello.bpf.c -o hello.bpf.o
```
- Use `clang` with `--target bpf` flag. This generates ELF file containing the `eBPF` instructions.
- `-g`: generate debug info (BTF). This is required for **CO-RE**
- `-target bpf`: Tell Clang to emit eBPF bytecode instead of x86 machine code.
- `-o hello.bpf.o`: resulting object file. 

3. Loader program ( in C ):

To write Loader in C ( using libbpf ): 
`loader.c`:
```c 
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include "hello.bpf.o" // In reality, you load the file path

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    // 1. OPEN: Parse the ELF file and check structure
    obj = bpf_object__open_file("hello.bpf.o", NULL);
    
    // 2. LOAD & VERIFY: Push bytecode to kernel; 
    // The Kernel Verifier checks for safety here!
    bpf_object__load(obj);

    // 3. FIND: Locate the specific program in the object
    prog = bpf_object__find_program_by_name(obj, "handle_execve");

    // 4. ATTACH: Hook the program to the actual kernel tracepoint
    link = bpf_program__attach(prog);

    printf("BPF program attached. Press Enter to exit...\n");
    read(0, NULL, 1);

    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
``` 

4. **maps**: Maps are defined in kernel-space code (eBPF program), but actually created by the kernel when
   the user-space loader loads the program via `libbpf`:
   the `.bpf.c` file contains the definition of the map:

- This is just a definition, not creation yet
```c 
// Kernel side definition of the map that's to be used
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, long);
} my_map SEC(".maps");
```
- user-space: loader creates the maps (using `bpf()` sys call):
    - When your Rust (or C) program does:
      `bpf_object__load()` (via `libbpf`)
      or `obj.load()` (via `libbpf-rs`)

    - `libbpf`: 
        * parses the ELF
        * finds map definitions
        * issues syscalls to the kernel.

- Final step: ( after the bpf() syscall from loader program:)
    * The kernel: when the syscall (bpf()) issues for map creation,
    * kernel allocates memory
    * sets map type, size, etc.
    * returns a file descriptor (FD)

4. Verification and attachment: ( Kernel's Job ):

Once your loader calls `bpf_object__load`, a fascinating process happens inside the Linux Kernel:

- **The Verifier**: The kernel receives the bytecode. It performs a "dry run" to ensure the code cannot
  crash the kernel. It checks for infinite loops, out-of-bounds memory access, and uninitialized variables.
  If the verifier says no, your loader program will crash with an error.

- **JIT Compilation**: If verified, kernel translates the generic `eBPF` bytecode into native machine code
  (x86 or ARM) for maximum speed.

- **Attachment**: When you call attach, the kernel inserts a jump instruction at the `tracepoint`. After
  which the code gets called every time `execve` is called, your BPF code runs.

- **Interact with MAP**: Maps are defined in kernel (eBPF program), but actually created by the kernel when
  the user-space loader loads the program via `libbpf`. To interact with the Maps:
  * `bpf_map__lookup_elem(...)`
  * `bpf_map__update_elem(...)`


5. Why `libbpf-rs`: a Rust wrapper:

    Issues with C based `libbpf`:

    - The `C` loader code is brittle: Has no check for misspell ex:`handle_execve` the compiler is fine but
      the program fails at runtime. 

    - In the Rust workflow, `libbpf-cargo` generates a struct where `handle_execve` is a property.
      If you rename it in C, the Rust code won't even compile, saving you hours of debugging.

    - `libbpf` exposes raw C pointers, which are inherently unsafe and easy to misuse. And other risks such
      as *null ptr de-reference*, *memory leaks*, *use-after-free*. 

    - `libbpf` has a manual life-cycle management ( easy for bug if the flow breaks )
    ```mermaid
    flowchart LR
        A[Open] --> B[Load] --> C[Verify] --> D[Attach] --> E[Destroy]
    ```
    - Weak error handling: 
    ```c 
        //inconsistent checks and poor error context
        if (!obj) return -1;
    ```
    - String based lookups:(not type safe) ( causes runtime failures on miss match and failures )
    `bpf_object__find_map_by_name(obj, "events");`

    - code bloating: Repetitive setup and attach code logic. (`libbpf` requires significant boilerplate
      code)
    
    Rust's `libbpf-rs`:

    - Eliminates unsafe pointer usage:

      `libbpf-rs encapsulates unsafe operations, exposing a safe API. 
     
      Instead of:  `unsafe { bpf_object__open_file(...)}`
      you get: `let obj = ObjectBuilder::default().open_file("hello.bpf.o")?; `

    - Rust automatic cleanup based on Scope:`drop(obj)` is done automatically. 

    - Error handling: use of error propagation "?" to upper calls:
    ` let obj = ObjectBuilder::default().open_file("hello.bpf.o")?.load()?`

    - Abstracts common work flow : `skel.attach()?;`

    `libbpf-cargo` Crate: Automate code generation, eliminates manual buildings.

Final Work flow:
```mermaid
flowchart LR
   A["BPF C code"] --> B["libbpf-cargo (build time)"] --> C["Generated Rust skeleton"] --> D["libbpf-rs (runtime API)"] --> E["libbpf (C core)"] --> F["Linux kernel"]
```
       
### Why `libbpf-rs` 

- `libbpf-rs` helps in transforming the low-level, unsafe C interface into a safe, idiomatic Rust
  API-reducing bugs, eliminating boilerplate, and enforcing correct life-cycle management. 

- `libbpf` is powerful, the trade off of using `libbpf-rs` comes with small abstraction overhead less
  control then pure `libbpf`, and the major plus point is it introduces safety and maintainability.


  ## `libbpf-rs`:

- Safe(ish) Rust  bindings over `libbpf`: It let's 
    * Loading Object files. 
    * Access Maps.
    * Attach Programs 
    * Replaces C based user-space loader. Opening for Async and other powerful frameworks at user-space
      control framework. 

- work flow:

```mermaid 
    flowchart LR 
    A["Rust App"] --> B["libbpf-rs"] --> C["libbpf"] --> D["kernel (eBPF)"]
```

#### `libbpf-cargo` Crate 

Refer to : "00_rust_tools_ecosystem/27-ProgramaticTooling.md"

- `libbpf-cargo` helps in building and developing eBPF programs with standard Rust Tooling. When combined
  with `libbpf-rs` it helps in comping with BPD C code, `*.bpf.c` to Bytecode so that `libbpf-rs` can work 
  with it.

- It's a build tool ( code generator ) 
    - Compiles `*.bpf.c` to eBPF byte code.
    - Generates Rust skeleton (bindings)

- workflow: 
    * `libbpf-cargo` comes with two interfaces:
        1. `SkeletonBuilder` API for use with cargo's build scripts.
        2. `cargo-libbpf` cargo subcommands for use with cargo.

    * when working with `libbpf-rs` the `SkeletonBuilder` API approach is preferred over cargo subcommands.

    The Skeleton is the magic bridge that makes `libbpf-rs` so powerful. 
    In traditional C development, you'd have to manually manage pointers to your `BPF` programs and `maps`. 
    In Rust, `libbpf-cargo` automates this by inspecting your compiled BPF object and generating a type-safe 
    Rust struct.

    * The process happens during your build phase, typically triggered by a build.rs script.
        - Compilation: clang compiles your `hello.bpf.c` into a BPF ELF object (`hello.bpf.o`).
        - Inspection: `libbpf-cargo` parses that ELF file. It looks for:
            * Programs: Functions marked with SEC("...").
            * Maps: Global variables or BPF maps used for storage.
            * Types: Any C structs defined in your BPF code.
        - Generation: It writes a Rust file (the skeleton) that mirrors the structure of your C code.

------------------
# Exampleour

To give you the "complete picture," we should look at how this was traditionally done in **C**, as it helps
appreciate exactly what `libbpf-rs` and `libbpf-cargo` are automating for you in **Rust**.

The standard workflow for any eBPF program (regardless of the loader language) follows this lifecycle: 

**Open → Load → Verify → Attach**.

---

## 1. The Kernel Code (`hello.bpf.c`)
First, we write the C code that will actually run in the kernel. We use `SEC` macros to tell the compiler where to put this code in the ELF binary.

```c 
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// This defines WHERE the program attaches (a tracepoint for execve)
SEC("tp/syscalls/sys_enter_write")
int handle_write(void *ctx) {
   // 1. use __u32 instead of u32 as In std C u32 is not builtin so we use __u32 or unsigned int
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid < 1000) { 
      bpf_printk("Write syscall detected from PID %d\n", pid);
    }
    return 0;
}
```

---

## 2. Compilation (C to Bytecode)
Use **Clang** with the `-target bpf` flag to creates the ELF file containing the eBPF instructions.

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hello.bpf.c -o hello.bpf.o
```
* `-g`: Generates debug information (BTF), which is required for **CO-RE**.
* `-target bpf`: Tells Clang to emit eBPF bytecode instead of x86 machine code.
* `-o hello.bpf.o`: The resulting "Object" file.

---

## 3. The Loader Program (in C)
If loader program written in C (using the raw `libbpf` library), your code would look like this. 
This mirrors what the Rust skeleton does behind the scenes.

**File:** `loader.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include "hello.bpf.o" // In reality, you load the file path

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    // 1. OPEN: Parse the ELF file and check structure
    obj = bpf_object__open_file("hello.bpf.o", NULL);
    
    // 2. LOAD & VERIFY: Push bytecode to kernel; 
    // The Kernel Verifier checks for safety here!
    bpf_object__load(obj);

    // 3. FIND: Locate the specific program in the object
    prog = bpf_object__find_program_by_name(obj, "handle_execve");

    // 4. ATTACH: Hook the program to the actual kernel tracepoint
    link = bpf_program__attach(prog);

    printf("BPF program attached. Press Enter to exit...\n");
    read(0, NULL, 1);

    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
```
---

## 4. Verification and Attachment (The Kernel's Job)
Once your loader calls `bpf_object__load`, a fascinating process happens inside the Linux Kernel:

1.  **The Verifier:** The kernel receives the bytecode. 
    - It performs a "dry run" to ensure the code cannot crash the kernel. 
    - It checks for infinite loops, out-of-bounds memory access, and uninitialized variables. 
    - If the verifier says no, your loader program will crash with an error.

2.  **JIT Compilation:** 
    - If verified, the kernel translates the generic eBPF bytecode into native machine code (x86 or ARM) for
      maximum speed.

3.  **Attachment:** 
    - When you call `attach`, the kernel inserts a jump instruction at the tracepoint. 
    - Now, every time `execve` is called, your BPF code runs.

---

## Comparison: C Loader vs. `libbpf-rs`
| Step | Raw C Loader | Rust (`libbpf-rs`) |
| :--- | :--- | :--- |
| **Step 1 & 2** | Identical (Clang + BPF C code). | Identical. |
| **Skeleton** | Manual or `bpftool gen skeleton`. | Automated by `libbpf-cargo`. |
| **Safety** | Raw pointers (`*obj`). Manual cleanup. | RAII (automatically cleans up when dropped). |
| **Finding Progs** | `bpf_object__find_program_by_name`. | `skel.progs.handle_execve`. |

Next: see the `bpftool` command used to inspect the bytecode inside that `.o` file to see what the kernel
actually sees?

-----------------------

# bpftool in action:


To see what the kernel actually sees, we use `bpftool`. 

This is the essential utility for debugging eBPF because it allows you to peak inside the ELF object file 
and the live kernel memory.

Here is how you inspect the bytecode and understand the verification process.

---

### 1. Inspecting the Bytecode (The ELF Object)
Once you've compiled your C code into `hello.bpf.o` using Clang, it contains "Generic eBPF Instructions." 
You can dump these to see the assembly-like code:

```bash
# Dump the instructions from the compiled object file
bpftool prog dump xlated file hello.bpf.o
```

**What you will see:**
A list of instructions like `(61) r1 = *(u32 *)(r1 +0)`, which represents moving data between virtual
registers. This is the "bytecode" that the loader sends to the kernel.

---

### 2. The Kernel's Verification Process
When your Rust or C loader calls `load()`, the kernel doesn't just run the code; it passes it through the
**Verifier**. This is the "Security Guard" of the Linux kernel.

* **DAG Check:** It ensures there are no loops (unless using modern bounded loops).
* **Memory Safety:** It ensures the program never reads or writes to memory it doesn't own.
* **Register Tracking:** It tracks the state of every register to ensure they contain valid types before 
  being used.

If the verifier fails, it provides a "Verifier Log."

This log is notoriously difficult to read but extremely precise.

`libbpf-rs` will capture this log and print it to your terminal if your program fails to load.

---

### 3. JIT (Just-In-Time) Compilation
If the Verifier is happy, the kernel's **JIT Compiler** takes that generic bytecode and translates it into
the actual machine code of your CPU (x86_64, ARM64, etc.). 

You can see the final, optimized machine code running on your CPU with:
```bash
# List all running BPF programs to get the ID
sudo bpftool prog list

# Dump the JITed (native) instructions for a specific ID
sudo bpftool prog dump jited id <PROG_ID>
```

---

### 4. Summary of the Entire Flow

| Step | Tool/Library | Artifact | Location |
| :--- | :--- | :--- | :--- |
| **Write** | Text Editor | `hello.bpf.c` | User Space |
| **Compile** | `clang -target bpf` | `hello.bpf.o` (Bytecode) | User Space |
| **Skeleton** | `libbpf-cargo` | `hello.skel.rs` | User Space |
| **Load** | `libbpf-rs` | System Call (`bpf()`) | User -> Kernel |
| **Verify** | **Kernel Verifier** | Safety Approval | Kernel Space |
| **JIT** | **Kernel JIT** | Native Machine Code | Kernel Space |
| **Attach** | `libbpf-rs` | Live Hook (Tracepoint) | Kernel Space |

---

### Pro-Tip: Debugging with `bpftool`
If your program is "attached" but nothing is happening, you can check if it's actually being triggered:

```bash
# See how many times your program has run and how much CPU time it took
sudo bpftool prog show id <PROG_ID> --stats
```

Now that you've seen the "Manual C" way and the "Rust/libbpf-rs" way, you have a complete picture of the 
eBPF ecosystem. 

Next: **BPF Map** to your Rust project now? ANd how it allows kernel code to send data back to your rust
code to be printed.


------------------------

# maps:

Adding a **BPF Map** is the "Aha!" moment in eBPF development. 

Since the kernel and your Rust program live in different memory spaces, they can't simply share a variable.
A BPF Map is a piece of shared memory managed by the kernel that both sides can access.

We will use a **Hash Map** to count how many times each Process ID (PID) calls a specific system call.

---

### 1. Update the Kernel Code (`hello.bpf.c`)
We define the map using the `SEC(".maps")` macro.

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define a Hash Map: Key = PID (u32), Value = Counter (u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} exec_counts SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count, init_val = 1;

    // Look up the PID in our map
    count = bpf_map_lookup_elem(&exec_counts, &pid);
    if (count) {
        // If found, increment the counter
        __sync_fetch_and_add(count, 1);
    } else {
        // If not found, insert 1
        bpf_map_update_elem(&exec_counts, &pid, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```



---

### 2. Update the Rust Loader (`main.rs`)
Because we are using `libbpf-cargo`, our generated skeleton now has a `maps` field. We can use this to poll
the data from the kernel.

```rust
mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}

use hello::HelloSkelBuilder;
use std::time::Duration;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let builder = HelloSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Monitoring execve() calls... Press Ctrl+C to stop.");

    // Access the map via the skeleton
    let maps = skel.maps();
    let exec_counts = maps.exec_counts();

    loop {
        thread::sleep(Duration::from_secs(2));
        println!("--- Stats ---");

        // Iterate through all keys (PIDs) currently in the kernel map
        // Note: In a real app, you'd use a more efficient way to collect keys
        let mut key = [0u8; 4]; // u32 is 4 bytes
        let mut next_key = [0u8; 4];

        // This is a simplified logic for demonstration
        // libbpf-rs provides idiomatic iterators for maps
        for key_bytes in exec_counts.keys() {
            let mut val_bytes = [0u8; 8]; // u64 is 8 bytes
            if let Ok(Some(value)) = exec_counts.lookup(&key_bytes) {
                let pid = u32::from_ne_bytes(key_bytes.try_into().unwrap());
                let count = u64::from_ne_bytes(value.try_into().unwrap());
                println!("PID {}: {} executions", pid, count);
            }
        }
    }
}
```

---

### 3. How to Inspect the Map with `bpftool`
While your Rust program is running, you can "spy" on the data directly using `bpftool` without even 
stopping the app.

1.  **Find the map ID:**
    ```bash
    sudo bpftool map list
    ```
2.  **Dump the contents:**
    ```bash
    # Replace <ID> with the ID found in the previous step
    sudo bpftool map dump id <ID>
    ```



---

### Why this is powerful
By using a BPF Map, you've moved from just "printing logs" to **State Management**. 
* The **Kernel** does the heavy lifting: filtering, counting, and aggregating.
* The **Rust App** only wakes up occasionally to read the final results.

This is exactly how high-performance tools like **Cilium** (networking) or **Falco** (security) work. 

They perform millions of checks per second in the kernel and only send relevant summaries to the user-space
application.

Next: Maps: Sending complex data (like full file paths or network headers) using `RingBuffer`, which is much faster than standard Maps for streaming events

--------------------

# maps ( ringbuffer )

Adding a **BPF Map** is the "Aha!" moment in eBPF development. Since the kernel and your Rust program live in different memory spaces, they can't simply share a variable. A BPF Map is a piece of shared memory managed by the kernel that both sides can access.

We will use a **Hash Map** to count how many times each Process ID (PID) calls a specific system call.

---

### 1. Update the Kernel Code (`hello.bpf.c`)
We define the map using the `SEC(".maps")` macro.

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define a Hash Map: Key = PID (u32), Value = Counter (u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} exec_counts SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count, init_val = 1;

    // Look up the PID in our map
    count = bpf_map_lookup_elem(&exec_counts, &pid);
    if (count) {
        // If found, increment the counter
        __sync_fetch_and_add(count, 1);
    } else {
        // If not found, insert 1
        bpf_map_update_elem(&exec_counts, &pid, &init_val, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```



---

### 2. Update the Rust Loader (`main.rs`)
Because we are using `libbpf-cargo`, our generated skeleton now has a `maps` field. We can use this to poll the data from the kernel.

```rust
mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}

use hello::HelloSkelBuilder;
use std::time::Duration;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let builder = HelloSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Monitoring execve() calls... Press Ctrl+C to stop.");

    // Access the map via the skeleton
    let maps = skel.maps();
    let exec_counts = maps.exec_counts();

    loop {
        thread::sleep(Duration::from_secs(2));
        println!("--- Stats ---");

        // Iterate through all keys (PIDs) currently in the kernel map
        // Note: In a real app, you'd use a more efficient way to collect keys
        let mut key = [0u8; 4]; // u32 is 4 bytes
        let mut next_key = [0u8; 4];

        // This is a simplified logic for demonstration
        // libbpf-rs provides idiomatic iterators for maps
        for key_bytes in exec_counts.keys() {
            let mut val_bytes = [0u8; 8]; // u64 is 8 bytes
            if let Ok(Some(value)) = exec_counts.lookup(&key_bytes) {
                let pid = u32::from_ne_bytes(key_bytes.try_into().unwrap());
                let count = u64::from_ne_bytes(value.try_into().unwrap());
                println!("PID {}: {} executions", pid, count);
            }
        }
    }
}
```

---

### 3. How to Inspect the Map with `bpftool`
While your Rust program is running, you can "spy" on the data directly using `bpftool` without even stopping the app.

1.  **Find the map ID:**
    ```bash
    sudo bpftool map list
    ```
2.  **Dump the contents:**
    ```bash
    # Replace <ID> with the ID found in the previous step
    sudo bpftool map dump id <ID>
    ```



---

### Why this is powerful
By using a BPF Map, you've moved from just "printing logs" to **State Management**. 
* The **Kernel** does the heavy lifting: filtering, counting, and aggregating.
* The **Rust App** only wakes up occasionally to read the final results.

This is exactly how high-performance tools like **Cilium** (networking) or **Falco** (security) work. They perform millions of checks per second in the kernel and only send relevant summaries to the user-space application.


Next: Example explore how to send complex data (like full file paths or network headers) using `RingBuffer`, which is much faster than standard Maps for streaming events.

-------------------
# maps (ringbugger : example 2)

While **BPF Maps** are great for storing state (like counters), they aren't ideal for "streaming" events (like every time a file is opened). For high-performance logging, the **RingBuffer** is the modern standard. 

It is a specialized memory area where the kernel writes data into a circular buffer, and your Rust app "polls" that data. It is much faster and more memory-efficient than older methods like `PerfBuffer`.

---

### 1. Define the Data Structure
To send complex data, we first define a shared C struct. This struct must be exactly the same size in both C and Rust (we use `#[repr(C)]` in Rust for this).

**In `hello.bpf.c`:**
```c
struct event {
    int pid;
    char comm[16];    // Process name
    char filename[64]; // Filename being opened
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} rb SEC(".maps");
```

---

### 2. Kernel Side: Writing to the RingBuffer
When the event occurs, we "reserve" space in the buffer, fill it, and "submit" it.

```c
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // 1. Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    // 2. Fill the data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)ctx->args[1]);

    // 3. Submit to user-space
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```



---

### 3. Rust Side: Consuming the Events
In Rust, we set up a `RingBufferReceiver`. This is an event-driven loop that waits for the kernel to push data.

**In `main.rs`:**
```rust
use libbpf_rs::RingBufferBuilder;

// Define the same struct in Rust
#[repr(C)]
struct Event {
    pid: i32,
    comm: [u8; 16],
    filename: [u8; 64],
}

fn handle_event(data: &[u8]) -> i32 {
    let event = unsafe { &*(data.as_ptr() as *const Event) };
    let comm = std::str::from_utf8(&event.comm).unwrap_or("unknown");
    let file = std::str::from_utf8(&event.filename).unwrap_or("unknown");
    
    println!("PID: {} | Task: {} | Opened: {}", event.pid, comm.trim_matches('\0'), file.trim_matches('\0'));
    0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut skel = HelloSkelBuilder::default().open()?.load()?;
    skel.attach()?;

    // Set up the RingBuffer consumer
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(skel.maps().rb(), handle_event)?;
    let rb = rb_builder.build()?;

    println!("Streaming file opens... Press Ctrl+C");

    // Poll the buffer indefinitely
    loop {
        rb.poll(Duration::from_millis(100))?;
    }
}
```

---

### Why use RingBuffer over Maps?
1. **Low Overhead:** The kernel doesn't have to wait for the user-space app. It just drops the data in the buffer and moves on.
2. **Memory Ordering:** It guarantees that the user-space app sees the events in the exact order they happened in the kernel.
3. **Efficiency:** It uses "memory mapping" (`mmap`), so the data isn't actually copied between the kernel and user space; they both look at the same physical RAM.



---

### Summary of your eBPF Toolkit
| Tool | Best Use Case |
| :--- | :--- |
| **`bpf_printk`** | Quick & dirty debugging (like `printf`). |
| **Hash Maps** | Storing counters, flags, or configuration. |
| **RingBuffer** | High-speed streaming of events/logs to user-space. |

You now have a complete understanding of how to build, compile, load, and communicate with eBPF programs using Rust. 

Next: template `Cargo.toml` and directory structure so you can start your first real-world project 

---------------------

# example project: 

This is the "Full Package." To make a real-world project work, you need a specific directory layout so that `libbpf-cargo` knows where to find your C code and where to spit out the Rust skeleton.

### 1. The Directory Structure
The most common pattern is to keep your BPF C code in a dedicated `src/bpf` folder.

```text
my-ebpf-project/
├── Cargo.toml
├── build.rs              # The "Glue" that runs libbpf-cargo
├── src/
│   ├── main.rs           # Your Rust User-space logic
│   └── bpf/
│       ├── hello.bpf.c   # Your Kernel-space logic
│       └── headers/      # (Optional) Custom C headers
└── target/               # Generated skeletons end up here
```

---

### 2. The `Cargo.toml`
You need `libbpf-rs` for the runtime and `libbpf-cargo` for the build process.

```toml
[package]
name = "my-ebpf-project"
version = "0.1.0"
edition = "2021"

[dependencies]
# The runtime library
libbpf-rs = "0.23.2" 
# For handling C-style strings and memory
libc = "0.2"
# Useful for handling the RingBuffer loop
plain = "0.2" 

[build-dependencies]
# The tool that compiles C to BPF and generates Rust code
libbpf-cargo = "0.23.2"
```

---

### 3. The `build.rs` Template
This script runs **before** your Rust code compiles. It ensures your BPF bytecode is always up to date.

```rust
use std::env;
use std::path::PathBuf;
use libbpf_cargo::SkeletonBuilder;

fn main() {
    // 1. Where to put the generated Rust skeleton
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("hello.skel.rs");

    // 2. Compile C -> BPF and generate the Rust skeleton
    SkeletonBuilder::new()
        .source("src/bpf/hello.bpf.c")
        .debug(true) // Keeps debug symbols for easier troubleshooting
        .build_and_generate(&out)
        .unwrap();

    // 3. Tell Cargo to re-run this script if the C file changes
    println!("cargo:rerun-if-changed=src/bpf/hello.bpf.c");
}
```

---

### 4. Why use this specific setup?
By using `OUT_DIR` (a temporary folder managed by Cargo), you avoid cluttering your source tree with generated files. In your `main.rs`, you simply "reach into" that folder to find your code:

```rust
mod hello {
    // This macro points to the file created in build.rs
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}
```



---

### Final Checklist Before You Code
1.  **Install `clang`**: The BPF backend for Clang is required.
2.  **Install `libelf-dev` & `zlib1g-dev`**: These are headers required by `libbpf` to parse ELF files.
3.  **Kernel Headers**: Ensure you have `linux-headers-$(uname -r)` installed so your C code can find `<linux/bpf.h>`.
4.  **Root Access**: Remember, your finished binary must be run with `sudo`.

### Your Next Step
You are now ready to build. I recommend starting by copying the **RingBuffer** code we discussed earlier into this structure.


------

Next: Check the ./hello-bpf/ for more .
