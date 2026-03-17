# eBPF programming with Rust:

## eBPF VM:

- The `eBPF` VM is a sandboxed runtime embedded within the Linux kernel. It bridges the gap between "fast
  but risky" kernel modules and "safe and slow" user-space programs. 

  Since the programs run inside the kernel space they have many restrictions to ensure it cannot crash the
  OS or leak sensitive data. 

- `eBPF` VM operates like a "Universal RISC" processor in SW, providing standard environment for code to
  execute regardless of the underlying hardware (x86, ARM, etc..)

### Execution Model:

* **Registers:** 
    - `eBPF` VM provides **11 64-bit registers** ( $R0$ through $R10$ ) 

* **$R0$:** 
    - Return value for helper functions and the program's exit code.

* **$R1$ - $R5$:** 
    - Arguments for calling kernel helper functions.

* **$R6$ - $R9$:** 
    - Callee-saved registers ( data survives function calls )

* **$R10$:** 
    - Read-only frame pointer for the stack.

### Programs:

* **JIT Compilation:** 
    - `eBPF` programs are written in bytecode, the kernel uses a **JIT compiler** to turn that bytecode into
      native machine instructions for near-zero execution overhead.

* **Helper Functions:** 
    `eBPF` programs cannot call arbitrary kernel functions. Instead, they call a stable API of "Helpers" to
    perform tasks like:
    - Reading/writing data to eBPF maps.
    - Accessing process context (PID, UID, cgroups).
    - Modifying network packets or performing redirects.
    - Printing debug messages.


### Maps:

* **eBPF Maps:** 
    - Since `eBPF` programs are stateless and run-to-completion, the VM uses "Maps" (Hash tables, Arrays,
      Ring buffers) to store data across multiple runs or share data with user-space.

### Memory and Storage Limits:

* **Stack Limit:**
    You get only 512 bytes of stack memory. This is small and cannot allocate large structures or string on
    the stack, for larger storage needs they should be stored in Maps.

* **Locked Memory:** 
    - `eBPF` programs use **Locked memory** ( non-swappable ). The system enforces a `MEMLOCK` limit,
      meaning you can't create infinitely large maps that starve the rest of the kernel. 

* **Bounded Loops:** 
    - For earlier kernel versions that supported `eBPF` loops were forbidden.
    - New kernel versions allow loops in code only if the Kernel Verifier can prove they have an exit
      condition and will terminate quickly. 

### Verification & Compilation:

* **Instruction limit:**
    - Most kernels limit a single program to **1 million instructions**. This prevents a `eBPF` program from
      hogging the CPU forever.

* **Complex Analysis:**
    - The Verifier performs a "symbolic execution" of every possible branch in your code. 
    - If the code is too "spaghetti-like" and has too many paths (state explosion), the Verifier will reject
      it as too complex to prove safe.

* **Memory Safe:**
    - You cannot perform arbitrary pointer arithmetic. 
    - If you have a pointer to a packet, you must check its length `if (data + 10 > data_end) return;`)
      before reading the *10th* byte.


### Calling Limitations:

* **No Blocking:** 
    - eBPF programs must be "run-to-completion." 
    - They cannot sleep, block for I/O, or wait for a mutex.

* **Tail Calls:** 
    - To get around the instruction limit, you can "Tail Call" another `eBPF` program, but you are limited
      to **33 consecutive calls** to prevent infinite recursion.

* **Function Arguments:** 
    - Helper functions are restricted to a maximum of **5 arguments**.


### Summary Table

| Feature | Limit / Capability | Why? |
| --- | --- | --- |
| **Stack Size** | 512 Bytes | Prevents stack overflows and kernel crashes. |
| **Registers** | 10 General Purpose | Efficient mapping to physical CPU registers. |
| **Max Instructions** | ~1 Million | Prevents CPU starvation (infinite loops). |
| **Maps** | 64 per program | Prevents excessive memory consumption. |
| **Concurrency** | No Blocking/Sleeping | Ensures the kernel thread remains responsive. |
| **Memory Access** | Strictly Verified | Prevents reading/writing outside allowed bounds. |

---

## Advanced / New topics in modern `eBPF` stack:

The below items are a shift from `eBPF` being a simple packet filter to becoming a fully-fledged kernel
extension framework.

Covering these advanced concepts would give us a complete the picture of the `eBPF` VM’s lifecycle and 
capabilities:

### 1. Safety & Extensions (KFuncs, Dynamic Pointers, Tokens)

While **Helpers** are the stable, legacy API, these features represent the "new way" the VM interacts with 
the kernel.

* **KFuncs (Kernel Functions):** 
    - KFuncs are special kernel functions that the kernel explicitly exposed for eBPF programs:
        ex: task helper, networking helpers, scheduler helpers.
        These are desribed in BTF Metadata.
    - Unlike Helpers, which require a stable UAPI (and thus take years to change), KFuncs allow eBPF to call
      specific kernel functions directly. 
    - KFuncs are often unstable/version-specific but much more powerful.
    - Officially KFuncs are unstable, unlike helper functions, kfuncs have no UAPI guarantees. In practice
      this might mean that `kfuncs` can change or be removed between kernel versions. 
    - Though as with all features, the kernel community will try to avoid breaking changes, and will provide
      desprecation warnings when possible. Users of kfuncs might need to be more vigilant about changes in
      the kernel, and be prepared to update their programs more frequently or write more complex code to 
      handle different kernel versions.

* **Dynamic Pointers (`bpf_dynptr`):** 
    - Remember that 512-byte stack limit? Dynamic pointers allow the VM to safely handle variable-sized
      memory regions (like large buffers or nested structures) without hitting the Verifier's strict 
      "static size" checks.

* **eBPF Tokens:** 
    - A security feature that allows fine-grained delegation of eBPF privileges. 
    - Instead of requiring "Global CAP_SYS_ADMIN," a container can be granted a "Token" to perform specific
      eBPF tasks (like loading a firewall) without full root access.

---

### 2. Program Lifecycle & Persistence (Pinning, Trampolines)

How does a program survive when the loading process exits, and how does it "hook" into the kernel?

* **Pinning:** 
    - By default, when the user-space process that loaded the eBPF program closes, the program and its maps
      are deleted. **Pinning** creates a file in the `bpffs` (BPF File System, usually at `/sys/fs/bpf`) to
      keep them alive and accessible to other processes.

* **Trampolines (fentry/fexit):** 
    - This is the "glue" that lets `eBPF` programs jump into kernel functions with almost zero overhead.
      It's a specialized piece of generated code that allows the VM to hook into the entry or exit of 
      nearly any kernel function without using the slower `kprobes`.

### 3. High-Performance Data & Events (AF_XDP, USDT, Timers)

These tools handle how data enters and leaves the VM environment.

* **AF_XDP:**
    - *AF_XDP* is the "express lane." 
    - It allows you to redirect network packets directly from the network driver into user-space memory,
      bypassing the entire Linux networking stack. 
    - The eBPF VM acts as the "traffic cop" deciding which packets get fast-tracked.

* **Timers:** 
    - Modern eBPF allows you to schedule a function to run in the future. 
    - This is critical for tasks like rate-limiting or cleanup jobs that need to happen without a 
      specific event (like a packet arriving) triggering them.

* **USDT (User-level Statically Defined Tracing):** 
    - While `kprobes` look at the kernel, USDT allows `eBPF` to hook into "tracepoints" baked into 
      user-space apps (like MySQL or Node.js). It’s how the VM bridges the gap between kernel visibility 
      app-level logic.

### 4. Execution Integrity (Concurrency Control)

* **Concurrency (`bpf_spin_lock`):** 
    - Because `eBPF` programs can run on multiple CPU cores simultaneously, they can face race conditions
      when updating the same Map entry. 
    - The VM provides specialized **Spinlocks** and **Atomic operations** to ensure data integrity without
      causing kernel deadlocks.

### Summary of Advanced VM Features

| Feature | Primary Purpose | Impact on Program |
| --- | --- | --- |
| **KFuncs** | Flexible Kernel API | Faster access to new kernel features. |
| **Pinning** | Persistence | Maps/Programs stay alive after process exit. |
| **AF_XDP** | Extreme Networking | Moves packet processing to user-space. |
| **Trampolines** | High-perf Tracing | Replaces kprobes for lower overhead. |
| **Tokens** | Security | Allows non-root users to use eBPF safely. |


## Compilation Flow:

To turn your code into eBPF bytecode, the toolchain must bridge the gap between high-level logic (C or Rust)
and the strict, instruction-based environment of the `eBPF` VM.

While **Clang/LLVM** is the industry standard (used by `libbpf`), **Rust** (via the **Aya** framework) has
become a powerful alternative by allowing "Pure Rust" from kernel to user-space.

---

### 1. The Compilation Flow

Both tool-chains the source code and lower it into **LLVM IR** (Intermediate Representation) before a
specialized *BPF* back-end emits the final bytecode.

#### Clang/LLVM (The "Standard" Way)

1. **Source:** 
    - Is written in restricted C.
2. **Frontend:** 
    - `clang` compiles the C into LLVM IR.
3. **Backend:** 
    - The LLVM BPF backend transforms IR into an **ELF object file** containing eBPF bytecode instructions.
4. **Linking:** 
    - Typically, no "linking" is done in the traditional sense until `libbpf` loads the ELF and performs
      **CO-RE**.

#### Rust / Aya (The "Modern" Way)

1. **Source:** 
    - Code is written in `no_std` Rust.
2. **Frontend:** 
    - `rustc` compiles Rust into LLVM IR.
3. **Linker:** 
    - Since Rust's standard linker doesn't understand *BPF*, you use **`bpf-linker`**. 
    - **`bpf-linker`** performs static linking and optimizations (like dead code elimination) specifically
      for the `eBPF` VM.
4. **Result:** 
    - An *ELF* file, much like the Clang output, but often with more safety metadata baked in.


### 2. Advanced Concepts: Clang vs. Rust Comparison

| Topic | Clang/LLVM (`libbpf`) Implementation | Rust (`Aya`) Implementation |
| --- | --- | --- |
| **Concurrency** | Uses `bpf_spin_lock` helpers. Requires manual care to avoid verifier errors. | Wrapped in safe abstractions. Rust’s `Send`/`Sync` traits help prevent data races at compile time. |
| **Pinning** | Managed via `bpf_obj_pin()` helper or by defining map attributes in C sections. | Accomplished using the `Map::pin` method in the userspace loader or via declarative macros. |
| **Timers** | Uses `bpf_timer_init` and `bpf_timer_set_callback` helpers. | Exposed via the `bpf-helpers` crate with more idiomatic "callback" registration. |
| **AF_XDP** | Relies on `libxdp` (a C library) to manage the UMEM and zero-copy rings. | Managed via the `aya-obj` and specialized AF_XDP crates that handle the ring buffers natively. |
| **KFuncs** | Declared as `extern` functions with the `__ksym` attribute in C. | Declared using `extern "C"` blocks with specialized attributes provided by `aya-ebpf`. |
| **Dynamic Pointers** | Uses the `struct bpf_dynptr` type and associated kernel helpers (`bpf_dynptr_from_mem`). | Mapped to `&[u8]` (slices) or specific `DynPtr` types that leverage Rust's slice safety. |
| **eBPF Tokens** | Handled during the load phase by passing a token FD to the `bpf()` syscall. | Supported in the `Aya` loader by attaching tokens to the `BpfLoader` configuration. |
| **Trampolines** | Linked via `SEC("fentry/...")` macros that the loader resolves to kernel symbols. | Supported via the `#[fentry]` or `#[fexit]` macros in the kernel-space crate. |
| **USDT** | Requires `libbpf` to parse the ELF notes of the target binary to find trigger points. | `Aya` provides built-in support to discover and attach to USDT probes in running processes. |

---

### 3. The "Gotcha": CO-RE (Compile Once – Run Everywhere)

This is the most critical part of the modern tool-chain. 
Because kernel structures change (e.g., a field in `task_struct` moves from offset 16 to 24), the compiler
generates **relocation records**.

* **Clang/LLVM:** 
    - Generates `.BTF` (BPF Type Format) sections in the ELF file. 
      `libbpf` reads this at load-time and "patches" the bytecode offsets to match the *current* kernel.

* **Rust/Aya:** 
    - Historically, this was hard for Rust because it required specialized LLVM features. 
    - Today, `bpf-linker` and `Aya` support CO-RE by generating the same BTF relocation info, allowing Rust
      `eBPF` programs to be portable across different kernel versions.

---

# eBPF program types

- eBPF programs get run when a event is triggered and each specific use case corresponds to different
  program type: These types define where the program can attach in the kernel, what context it operated
  within and which helper functions it can use. 

- i.e `eBPF` program types essentially define 2 things:

    1. **The Hook**: What specific event in the kernel triggers your code ( a pkt arrival, a function call,
       a process starting ...)
    2. **The Context**: What data your program is allowed to see and modify. Ex: `XDP` programs can see raw
       packet buffers, while `kprobe` see CPU registers and function arguments.

## Categorizing the List:

To make your mental map even clearer, you can group the types you mentioned into three "functional buckets":

#### 1. Networking (Packet & Socket level)
These are for filtering, routing, or modifying data as it moves through the network stack.

* **XDP:** 
    - The "fast path" at the driver level.

* **socket_filters:** 
    - Classic filtering (like `tcpdump`).

* **sock_ops / cgroup_skb:** 
    - Managing traffic specifically for containers or specific sockets.

#### 2. Observability & Tracing (System level)
These are for seeing what the OS and applications are doing without changing their behavior.

* **Kprobe / Kretprobe:** 
    - Dynamic hooks into any kernel function.

* **Uprobe / Uretprobe:** 
    - Dynamic hooks into userspace libraries (like OpenSSL or libc).

* **Tracepoints:** 
    - Static, stable hooks baked into the kernel source.

#### 3. Security & Policy (Control level)
These are for enforcing rules and "saying no" to certain actions.

* **LSM (Linux Security Module):** 
    - The newest powerhouse. 
    - It lets you write `eBPF` programs that act as a security policy (ex "This process cannot touch this
      specific file").

* **cgroup_sockopt:** 
    - Controlling what socket options (like `timeouts` or buffers) a specific container is allowed to set.

---

# `bindgen` 

`bindgen` is a tool used mainly to automatically generate Rust bindings for *C* and *C++* libraries. 
In short it helps Rust code call functions and use types defined in *C/C++* headers without writing all the
interface code. 

In case of `eBPF` its a crucial bridge that allows Rust to talk to the Linux Kernel (which is in "C").

Because the `eBPF` ecosystem is rooted in C ( kernels language ) `bindgen` is the translator that makes
modern `eBPF` development in Rust possible.

## Transforms c -> Rust

- For a given *C/C++* library with header files like: in file example.h => `int add(int a, int b)` bindgen
  reads this header file and generates Rust code like:
  ```Rust 
    extern "C" {
        pub fn add( a: ::std::os::raw::c_int, b: ::std::os::raw::c_int) -> ::std::os::raw::c_int;
    }
  ```
  This allows Rust code call call the "C" function directly.

  Example: 
  - atoms.h:
  ```c 
  typedef struct Element {
    int protons;
    int neutrons;
  } Element;
  void periodic_classification(Element* element);
  ```
  `bindgen` produces Rust FFI code allowing you to call into the `atoms` library functions and use its
  types:
  ```rust 
    /* automatically generated by rust-bindgen 0.72.1  */ 
    #[repr(C)]
    pub struct Element {
        pub protons: ::std::os::raw::c_int;
        pub neutrons: ::std::os::raw::c_int;
    }
    
    extern "C" {
        pub fn periodic_classification(element: *mut element);
    }
  ```
  - `#[repr(C)]`: This tells Rust compiler to layout the data in memory **exactly like C** does, rather then
    using Rust's default(which is often different) memory optimization.
  - Types: It maps `unsigned char` to `u8` and `__be16` ( big-endian 16-bit ) to `u16`.
  - `bindgen`: automatically adds `Copy` and `Clone` because simple C structs are plain old data.

  ## Linux Kernel:

- All data structures and its helper functions in the Linux Kernel are defined in "C". When writing eBPF
  programs in Rust we need to use crates like **Aya** or **libbpf-rs**, and Rust code need to know exactly
  how those *C* structures are laid out in memory. 

  - Manual recreating this structures in Rust is Error prone, and Unmaintainable. 

- Building eBPF code via Aya in Rust, `bindgen` typically runs during compilation phase. 
  1. It takes kernels C header ( often provided by `vmlinux.h` )
  2. It parses the C code to understand types, enums and structs.
  3. It produces a `.rs` file containing equivalent Rust code, usually wrapped in **`unsafe`** block
     allowing you to use kernel types directly in your Rust based eBPF programs.
  4. Rust code calls them through FFI.

- `bindgen` relies on *Clang* ( via `libclang` ) to parse C/C++ headers correctly.

- Typical usage in a Rust project:

```rust 
    let bindings = bindgen::Builder::default()
                    .header("wrapper.h")
                    .generate()
                    .expect("Unable to write bindngs!!!");
    bindings
        .write_to_file("src/bindings.rs")
        .expect("could'nt Write Bindings!!! ");
```
- use bindgen to generate entire kernel's internal data structs ( using BTF info )
    1. First we require vmlinux.h, File that contains every type definition used in the running kernel for
       which we use `btftool`

       ```bash  
       bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
       ```
    2. Now use `bindgen` on "vmlinux.h" file to generate rust bindings:
        ```bash  
        bindgen vmlinux.h \
            -o vmlinux.rs \
            --ctypes-prefix "core::ffi" \
            --use-core \
            -- \
            -target x86_64-unknown-linux-gnu

        ```

    3. Automate this with build.rs:
    ```rust 
    // build.rs
    use std::env;
    use std::path::PathBuf;
    fn main() {
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    
        bindgen::Builder::default()
            .header("vmlinux.h")
            .use_core()
            .ctypes_prefix("core::ffi")
            .no_copy(".*") // Large kernel structs should stay as references
            .layout_tests(false)
            // Networking specific optimization: only generate what you need
            // .allowlist_type("task_struct")
            // .allowlist_type("sk_buff") 
            .generate()
            .expect("Unable to generate vmlinux bindings")
            .write_to_file(out_path.join("vmlinux.rs"))
            .expect("Couldn't write bindings!");
    }
    ```
    4. the above automation generates a big file and if we want to reduce the scope to say "sk_buff".
        - You can add `.allowlist_type("sk_buff)` , `.allowlist_type("ethhdr)`

    5. NOTE: Make sure to use the correct target if you are using aarch64 add:
        `.clang_arg("-target").clang_arg("aarch64-linux-gnu")`

- Aya example:
    ```rust 
        let eth = unsafe { *ptr_to_packet_start as ethhdr };
        if eth.h_proto == 0x0800 {
            // This is IPv4 Packet.
        }
    ```
    Without `bindgen` you have to manually count bytes ( ex: protocol ID start at the 12th byte )... which
    are generally source of bugs. 

- Aya 0.13.x uses build.rs setup:
    - Instead of using bindgen in the terminal, you can use a `build.rs` script. This is a special file that
      Cargo runs before compiling your main code. 
      That is `build.rs` acts like a preprocessor that parses the bridge  between C and Rust.


    - `build.rs` Setup:
        * First add `bindgen` to `Cargo.toml` build dependencies:
        ```toml 
            [build-dependencies]
            bindgen = { workspace = true, default-features = true }
        ```
        * Next :
        ```rust 
        use std::env;
        use std::path::PathBuf;

        fn main() {
            // 1. Tell Cargo to rebuild its header changes 
            println!("cargo:rerun-if-changed=wrapper.h");

            // 2. Configure bindgen 
            let bindings = bindgen::Builder::default()
                // C header that we want to Rustify: 
                .header("wrapper.h")
                // Specific for eBPF: ensure we use the right clang arguments 
                .clag_arg("-I/usr/include")
                // Generate the bindings 
                .generate()
                .expect("Unable to generate bindings");

            // Write the binginds to $OUT_DIR/bindings.rs file 
            let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
            bindings 
                .write_to_file(out_path.join("bindings.rs"))
                .expect("Could not write bindings !");
        }
        ```
    - Wrapper header (`wrapper.h`)
        You keep a simple C file that includes exactly what you need from the kernel. This keeps your Rust
        env clean. 
        ```c 
        // wrapper.h 
        #include <linux/if_ether.h>
        #include <linux/ip.h>
        #include <linux/in.h>
        ```
    - Include it in your Rust code: 
        Once the build script runs, the generated code lives in a temporary folder, To use it in eBPF
        program you pull it like this:
        ```rust 
            #![allow(non_upper_case_globals)]
            #![allow(non_camel_case_types)]
            #![allow(non_snake_case)]

            // This macro includes the file generated by build.rs 
            include!(concat!(env!("OUT_DIR"), "/bindings.rs"))

            // Now On you can use `iphdr` .. etc as native Rust types!
        ```

- This above approach is version sync: i.e if you update kernel headers and re-compile, Rust types update
  automatically.

- No manual work: we never have to type `pub struc ...` for kernel types again. 

- CI/CD friendly: Your build pipeline will always generate the correct bindings for the target environment.


## Aya (0.10.+ ) handles this differently : using build.rs 

- `bindgen` is the standard tool for connecting Rust to C headers, `Aya` framework often takes a more
  Rust-native approach:

  Earlier version and when working with `libbpf-rs` you will need `clang` installed on the system to parse
  the headers. 

  Aya allows to skip clang dependency by using **BTF** data directly from your kernel. 

- Aya difference: `aya-tool` vs `bindgen`

    * Instead of `bindgen` Aya developers often use `aya-tool`. This tool does not looks at `.h` files, but
      it looks at `/sys/kernel/btf/vmlinux` which is the binary representation of every type in the running
      kernel. 

    * How the workflow changes:
      1. No header files: ( you dont have to manage C header files on your system )
      2. No Clang dependency 
      3. CLI generation: You run a command to generate your Rust module directly:

      ```bash 
      # generate Rust bindings for `task_struct` direcrlt from kernel's BTF :
      aya-tool generate task_struct > my_proj-ebpf/src/vmlinux.rs
      ```

## CO-RE: 

- Big reason for `bindgen` or `aya-tool` are so powerful is `eBPF`is a feature called CO-RE. 
    * If a offset of a field in a struct is changed from say 16 to 20 , the eBPF program would break.
    * With `bindgen` + CO-RE:
        - `bindgen` tags the generated Rust struct with metadata 
        - When the program loads the `eBPF Loader` ( Aya or libbpf ) checks the actual kernel it's running
          on.
          - If the field moved the loader **rewrites your code on the fly** to use the new offset.

- `bindgen` workflow:
    ```bash 
        C header files
              ↓
        Clang AST parsing
              ↓
        Rust FFI bindings
              ↓
        Rust program calls C library
    ```

- `aya-tool` workflow:
    ```bash 
        Running Linux kernel
                ↓
        /sys/kernel/btf/vmlinux
                ↓
        BTF type extraction
                ↓
        Rust struct definitions
                ↓
        Rust eBPF program
    ```

- Differences between `bindgen` vs `aya-tool`
    Unline `bindgen` **BTF** usually contains:
    - `struct` definitions
    - `enums`
    - `typedefs`
    - `field offsets`
    It does not expose callable kernel function interface for `eBPF`.
    eBPF progrtams instead use:
        - Kprobe -> attach to kernel function 
        - tracepoint -> stable tracing events. 
        ...

    => so with aya-tool you genearte **data structures**, then attach to kernel functions using probes. 


