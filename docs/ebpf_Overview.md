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
    - A security feature that allows fine-grained delegation of eBPF privileges. Instead of requiring "Global CAP_SYS_ADMIN," a container can be granted a "Token" to perform specific eBPF tasks (like loading a firewall) without full root access.

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


