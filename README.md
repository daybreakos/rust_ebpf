## Rust-eBPF: 

### Programming for next-generation Networking, Observability & Security and more.

**Rust-eBPF: A modern Kernel instrumentation using Rust and the eBPF ecosystem**


Explore a new modern kernel eBPF instrumentation using Rust and its growing ecosystem of crates, which
offer significant advantages over traditional C-based eBPF development. 

Rust offers production-oriented eBPF development using Aya framework and its ecosystem of
crates, which can be used to build maintainable, portable kernel instrumentation without traditional
C-centric eBPF toolchain. 

The [programs](./progs/) folder contains demo applications that highlight how to build production-grade,
container-aware observability and security tooling while avoiding the complexities of the traditional C
toolchain and runtime dependencies. 

**Why?** 

eBPF development often depends on a stack that includes C/Clang/LLVM, kernel headers or source tree, and
additionally language runtimes require python, Go.. for loading and interacting with eBPF programs. 

This can introduce :

    - Development and iteration speed,
    - cross-platform development, 
    - rebuild for different kernel versions and machines
    - dependencies and toolchain management. 

Plus the language used to load and interact with eBPF programs (C,Py,Go,..) can fall short on  safety,
performance or operational complexity. 

**Rust?**

Rust provides powerful, safety first approach, when combined with eBPF crates (Aya framework of crates)
we get many advantages:

- Provides a powerful approach to build production grade eBPF applications, borrows the goodies from Rust, offering memory safety, zero-runtime dependencies, developer friendly workflow. 

- Ownership model and compile time checks, prevents many common classes of bugs found in C-based eBPF
programs (invalid memory access, data races ).

- Rust's type systems, Ownership model, and bounds checking can reduce bugs that commonly cause kernel
verifier rejection. 
    - Aya's Rust abstraction is focused towards verifier-friendly patterns. 

---
    Note: Rust does not replace the Linux eBPF verifier, but its compile-time guarantees and Aya,s
    restricted programming model significantly reduces, unsafe behaviour which generally leads 
    to verification rejection. Improving correctness and developer productivity. 
---

- Applications developed this way produce self contained binaries that do not require LLVM, Clang, or BCC
  at runtime, and still supporting true CO-RE, which makes it a right tool for large servers to resource
  constrained embedded systems. 

---
    Note: BTF supported kernel is required for true CO-RE.
--- 

- Memory Safe: Prevents common pitfalls that are associated with C-based eBPF programming. 

- zero-dependency: Produces self-contained binaries that do not require LLVM or BCC at runtime, it also
generates true CO-RE. 

- Developer Centric: development uses a shared Rust data structures between the kernel and user-space for
  seamless communication ( similar with RPC common code that gets shared with two worlds ).

---
**Key Features**:

- **Safety First:**
    - Kernel's eBPF verifier is a strict gatekeeper. It's very picky with constrains.
    - Rust's Ownership model can catch many memory safety issues at compile-time, saving time that would
      otherwise cause the kernel verifier to reject your `eBPF` bytecode programs at runtime. 
    - Rust’s type system naturally mirrors the verifier's constraints, reducing "rejected program" iterations.

- **No Runtime Dependencies:** 
    - Using Rust **Aya** a framework of eBPF related crates, you can drop `libbcc` or `llvm` installed on
      your target production servers/system. 
    - You release/ship a single, static binary.
    - Easy to cross build to different targets.

- => **Aya Framework:** <=
    - `libbpf` based tooling require C,C++,Go,python, multiple languages to run/control/monitor eBPF programs, Aya allows for a 100% Rust workflow. 
    - No dependency on **`libbcc`** or **`llvm`** on the target machine.
    - BTF aware.
    - Build / cross built once can run on different targets ( CO-RE )

- **Shared Codebase and binary layout:** 
    - You can define `struct` once (generally in a common crate) and use it in both kernel and user-space
      code. (Rust FFI bridges this with ease)
    - The common share can be used in eBPF kernel bytecode and the User-space CLI via `aya-log` ( data
      serialization).
    - Define a `#[repr(C)]` struct once. 
      Use it in both the kernel bytecode and the user-space agent. 
      Guarantees binary compatibility and eliminates the need for manual byte-shuffling or keeping fragile 
      C headers in sync.

- **Native Performance**: 
    - Rust give C-level execution speed.
    - Zero cost abstraction: Rust has no garbage collector or runtime overhead while interacting with kernel.
    - You avoid the "CGO tax" the cost of stack switching when moving data from the kernel map to your
      user-space logic.
    - Additionally it comes with powerful `cargo` tooling to handle  dependency management.

- **Async based data handling**:
    - Asynchronous executor crates: `Tokio`, `async-std`( replace with  `smol`) can be used to poll `eBPF`
      maps ( `RingBuf`, or `PerfEventArray`) without blocking main thread.
    - Async approach allows single user-space daemon/program to handle millions of events per second for
      multiple hooks across different containers with minimal CPU jitter. 

- **High-Throughput Performance (Packet/Event Analytics)**
    - Rust compiled binaries run with performance *equal to or better than C*. Providing zero-cost
      abstractions for low-latency works.
    - Attaching eBPF programs to XDP or TC can pushing millions of events per second into
      `RingBuffer` maps. 
    - Using async eco-system (`Tokio`) and parallel processing (Rayon) crates to drain and analyze kernel buffers with minimal latency.

- And more... 

---

Typical Rust - Aya based repository structure:

```text
├── ebpf/               # Kernel-space Rust code (compiled to bpfel-unknown-none)
├── common/             # Shared data structures (structs, constants)
├── user-space/         # Rust CLI to load, attach, and log eBPF data
└── xtask/              # Build automation and management

```

This project also explores:

* **BTF (BPF Type Format):** Ensuring "Compile Once – Run Everywhere" (CO-RE) portability.
* **Async/Await in User-space:** Utilizing `Tokio` to process high-throughput event streams from eBPF maps.

---

#### pre-requisites

1. Install the Rust toolchain: `rustup toolchain install nightly`.
2. Install `bpf-linker`: `cargo install bpf-linker`.
3. Install `cargo-generate` if intend to use remote source template. 
4. Other tools bpftool, clang, llvm, cross-toolchains and rustup related target compiler targets

---

