# Rust-eBPF: Programming for next-generation Networking, Observability & Security and more.

**Overview:** 

Intent of the this repo is to use Rust for eBPF  to stream line Instrumentation without the C toolchain.
Rust based approach allows to implement Kernel logic with memory safety and zero-dependencies.

Repository explores **eBPF (extended Berkeley Packet Filter)** through the lens of **Rust**. 

Demonstrating on how to build production-grade, container-aware tooling for networking, security, and 
observability using the **Aya** framework and also explore other ways to write programs. 

Traditional eBPF development generally relies on C and LLVM dependencies at runtime.
This project leverages Rust to provide:

- **compile-time safety**, 
- **shared data structures**, and 
- **zero-dependency binaries** for modern Linux environments.

---

##  Why Rust?

As of 2026 Rust has become the preferred language for kernel-adjacent tooling:

* **Safety First:**
    - Linux kernel verifier is a strict gatekeeper. Is very picky with constrains.
    - Rust's Ownership model can catch many memory safety issues at compile-time, saving time that would
      otherwise cause the kernel verifier to reject your `eBPF` bytecode programs at runtime. 
    - Rust’s type system naturally mirrors the verifier's constraints, reducing "rejected program" iterations.

* **No Runtime Dependencies:** 
    - Using Rust **Aya** a framework of eBPF related crates, you can drop `libbcc` or `llvm` installed on
      your target production servers/system. 
    - You release/ship a single, static binary.
    - Easy to cross build to different targets.

* => **Aya Framework:** <=
    - No need to work with multiple languages to run/control/monitor eBPF programs, which is found with `C`
      or `libbpf` based tooling, Aya allows for a 100% Rust workflow. 

    - No dependency on **`libbcc`** or **`llvm`** on the target machine.
    - And its BTF aware.
    - Build / cross built once can run on different targets ( CO-RE )

* **Shared Codebase and binary layout:** 
    - You can define `struct` once (generally in a common crate) and use it in both kernel and user-space
      code. (Rust FFI bridges this with ease)
    - The common share can be used in eBPF kernel bytecode and the User-space CLI via `aya-log` ( data
      serialization).
    - Define a `#[repr(C)]` struct once. 
      Use it in both the kernel bytecode and the user-space agent. 
      Guarantees binary compatibility and eliminates the need for manual byte-shuffling or keeping fragile 
      C headers in sync.

* **Native Performance**: 
    - Rust give C-level execution speed.
    - Zero cost abstraction: Rust has no garbage collector or runtime overhead while interacting with kernel.
    - You avoid the "CGO tax" the cost of stack switching when moving data from the kernel map to your
      user-space logic.
    - Additionally it comes with powerful `cargo` tooling to handle  dependency management.

* **Async based data handling**:
    - Asynchronous executor crates: `Tokio`, `async-std`( replace with  `smol`) can be used to poll `eBPF`
      maps ( `RingBuf`, or `PerfEventArray`) without blocking main thread.
    - Async approach allows single user-space daemon/program to handle millions of events per second for
      multiple hooks across different containers with minimal CPU jitter. 

Source folder has examples that cover different use-case's.
Documents folder contains concepts and how to implement using Rust.


Existing Tools vs. This repo:

| Feature | BCC / libbpf (C) | This Project (Rust/Aya) |
| --- | --- | --- |
| **Development** | Manual C headers / Python wrappers | Pure Rust |
| **Safety** | Runtime Verifier checks only | Compile-time + Runtime checks |
| **Portability** | Requires `clang`/`llvm` on host | Single static binary |
| **Container Awareness** | Manual PID filtering | Native cgroup-v2 integration |

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
* **eBPF on Windows:** Investigating the portability of Rust-based eBPF logic to non-Linux kernels.

---

## Installation 

1. Install the Rust toolchain: `rustup toolchain install nightly`.
2. Install `bpf-linker`: `cargo install bpf-linker`.
3. Install `cargo-generate` if intend to use remote source template. 
4. Other tools bpftool, clang, llvm, cross-toolchains and rustup related target compiler targers

---

