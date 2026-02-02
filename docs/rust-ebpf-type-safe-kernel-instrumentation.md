# rust-eBPF-type-safe-instrumentation

1. Shift to Rust-eBPF:

- Move away from c/clang toolchain.

2. Develop dependency free framework for deployment:

- Move away from multiple programming languages to deploy/interact with eBPF programs. 
- Move away from `libbpf`, python.
- Single binary deployment. 
- CO-RE 

The traditional approach for writing eBPF programs require: `libbpf`, `clang` and `llvm` headers  on the
target system to compile or load. 
With Rust (Using Aya framework of crates) results in binary is a fat "ELF" file containing the bytecode, and
the user space application does not require to link against `libbpf.so` or have a C compiler installed on
the production server. 



3. Type-safety: 

- Shared crates: use same structs in kernel and user-space.
- Enums vs magic numbers.

`eBPF` bytecode is just assembly instructions and kernel executes, Rust provide a clean way to arrive at
those instructions. 

Typical eBPF development challenge is ensure kernel and use-userspace agree on data structures. 

In traditional `C` way: You define a `struct` in a header file. You need to ensure your `C` compiler (for
kernel) and user-space (Go, C++, Python ) interpret padding, alignment, and member sizes to be identical.
Any mismatch will give you garbage data or crash. 

With Rust way: You define `struct` in shared Rust crate, Both kernel probe and user-space daemon import the
exact same `struct`. If you change a field from `u32` to `u64` both side fail to compile until the types
match. This type-safety is achieved across boundaries. 

Kernel programming is notorious for void * pointers, essentially "here is a memory address, good luck." 
In Rust-eBPF (Aya), we use *Attributes* and *Generics* to give those pointers meaning:

- Maps: Instead of a generic "lookup" that returns a raw pointer, Aya uses Map<Key, Value>. 
  When you pull data from a map, the compiler knows exactly what type it is.

- Context: When a probe triggers (ex: a `Kprobe`), the context is passed as a typed argument 
  (like ProbeContext). You aren't just looking at a register; you are looking at a structured object.

Enum Safety and Match Arms: kernel uses many "magic numbers" (constants) to represent states or error codes. 

- In `C` you use `#define` or `ints`, its easy to pass the wrong integer to the wrong function.

- In Rus we use `Enums` The compiler ensures you’ve handled all possible states (exhaustiveness checking). 
  This prevents the "forgotten edge case" that often leads to security vulnerabilities.

"Type-Safe Systems Programming in Rust-eBPF eliminates the 'semantic gap' between the kernel and userspace
by enforcing shared data contracts and preventing logic errors through Rust’s expressive type system."

4. Memory safety in Unsafe world: 

- Kernel eBPF verifier 
- Using Rust to wrap `unsafe` kernel pointer into safe abstractions.

Kernel verifier makes sure `eBPF` programs written in C or Rust cannot crash the kernel.
The verifier performs a static analysis to ensure:
* No Infinite loops.
* No out-of-bounds memory access.
* No reading uninitialized memory. 

In `C` entire eBPF program is effectively "unsafe". With Rust ( using Aya Framework of crates ), the
`unsafe` is generally reserved for the "boundary" where the program interact with raw kernel memory or
pointers provided by the *context*.

Aya also provides safe, idiomatic wrappers around `eBPF` *maps* and *helpers*.  Once data is pulled out of
`unsafe` that from a raw pointer, you can process that data using safe Rust.

Rust's borrow checker still operates on the logic around the unsafe blocks. Preventing data races in
user-space and ensures that you are not mismanaging references to the date you have captured. 

"Rust-eBPF provides memory safety by encapsulating the inherently unsafe kernel interactions within a
type-safe framework, allowing the majority of the logic to be verified by the Rust compiler before the 
Verifier even sees it."

NOTE: In this case Rust dont not make the kernel safe, it makes the implementation of kernel logic
significantly less likely to trigger a verifier rejection or a logic bomb/bug.


5. 
    

