# Hook Execution Internals:


## What are hook points and program types:

In eBPF, **hook types** and **program types** are related but different concepts:

- **Hook type** = *where/when* your eBPF code runs in the kernel.
- **Program type** = *what execution model and verifier rules* the kernel applies to your eBPF program.

A useful mental model:

> Hook = attachment point
> Program type = ABI + capabilities + context structure

### 1. Hook Types

Hook types describe the **event source** or **kernel integration point**.

Examples:

| Hook Type        | Meaning                                 |
| ---------------- | --------------------------------------- |
| `kprobe`         | Attach to a kernel function entry       |
| `kretprobe`      | Attach to a kernel function return      |
| `tracepoint`     | Attach to static kernel trace events    |
| `raw_tracepoint` | Lower-level tracepoint interface        |
| `tp_btf`         | BTF-enabled typed tracepoint attachment |
| `XDP`            | Attach to NIC RX path very early        |
| `tc`             | Traffic control ingress/egress          |
| `LSM`            | Linux Security Module hooks             |
| `uprobes`        | User-space function entry               |
| `uretprobes`     | User-space function return              |
| `perf_event`     | PMU / performance monitoring events     |
| `cgroup hooks`   | Network/syscall/resource control hooks  |
| `fentry/fexit`   | BTF-based function entry/exit tracing   |

These answer:

> “What kernel/user-space event triggers this eBPF program?”

---

### 2. Program Types

Program types are kernel-defined enums like:

```c
enum bpf_prog_type {
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_LSM,
    ...
};
```

Program type determines:

* verifier behavior
* allowed helper functions
* context struct
* return value semantics
* attach API
* execution constraints

Examples:

| Program Type                  | Typical Context         |
| ----------------------------- | ----------------------- |
| `BPF_PROG_TYPE_KPROBE`        | `struct pt_regs *`      |
| `BPF_PROG_TYPE_TRACEPOINT`    | tracepoint event struct |
| `BPF_PROG_TYPE_XDP`           | `struct xdp_md *`       |
| `BPF_PROG_TYPE_SCHED_CLS`     | `struct __sk_buff *`    |
| `BPF_PROG_TYPE_LSM`           | typed LSM args          |
| `BPF_PROG_TYPE_SOCKET_FILTER` | packet buffer           |
| `BPF_PROG_TYPE_CGROUP_SKB`    | cgroup skb context      |

This answers:

> “How should the kernel execute and validate this BPF program?”

---

### 3. Why They Feel Confusing

Because many hook types map almost 1:1 to program types.

Example:

| Hook         | Program Type               |
| ------------ | -------------------------- |
| `kprobe`     | `BPF_PROG_TYPE_KPROBE`     |
| `tracepoint` | `BPF_PROG_TYPE_TRACEPOINT` |
| `XDP`        | `BPF_PROG_TYPE_XDP`        |
| `LSM`        | `BPF_PROG_TYPE_LSM`        |

So people casually mix them together.

But they are not fundamentally identical.

---

### 4. Important Distinction: One Program Type Can Support Multiple Hook Types

This is where the distinction becomes clearer.

Example: `BPF_PROG_TYPE_TRACING`

This single program type supports several attachment styles:

* `fentry`
* `fexit`
* `fmod_ret`
* `tp_btf`
* sometimes typed raw tracepoints

So:

| Hook Type | Program Type            |
| --------- | ----------------------- |
| `fentry`  | `BPF_PROG_TYPE_TRACING` |
| `fexit`   | `BPF_PROG_TYPE_TRACING` |
| `tp_btf`  | `BPF_PROG_TYPE_TRACING` |

The hook changes, but verifier/runtime model stays the same.

---

### 5. Another Example: TC vs XDP

Both are packet-processing hooks.

#### XDP

Hook:

* NIC RX path before skb allocation

Program type:

* `BPF_PROG_TYPE_XDP`

Context:

* `struct xdp_md`

Return values:

* `XDP_PASS`
* `XDP_DROP`
* `XDP_TX`
* etc.

---

#### TC

Hook:

* Linux traffic control ingress/egress

Program type:

* `BPF_PROG_TYPE_SCHED_CLS`

Context:

* `struct __sk_buff`

Return values:

* TC actions

Different hook point, different program model.

---

### 6. Tracepoint vs tp_btf vs kprobe

These are especially important to distinguish.

---

### kprobe

Hook:

* arbitrary kernel symbol entry

Program type:

* `BPF_PROG_TYPE_KPROBE`

Characteristics:

* dynamic instrumentation
* fragile across kernel versions
* raw register access (`pt_regs`)
* less type safety

---

### tracepoint

Hook:

* predefined static trace event

Program type:

* `BPF_PROG_TYPE_TRACEPOINT`

Characteristics:

* stable ABI
* predefined event struct
* lower overhead than kprobe
* safer

---

### tp_btf

Hook:

* BTF-described typed trace hooks

Program type:

* usually `BPF_PROG_TYPE_TRACING`

Characteristics:

* typed arguments
* CO-RE friendly
* no manual struct decoding
* modern replacement direction

---

### 7. Attach Type (Third Concept!)

There’s actually a third axis:

```c
enum bpf_attach_type
```

Examples:

* `BPF_TRACE_FENTRY`
* `BPF_TRACE_FEXIT`
* `BPF_XDP`
* `BPF_LSM_MAC`

So modern eBPF often has:

| Concept      | Example                 |
| ------------ | ----------------------- |
| Program Type | `BPF_PROG_TYPE_TRACING` |
| Attach Type  | `BPF_TRACE_FENTRY`      |
| Hook Target  | `tcp_v4_connect`        |

This separation became important as eBPF evolved.

---

### 8. Real Example

With libbpf:

```c
SEC("fentry/tcp_v4_connect")
int BPF_PROG(handle_connect, struct sock *sk)
{
    return 0;
}
```

Internally:

| Thing        | Value                   |
| ------------ | ----------------------- |
| Hook style   | `fentry`                |
| Hook target  | `tcp_v4_connect`        |
| Program type | `BPF_PROG_TYPE_TRACING` |
| Attach type  | `BPF_TRACE_FENTRY`      |

---

### 9. Quick Summary

## Hook Types

Describe:

* where execution happens
* what event triggers BPF

Examples:

* kprobe
* tracepoint
* xdp
* lsm
* tc
* uprobes

---

### Program Types

Describe:

* execution semantics
* verifier rules
* helper availability
* context type

Examples:

* `BPF_PROG_TYPE_XDP`
* `BPF_PROG_TYPE_KPROBE`
* `BPF_PROG_TYPE_TRACING`
* `BPF_PROG_TYPE_LSM`

---

### 10. Modern Trend

Modern kernels are converging toward:

* fewer generic program types
* richer attach types
* BTF-typed hooks

Especially:

* `BPF_PROG_TYPE_TRACING`
* `fentry/fexit`
* `tp_btf`

are replacing many old-style `kprobe` use cases.

---

# Conceptual Architecture

```text
                 eBPF Program
                        |
                Program Type
      (execution/verifier model)
                        |
                 Attach Type
            (fentry, fexit...)
                        |
                  Hook Target
        (tcp_v4_connect, xdp RX,
         security_inode_create...)
```

That layered model is the cleanest way to think about modern eBPF.


---

## Actual Mechanism of Hooks:

At a low level, an eBPF “hook” is just a **kernel-supported interception point** where the kernel 
intentionally transfers execution into the eBPF VM/JIT-generated code.

The important thing is:

> **eBPF does not magically “watch” the kernel**.
> **The Linux kernel explicitly calls into eBPF infrastructure at specific places.**

Different hook families implement this differently.

### Big Picture

When an event happens:

```text
kernel event occurs
        ↓
hook infrastructure activates
        ↓
kernel finds attached BPF programs
        ↓
BPF dispatcher/trampoline runs
        ↓
eBPF program executes
        ↓
result returned to kernel
        ↓
kernel continues execution
```

The *interesting part* is:

> How does the kernel divert execution into BPF code?

The answer depends on the hook type.

There are several major mechanisms:

| Hook Family             | Underlying Mechanism          |
| ----------------------- | ----------------------------- |
| kprobe/uprobe           | Dynamic breakpoint patching   |
| tracepoint              | Static instrumentation sites  |
| fentry/fexit/tp_btf     | BPF trampolines               |
| XDP                     | Explicit driver call site     |
| tc/cgroup/socket filter | Networking callback chains    |
| LSM                     | Security hook dispatch tables |
| perf events             | Perf subsystem callbacks      |

Each works very differently internally.

#### 1. kprobe Mechanism

kprobes are based on **dynamic instruction patching**.

=> What Happens

Suppose you attach to:

```text 
tcp_v4_connect()
```

The kernel:

1. Locates the function address
2. Replaces first instruction with breakpoint instruction

   * x86: `int3`
   * arm64: `brk`
3. Registers a handler

Now execution becomes:

```text
CPU executes tcp_v4_connect
        ↓
hits breakpoint
        ↓
CPU trap into kernel exception handler
        ↓
kprobe framework invoked
        ↓
BPF program executed
        ↓
original instruction emulated/restored
        ↓
continue execution
```


##### Internal Flow

Simplified:

```text 
kernel function
    ↓
breakpoint trap
    ↓
do_int3()
    ↓
kprobe_handler()
    ↓
bpf_prog_run()
```

##### Why kprobes Are Flexible

Because they can patch:

* almost any kernel symbol
* dynamically at runtime
* without recompiling kernel


=> Downsides

This mechanism is expensive:

* CPU trap
* exception handling
* register save/restore
* instruction emulation

Also fragile:

* function layouts change
* compiler optimizations differ
* symbols disappear

This is why modern BPF prefers trampolines.

#### 2. tracepoint Mechanism

Tracepoints are fundamentally different.

They are **statically compiled instrumentation sites**.

Kernel source literally contains macros like:

```c
trace_sched_switch(prev, next);
```

which expand into conditional tracing code.


=> Actual Kernel Path

At compile time:

```text 
kernel source
    ↓
TRACE_EVENT macro
    ↓
generated tracepoint structures
    ↓
tracepoint callsite inserted
```

At runtime:

```text
kernel execution
    ↓
tracepoint function
    ↓
iterate registered callbacks
    ↓
BPF tracepoint callback invoked
```

---

=> Important Detail

No breakpoints.

No instruction patching.

The kernel already contains explicit callback locations.

Conceptually:

```c
if (tracepoint_enabled)
    call_callbacks();
```

###### BPF Attachment

When you attach BPF:

```text 
tracepoint
    ↓
register callback into tracepoint subsystem
    ↓
callback points to BPF dispatcher
```


=> Why Tracepoints Are Faster

No CPU exception/trap.

Just normal function calls.


#### 3. fentry/fexit/tp_btf Mechanism (Modern BPF)

This is the most sophisticated mechanism.

Uses:

=> BPF Trampolines

---

=> Core Idea

Instead of breakpoints:

> Dynamically rewrite function call flow to jump directly into generated BPF dispatch code.

This is extremely fast.

---

=> The Trampoline

Kernel creates executable memory containing generated machine code:

```text 
save registers
call BPF program 1
call BPF program 2
...
restore registers
jump back
```

This is called a:

```text
BPF trampoline
```

---

=> Function Entry Flow

Originally:

```text 
caller
   ↓
tcp_v4_connect
```

After attaching fentry:

```text
caller
   ↓
BPF trampoline
   ↓
BPF programs
   ↓
real tcp_v4_connect
```

---

=> How Kernel Achieves This

Architecture-specific code rewrites function prologue/call target.

Depends on architecture:

* ftrace infrastructure
* direct call patching
* text_poke()
* static calls

---

=> Why This Is Fast

No:

* traps
* exceptions
* breakpoint handling

Just direct jumps/calls.

Performance is close to native function call overhead.

---

=> ftrace Relationship

Modern BPF tracing heavily reuses:

```text
ftrace
```

kernel infrastructure.

ftrace already solved:

* dynamic function instrumentation
* safe text patching
* per-CPU dispatch
* recursion protection

BPF layers on top.

---

#### 4. XDP Mechanism

XDP is completely different.

No tracing.

No instrumentation.

Instead:

> Network driver explicitly calls BPF program.

---

=> Packet Receive Flow

Without XDP:

```text 
NIC DMA packet
    ↓
driver RX handler
    ↓
allocate skb
    ↓
network stack
```

With XDP:

```text
NIC DMA packet
    ↓
driver RX handler
    ↓
call BPF program
    ↓
BPF decides PASS/DROP/TX/REDIRECT
```

---

=> Actual Driver Code

Driver literally does something like:

```c 
act = bpf_prog_run_xdp(prog, xdp_ctx);
```

So XDP is:

> explicit invocation by networking subsystem.

No patching at all.

---

=> Why XDP Is Extremely Fast

Runs:

* before skb allocation
* before most networking stack
* directly in NAPI RX path

Often:

* fully JIT compiled
* CPU-cache hot
* zero-copy paths

---

#### 5. TC / Socket Filter Hooks

Very similar conceptually to XDP.

Networking stack has callback chains:

```text 
packet processing stage
      ↓
classifier/action framework
      ↓
BPF program invoked
```

Again:

* explicit subsystem integration
* not dynamic instrumentation

---

#### 6. LSM Hook Mechanism

Linux Security Module framework already contains security hooks.

Kernel code does:

```c 
security_inode_create(...)
```

Internally:

```text 
LSM dispatcher
    ↓
iterate registered security hooks
    ↓
SELinux/AppArmor/BPF-LSM callbacks
```

BPF-LSM registers itself into this hook table.

---

=> BPF LSM Flow

```text 
kernel security event
    ↓
LSM hook called
    ↓
BPF LSM dispatcher
    ↓
attached BPF programs run
    ↓
allow/deny result returned
```

---

=> Important Observation

LSM hooks are:

* not tracing
* not breakpoints

They are:

> policy enforcement callbacks.

---

#### 7. How eBPF Programs Actually Execute

Regardless of hook type:

Eventually kernel calls something like:

```c
bpf_prog_run(prog, ctx)
```

---

=> Program Lifecycle

---

##### Step 1 — Userspace Loads Program

Using syscall:

```c
bpf(BPF_PROG_LOAD, ...)
```

Kernel:

* verifies bytecode
* validates safety
* JIT compiles (usually)

---

##### Step 2 — Program Stored in Kernel

Kernel creates:

```c 
struct bpf_prog
```

Contains:

* JITed machine code
* metadata
* verifier info
* helper permissions

---

##### Step 3 — Program Attached

Attach API connects program to hook.

Examples:

```text
bpf_link_create()
perf_event_open()
netlink tc attach
xdp attach ioctl
```

---

##### Step 4 — Hook Stores Program Reference

Subsystem stores pointer:

```text 
hook point
    ↓
array/list/dispatcher
    ↓
struct bpf_prog *
```

---

##### Step 5 — Event Happens

Kernel reaches hook.

---

##### Step 6 — Program Runs

Usually:

```text
JITed native machine code executes directly in kernel mode
```

NOT interpreted in most production systems.

---

#### 8. BPF Dispatcher Optimization

Modern kernels optimize multiple attached programs.

Instead of:

```text
for each prog:
    indirect call
```

Kernel generates specialized dispatchers:

```text
direct call prog1
direct call prog2
```

Reducing:

* branch mispredicts
* indirect call overhead

Important for:

* XDP
* tracing
* tc

---

#### 9. Safety Model

Critical insight:

> Hooks are dangerous because BPF runs in kernel context.

Safety comes from verifier.

Verifier guarantees:

* bounded execution
* valid memory access
* no arbitrary kernel corruption
* safe helper usage

Without verifier:

* hooks would be arbitrary kernel modules

---

#### 10. Architectural Summary

Different hook families use different interception technologies:

```text
                    eBPF Hooks
                         |
    ------------------------------------------------
    |              |             |                 |
Dynamic         Static       Callback         Trampoline
Patching      Instrument.    Invocation        Rewriting
    |              |             |                 |
 kprobe       tracepoint      XDP/TC/LSM      fentry/fexit
```

---

=> Modern Trend

Linux is increasingly moving toward:

```text
BTF + trampolines + typed contexts
```

because they provide:

* lower overhead
* better type safety
* more stability
* better verifier knowledge

Which is why:

* `fentry/fexit`
* `tp_btf`
* BPF trampolines

are considered the modern architecture for observability BPF.

-------
## Note: 
=> kprobe breakpoint trap is conceptually similar to GDB 

Very similar idea.

Both use:

* instruction patching
* breakpoint exception/trap
* CPU interrupt handling

Example on x86:

```text
original instruction
    ↓
replace with int3
    ↓
CPU hits int3
    ↓
trap handler executes
```

Difference:

| GDB                  | kprobe                        |
| -------------------- | ----------------------------- |
| debugger-oriented    | kernel instrumentation        |
| user-space debugging | kernel tracing/monitoring     |
| ptrace-based control | kernel probe framework        |
| stops process        | usually continues immediately |

So yes:

> kprobe is essentially production-grade dynamic kernel breakpoint instrumentation.

---

# eBPF Context: 

## How Context Relates to Hooks

This is one of the MOST important eBPF concepts.

The “context” is:

> The kernel-generated execution state object passed into the BPF program when the hook fires.

Every hook mechanism constructs a context differently.

---

## Core Idea

When a hook triggers:

```text 
kernel event occurs
       ↓
kernel gathers relevant state
       ↓
builds/passes context
       ↓
BPF program receives ctx
```

Your BPF program never runs “in empty space.”

It always executes with a hook-specific context.

---

## Generic Execution Model

Kernel internally does something like:

```c
bpf_prog_run(prog, ctx);
```

That `ctx` pointer is the context object.

---

## Why Context Exists

The BPF program needs event-specific data.

Examples:

| Hook       | Needed Information           |
| ---------- | ---------------------------- |
| XDP        | packet buffer                |
| kprobe     | CPU registers/function args  |
| tracepoint | event fields                 |
| LSM        | security operation arguments |
| tc         | skb/network metadata         |

So each subsystem defines:

* what information exists
* how it is structured
* what BPF can access

---

## Context Depends on Program Type

This is why program type matters.

Program type defines:

* expected context structure
* verifier rules for accessing it

---

## Example 1 — kprobe Context

kprobe triggers at arbitrary kernel instruction/function.

Kernel only reliably has:

* CPU register state
* stack state

So context is:

```c
struct pt_regs *ctx;
```

This contains:

* CPU registers
* instruction pointer
* stack pointer
* function arguments (ABI dependent)

---

## Flow

```text
breakpoint trap
      ↓
CPU register snapshot exists
      ↓
kernel wraps as pt_regs
      ↓
passed to BPF
```

---

## Accessing Function Args

Example:

```c
SEC("kprobe/tcp_v4_connect")
int prog(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
}
```

Why macro needed?

Because:

* x86 args in registers
* arm64 different registers
* ABI varies

So:

> kprobe context is architecture-level machine state.

Not typed kernel objects.

---

## Example 2 — tracepoint Context

Tracepoints are predefined events.

Kernel already knows exact event schema.

Example tracepoint:

```text
sched:sched_switch
```

Kernel generates struct:

```c
struct trace_event_raw_sched_switch {
    ...
    char prev_comm[16];
    pid_t prev_pid;
    ...
};
```

So BPF gets:

```c
struct trace_event_raw_sched_switch *ctx
```

---

## Important Difference

Unlike kprobe:

* no raw registers
* no ABI decoding
* already structured event data

Much safer/stable.

---

## Example 3 — XDP Context

XDP runs inside NIC RX path.

Kernel passes:

```c
struct xdp_md *ctx
```

Contains packet boundaries:

```c
data
data_end
data_meta
ingress_ifindex
```

---

## Important Insight

Packet itself is NOT copied into context.

Instead:

```text
ctx contains pointers into packet memory
```

BPF directly accesses packet buffer.

---

## XDP Flow

```text 
packet arrives
     ↓
driver creates xdp_md
     ↓
ctx->data points to packet
     ↓
BPF parses packet in-place
```

---

## Example 4 — tc Context

TC operates later in networking stack.

Packet already became:

```text 
struct sk_buff
```

So context:

```c 
struct __sk_buff *ctx
```

This is skb-oriented networking metadata.

---

## Example 5 — LSM Context

LSM hooks are typed kernel security operations.

Example:

```c 
SEC("lsm/file_open")
int BPF_PROG(check, struct file *file)
```

Here context is effectively:

```text 
actual kernel function arguments
```

because modern trampoline/BTF hooks understand types.

---

## Important Evolution

Old hooks:

* machine-state-oriented
* register-oriented

Modern hooks:

* typed semantic objects

This is a HUGE evolution in BPF architecture.

---

## Context Memory Is NOT Arbitrary

Verifier tightly controls context access.

Example:

```c
ctx->data
```

Verifier knows:

* valid offsets
* field sizes
* allowed reads/writes

---

## Verifier Tracks Context Types

Internally verifier assigns register types:

```text 
PTR_TO_CTX
PTR_TO_PACKET
PTR_TO_MAP_VALUE
...
```

When program starts:

```text
R1 = PTR_TO_CTX
```

Convention:

* first argument in R1
* points to context

---

## Example Internal Verification

Suppose:

```c
u32 ifindex = ctx->ingress_ifindex;
```

Verifier checks:

* offset valid?
* field exists?
* access size correct?
* readable in this prog type?

Only then accepted.

---

## Why Hook Type Influences Context

Because hook location determines available information.

Example:

---

### Very Early Hook (XDP)

At this stage:

* no skb yet
* only raw packet memory

So context can only expose:

* packet pointers
* NIC metadata

---

### Later Hook (TC)

Now:

* skb allocated
* routing metadata exists
* socket association may exist

So richer context possible.

---

## Trampoline Hooks and Typed Contexts

Modern hooks (`fentry`, `fexit`, `tp_btf`) use BTF type metadata.

Kernel knows:

```c
int tcp_v4_connect(struct sock *sk, ...)
```

So trampoline directly passes typed arguments.

No register decoding needed.

This is why modern BPF is cleaner.

---

## Deep Internal View

Internally hook invocation often becomes:

```c
generated_trampoline(sk, ...)
{
    bpf_prog(sk, ...);
}
```

instead of:

```text
extract args from pt_regs manually
```

---

## Key Conceptual Model

```text 
Hook fires
    ↓
Kernel constructs execution context
    ↓
Verifier-defined context type
    ↓
BPF program receives ctx
    ↓
BPF safely accesses allowed fields
```

---

## Simplified Mapping

| Hook Type    | Context Nature             |
| ------------ | -------------------------- |
| kprobe       | raw CPU state              |
| tracepoint   | predefined event struct    |
| XDP          | packet memory window       |
| tc           | skb wrapper                |
| LSM          | typed kernel function args |
| fentry/fexit | typed function args        |
| perf_event   | perf sample data           |

---

## Most Important Insight

The hook determines:

1. when BPF runs
2. what information is available

The context object is:

> the kernel’s packaged representation of that available information.

---

# Context and Langauges:


## The context is fundamentally kernel-defined, not language-defined

Whether you write eBPF in:

* restricted C
* Rust (`no_std`)
* Zig
* even hand-written BPF bytecode

…the **kernel hook determines the context**, not the language.

So for XDP:

```c
struct xdp_md *ctx
```

is the same conceptual context regardless of:

* libbpf + C
* Aya + Rust
* other frameworks

The framework/library only helps:

* expose those kernel structs safely
* generate bindings
* load/attach programs
* manage maps
* handle relocations/BTF

---

## libbpf vs Aya

### libbpf (C)

Mostly thin wrapper around:

* `bpf()` syscall
* ELF parsing
* BTF/CO-RE relocation
* attach APIs

You directly use kernel-compatible structs.

Example:

```c
SEC("xdp")
int prog(struct xdp_md *ctx)
```

---

## Aya (Rust)

Aya provides:

* Rust-side abstractions
* Rust bindings for kernel structs
* loaders/attachers
* safe wrappers where possible

Example:

```rust
#[xdp]
pub fn xdp_prog(ctx: XdpContext) -> u32
```

Internally:

* `XdpContext` wraps raw kernel context pointer
* eventually still becomes raw BPF-compatible memory layout

---

## About FFI in Aya

Yes — but slightly nuanced.

There are effectively TWO worlds:

| World            | Runs Where            |
| ---------------- | --------------------- |
| userspace loader | normal Rust userspace |
| eBPF program     | kernel BPF VM/JIT     |

---

## Userspace Side

Aya userspace loader absolutely interacts through:

* syscalls
* kernel APIs
* netlink/ioctl/etc.

This is normal systems programming.

---

## eBPF Program Side

Inside the actual BPF program:

Rust compiles to:

```text
LLVM BPF backend
    ↓
eBPF bytecode
```

There is NO traditional runtime:

* no libc
* no OS
* no allocator (normally)
* no standard FFI layer like normal Rust/C interop

Instead:

* helper calls are ABI-defined
* kernel expects specific register conventions

Example helper:

```text
bpf_map_lookup_elem
```

is basically a special kernel-call ABI.

---

## So Is There FFI?

Conceptually yes:

* Aya bridges Rust ↔ kernel ABI

But technically:

* not classic dynamic-library FFI
* more ABI compatibility + generated bindings

Aya must ensure:

* struct layout compatibility
* calling convention compatibility
* verifier-compatible codegen

---

## Extremely Important Insight

The kernel NEVER knows:

* “this was written in Rust”
* “this was written in C”

Kernel only sees:

```text 
verified eBPF bytecode
```

and associated metadata.

Language disappears after compilation.

---

## 2. Yes — understanding context is CRITICAL for writing good eBPF programs

This is absolutely true.

In practice:

> Understanding the hook’s context is often more important than syntax knowledge.

Because context determines:

* what data exists
* what operations are cheap
* what helpers are available
* what memory access patterns are legal
* what performance constraints exist

---

## Example — XDP Context Knowledge

If you understand:

```c 
ctx->data
ctx->data_end
```

you realize:

* packets are zero-copy
* parsing must be bounds-checked
* no skb exists yet
* very early fast path

Then you naturally write:

* linear packet parsers
* cache-friendly code
* minimal helper calls

Without context knowledge:

* people write inefficient skb-like logic
* verifier failures happen
* performance collapses

---

## Example — kprobe Context Knowledge

Understanding:

```c
struct pt_regs
```

means understanding:

* ABI calling conventions
* register argument extraction
* architecture differences
* unstable function layouts

Then you understand why:

* CO-RE matters
* BTF tracing is preferred
* kprobes are fragile

---

## Example — tracepoint Context Knowledge

Knowing tracepoint context means:

* event fields are pre-structured
* ABI is relatively stable
* no manual register decoding

Then you can efficiently:

* correlate scheduler events
* track syscalls
* aggregate telemetry

---

## Example — tc Context Knowledge

Understanding `__sk_buff` means understanding:

* skb lifecycle
* packet cloning
* GRO/GSO
* metadata availability

This changes:

* how you rewrite packets
* checksum handling
* redirect behavior

---

## Example — LSM Context Knowledge

Understanding LSM hooks means understanding:

* security decision flow
* object lifetime
* reference validity
* sleepable vs non-sleepable execution

Otherwise:

* policy logic becomes unsafe or incorrect

---

## Real eBPF Expertise

Advanced eBPF skill is actually:

```text
Kernel subsystem knowledge
        +
Hook semantics
        +
Context understanding
        +
Verifier constraints
```

NOT just:

* “knowing BPF syntax”

---

## The Best Mental Model

Think of eBPF programs as:

```text
small kernel extensions
```

attached to:

* networking pipeline
* tracing pipeline
* security pipeline
* scheduler pipeline
* syscall pipeline

To write good programs:
you must understand the subsystem’s execution context.

---

## Practical Rule

When learning a hook type, always study:

| Important Thing    | Why                     |
| ------------------ | ----------------------- |
| Context struct     | accessible data         |
| Hook timing        | what exists yet         |
| Return semantics   | what decisions possible |
| Allowed helpers    | kernel capabilities     |
| Concurrency model  | races/preemption        |
| Memory lifetime    | pointer safety          |
| Performance budget | optimization strategy   |

That is the real foundation of effective eBPF development.

--- 


