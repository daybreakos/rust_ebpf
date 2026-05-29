# eBPF Roadmap 

Suggested Learning Order for eBPF (From Beginner → Advanced)

This order is optimized for:

* understanding the architecture deeply
* reading kernel/libbpf/Aya source code effectively
* building intuition instead of memorizing APIs

**The key principle**:

> Learn the execution model first, tooling second.

Many people do the reverse and get stuck.

---

## Phase 1 — Build the Correct Mental Model

Before writing programs, understand:

```text
What eBPF actually IS
```


### 1. Understand What eBPF Really Is

Learn:

* eBPF VM concept
* bytecode execution
* verifier
* JIT compilation
* helper calls
* maps

Goal:
Understand that eBPF is:

```text
restricted kernel extension runtime
```

NOT:

* scripting
* magical tracing
* “just packet filters”

### 2. Learn the Program Lifecycle

Understand:

```text 
userspace loader
    ↓
BPF_PROG_LOAD
    ↓
verification
    ↓
JIT compilation
    ↓
attach to hook
    ↓
event triggers execution
```

This is foundational.

### 3. Learn Program Types vs Hook Types vs Attach Types

This is CRITICAL early.

Understand clearly:

| Concept      | Meaning              |
| ------------ | -------------------- |
| Program type | execution model      |
| Hook type    | trigger location     |
| Attach type  | attachment semantics |

Without this:

* modern BPF architecture becomes confusing.

---

## Phase 2 — Learn Hook Execution Internals

Now understand:

```text 
HOW hooks actually work internally
```

This changes everything.


### 4. Learn Hook Mechanisms

Study:

* kprobes
* tracepoints
* trampolines
* XDP invocation
* LSM callbacks

Understand:

* breakpoint patching
* static instrumentation
* callback dispatch
* trampoline rewriting

Goal:
Understand how execution enters BPF.

### 5. Learn Context Deeply

This is one of the MOST important topics.

Study:

* what context is
* how hooks generate context
* verifier-visible context rules
* typed vs raw context

Learn examples:

| Hook       | Context      |
| ---------- | ------------ |
| kprobe     | `pt_regs`    |
| tracepoint | event struct |
| XDP        | `xdp_md`     |
| tc         | `__sk_buff`  |
| LSM        | typed args   |

Goal:
Understand:

> hook timing determines available information.

### 6. Learn Verifier Fundamentals

This is where real eBPF begins.

Study:

* register tracking
* pointer types
* scalar ranges
* bounds analysis
* packet validation
* stack limits

Especially:

* `PTR_TO_CTX`
* `PTR_TO_PACKET`
* helper constraints

Goal:
Read verifier errors comfortably.

---

## Phase 3 — Learn One Domain Deeply

Choose ONE subsystem first.

Do NOT learn all hooks simultaneously.

Recommended order:


### Recommended First Path: XDP

Why:

* self-contained
* easier mental model
* visible packet flow
* performance-oriented
* modern APIs

Learn:

* `xdp_md`
* packet parsing
* verifier bounds checks
* XDP actions
* NIC RX flow

Then:

* redirects
* cpumap/devmap
* AF_XDP

This teaches:

* contexts
* verifier reasoning
* helper usage
* memory access patterns

### Alternative First Path: Tracepoints

If observability interests you more.

Learn:

* tracepoint structs
* scheduler events
* syscall tracing
* perf/ringbuf

This teaches:

* event-driven tracing
* stable hooks
* kernel telemetry

### Avoid Starting With kprobes

Beginners often start here because tutorials do.

Bad idea initially because:

* ABI-dependent
* fragile
* raw registers
* unstable semantics

Learn kprobes AFTER understanding:

* tracepoints
* trampolines
* contexts

---

## Phase 4 — Learn Tooling

Only now start learning frameworks deeply.


### 7. Learn libbpf Architecture

Understand:

* ELF sections
* CO-RE
* BTF
* skeletons
* loaders
* links

Read:

* libbpf-bootstrap
* kernel selftests

Goal:
Understand canonical Linux eBPF model.


### 8. Learn BTF and CO-RE

This is modern eBPF infrastructure.

Study:

* BTF type metadata
* relocations
* field offset rewriting
* typed tracing

This unlocks:

* portable BPF programs
* modern tracing hooks

### 9. Learn Trampoline-Based Hooks

Study:

* fentry/fexit
* tp_btf
* fmod_ret

Understand:

* generated trampolines
* typed arguments
* why they replace kprobes

This is modern production tracing.

---

## Phase 5 — Learn Rust/Aya (Optional but Valuable)

Once kernel-side concepts are solid.

Then learn:

* Aya architecture
* Rust BPF constraints
* no_std
* safe wrappers
* userspace loaders

Important:
Understand:

* Rust abstractions are built ON kernel semantics
* not replacements for them

---

## Phase 6 — Learn Kernel Subsystems

At advanced levels:

```text
eBPF becomes mostly kernel engineering
```

Now study:

| Area              | Why                    |
| ----------------- | ---------------------- |
| Networking stack  | XDP/tc/socket hooks    |
| Scheduler         | tracing                |
| VFS               | LSM/filesystem hooks   |
| Memory management | allocator tracing      |
| Syscalls          | observability/security |
| cgroups           | resource hooks         |

This is where expertise forms.

---

## Phase 7 — Read Kernel Source

Now source code becomes understandable.

Start reading:

* `kernel/bpf/`
* `net/core/filter.c`
* `kernel/trace/bpf_trace.c`
* `kernel/bpf/verifier.c`
* `kernel/bpf/trampoline.c`

This becomes MUCH easier if previous phases are understood.

---

## Recommended Practical Progression

---

### Beginner Projects

#### XDP

* packet counter
* drop ICMP
* parse Ethernet/IP/TCP

#### Tracepoints

* syscall logger
* scheduler latency monitor

---

### Intermediate Projects

* DNS parser
* TCP latency tracker
* per-cgroup accounting
* ringbuf telemetry pipeline

---

### Advanced Projects

* custom LSM policy engine
* tc traffic shaping
* BPF scheduler extensions
* userspace networking with AF_XDP

---

## Best Learning Sequence (Condensed)

```text
1. eBPF VM + verifier basics
2. Program lifecycle
3. Hook/program/attach types
4. Hook execution mechanisms
5. Contexts
6. Verifier internals
7. ONE hook family deeply
8. libbpf
9. BTF + CO-RE
10. Trampolines
11. Rust/Aya
12. Kernel subsystems
13. Kernel source code
```

---

## Final Advice

The people who become strong at eBPF usually think in this order:

```text
kernel subsystem
    ↓
hook timing
    ↓
context semantics
    ↓
verifier constraints
    ↓
BPF implementation
```

NOT:

```text
framework API first
```

That mindset makes source code and advanced concepts dramatically easier to understand later.
