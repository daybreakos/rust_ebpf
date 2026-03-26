# Variables
TARGET := pps_stats
BPF_OBJ := $(TARGET).bpf.o
BPF_C := $(TARGET).bpf.c
USER_C := $(TARGET).c
SKEL := $(TARGET).skel.h

# Compilers
CLANG := clang
CC := gcc
BPFTOOL := bpftool

# Flags
# -g is essential for BTF (CO-RE) to work
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 
USER_CFLAGS := -g -O2 -Wall
LIBS := -lbpf -lelf -lz

.PHONY: all clean generate

all: $(TARGET)

# 1. Generate vmlinux.h (The kernel's type library)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile BPF code to object file
$(BPF_OBJ): $(BPF_C) vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 3. Generate the Skeleton header from the BPF object
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 4. Build the final User-space binary
$(TARGET): $(USER_C) $(SKEL)
	$(CC) $(USER_CFLAGS) $< -o $@ $(LIBS)

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(SKEL) vmlinux.h
