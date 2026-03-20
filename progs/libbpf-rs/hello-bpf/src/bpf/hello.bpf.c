#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_write")
int handle_write(void *ctx) {
   // 1. use __u32 instead of u32 as In std C u32 is not builtin so we use __u32 or unsigned int
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid < 1000) { 
      bpf_printk("Write syscall detected from PID %d\n", pid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
