//#include "vmlinux.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static unsigned long long (*bpf_get_current_pid_tid)(void) = (void *) 14;
extern void bpf_rcu_read_lock(void) __ksym;    // comment if vmlinux.h is included
extern void bpf_rcu_read_unlock(void) __ksym;  // comment if vmlinux.h is included

char _license[] SEC("license") = "GPL";

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(handle_kfunc_demo) {
   __u32 pid = bpf_get_current_pid_tid() >> 32; 
   bpf_rcu_read_lock();
   if (pid > 5000 ) { // reduce console log
      bpf_printk("KFunc: demo PID %u is opening a file", pid );
   }

   bpf_rcu_read_unlock();

   return 0;
}
