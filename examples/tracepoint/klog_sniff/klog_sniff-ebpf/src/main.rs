#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::EbpfContext;
use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

use core::str::from_utf8_unchecked;

#[tracepoint]
pub fn klog_sniff(ctx: TracePointContext) -> u32 {
    match try_klog_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_klog_sniff(ctx: TracePointContext) -> Result<u32, i64> {
    // 1. Read the PID (at offset 4)
    let pid: i32 = unsafe { ctx.read_at::<i32>(4)? };

    // 2. Read the __data_loc for 'msg' (at offset 8)
    // The format says: field:__data_loc char[] msg; offset:8; size:4;
    let data_loc: u32 = unsafe { ctx.read_at::<u32>(8)? };

    // 3. Extract the offset (lower 16 bits)
    let offset = (data_loc & 0xFFFF) as usize;

    // 4. Prepare a buffer for the message
    let mut buf = [0u8; 128];

    // 5. calculate the pointer to the string
    // TracePointContext implementes BpfContext, which provides as_ptr()
    // The offset is relative to the start of the tracepoint struct .
    let base_ptr = ctx.as_ptr() as usize;
    let msg_ptr = (base_ptr + offset) as *const u8;

    let msg_bytes = unsafe { bpf_probe_read_kernel_str_bytes(msg_ptr, &mut buf)? };

    let msg_to_print = unsafe { from_utf8_unchecked(msg_bytes) };

    // 6. Log the PID and the message
    info!(&ctx, "PID {}: {}", pid, msg_to_print);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
