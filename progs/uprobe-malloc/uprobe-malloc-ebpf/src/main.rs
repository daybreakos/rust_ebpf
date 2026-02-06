#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext, EbpfContext};
use aya_log_ebpf::info;

#[uprobe]
pub fn uprobe_malloc(ctx: ProbeContext) -> u32 {
    match try_uprobe_malloc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_malloc(ctx: ProbeContext) -> Result<u32, u32> {
    // info!(&ctx, "function malloc called by libc");
    // In x86_64, the 1st argument (size) is in %rdi
    // Aya's  .arg(0) helper handles this register mapping
    let size: usize = ctx.arg(0).ok_or(0u32)?;
    // reduce the console log to make the program responsive
    if size <= 102400 {
        return Ok(0);
    }

    // We can also get the PID of the process calling malloc
    let pid = ctx.pid();

    // 1. Capture the Result into a variable so the data lives long enough
    let comm_raw = ctx.command();

    //NOTE: the ctx.command() is typically 16 byte null-terminated string
    //While from_utf8_unchecked() is fast we might see occasionally some garbage trailing
    //characters in log if null termination is handles incorrectly. How ever aya_log should
    //generally handle byte slices and strings correctly for the trace buffer.

    // 2. Use a match to handle the Result and conversion in one scope
    let comm = match &comm_raw {
        Ok(val) => unsafe { core::str::from_utf8_unchecked(val) },
        Err(_) => "unknown",
    };
    //info!(&ctx, "PID {}: alloc called for {} bytes ", pid, size);
    info!(
        &ctx,
        "{} app with PID {}: alloc called for {} bytes ", comm, pid, size
    );
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
