use clap::Parser;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, OpenObject};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

// Include the generated skeleton from build.rs
mod pps_stats {
    include!(concat!(env!("OUT_DIR"), "/pps_stats.skel.rs"));
}

#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct DataRec {
    packets: u64,
    bytes: u64,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short = 't', long, default_value_t = 1)]
    interval: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Get interface index
    let ifindex = nix::net::if_::if_nametoindex(args.interface.as_str())? as i32;

    // 2. Initialize the BPF Object memory (Required in 0.26.x)
    let mut open_obj = MaybeUninit::uninit();
    //let skel_builder = pps_stats::PpsStatsSkelBuilder::default();

    // 3. Open and Load Phase
    let open_skel = pps_stats::PpsStatsSkelBuilder::default().open(&mut open_obj)?;
    //let open_skel = skel_builder.open(&mut open_obj)?;
    //let mut skel = open_skel.load()?;
    let skel = open_skel.load()?;

    // 4. Attach XDP
    // In libbpf-rs 0.26, maps and progs are accessible via public fields
    let _link = skel.progs.xdp_stats_prog.attach_xdp(ifindex)?;

    println!(">>> Monitoring interface: {}", args.interface);
    println!(">>> Press Ctrl+C to stop.");

    // 5. Shutdown handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut prev_pkts = 0u64;
    let mut prev_bytes = 0u64;

    // 6. Stats Loop
    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(args.interval));

        let mut total_pkts = 0u64;
        let mut total_bytes = 0u64;
        let key = 0u32.to_ne_bytes();

        // Access map directly via the 'maps' field
        if let Some(raw_values) = skel
            .maps
            .pkt_count
            .lookup_percpu(&key, libbpf_rs::MapFlags::empty())
            .unwrap()
        {
            for cpu_bytes in raw_values {
                // Explicitly cast the pointer to read the DataRec struct
                let rec: DataRec = unsafe { std::ptr::read(cpu_bytes.as_ptr() as *const DataRec) };
                total_pkts += rec.packets;
                total_bytes += rec.bytes;
            }
        }

        let delta_pkts = total_pkts.saturating_sub(prev_pkts);
        let delta_bytes = total_bytes.saturating_sub(prev_bytes);
        let mbps = (delta_bytes as f64 * 8.0) / 1_000_000.0;

        println!(
            "PPS: {:<10} | Mbps: {:<10.2} | Total Pkts: {}",
            delta_pkts, mbps, total_pkts
        );

        prev_pkts = total_pkts;
        prev_bytes = total_bytes;
    }

    Ok(())
}
