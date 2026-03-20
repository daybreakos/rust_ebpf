use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder}; // Added OpenSkel here
use std::mem::MaybeUninit;
use std::time::Duration;

mod hello {
    include!(concat!(env!("OUT_DIR"), "/hello.skel.rs"));
}

use hello::HelloSkelBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. In v0.26+, we must provide a place for the OpenObject to live
    // Prepare memory for the BPF Object
    let mut open_obj = MaybeUninit::uninit();

    // 2. Open Phase
    // Pass that reference to the builder's open() method
    let builder = HelloSkelBuilder::default();
    let open_skel = builder.open(&mut open_obj)?;

    // 3. Load Phase
    // Now .load() works because we imported the OpenSkel trait
    let mut skel = open_skel.load()?;

    // 4. Attach phase
    // Attach programs to the kernel hooks
    skel.attach()?;

    println!("Successfully started! Monitoring system writes...");
    println!("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see kernel output.");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
