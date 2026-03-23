use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::mem::MaybeUninit;
use std::time::Duration;

mod rcu {
    include!(concat!(env!("OUT_DIR"), "/rcu.skel.rs"));
}

use rcu::RcuSkelBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut open_obj = MaybeUninit::uninit();

    let builder = RcuSkelBuilder::default();
    let open_skel = builder.open(&mut open_obj)?;

    let mut skel = open_skel.load()?;

    skel.attach()?;

    println!("Successfully started! Monitoring system writes... ");
    println!("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see additional output ");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
