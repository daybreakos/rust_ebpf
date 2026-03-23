use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("rcu.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/rcu.bpf.c")
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/rcu.bpf.c");
}
