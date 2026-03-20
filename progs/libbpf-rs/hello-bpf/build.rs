// // for libbpf-cargo version less then 0.25.0
// use libbpf_cargo::SkeletonBuilder;
// use std::path::PathBuf;
//
// fn main() {
//     let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("hello.skel.rs");
//
//     SkeletonBuilder::new()
//         .source("src/bpf/hello.bpf.c")
//         .debug(true)
//         .build_and_generate(&out)
//         .unwrap();
//
//     // Rerun build if the C file changes
//     println!("cargo:rerun-if-changed=src/bpf/hello.bpf.c");
// }
use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("hello.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/hello.bpf.c")
        // .debug(true) <---  Older version
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/hello.bpf.c");
}
