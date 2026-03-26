use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    // 1. Generate vmlinux.h dynamically if it doesn't exist
    let vmlinux_path = "src/bpf/vmlinux.h";
    if !std::path::Path::new(vmlinux_path).exists() {
        let output = std::process::Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to execute bpftool. Is it installed?");
        std::fs::write(vmlinux_path, output.stdout).unwrap();
    } else {
        println!("Generating BTF file : {} Done. ", vmlinux_path);
    }

    // 2. Run the SkeletonBuilder to generate the *.skel.rs file
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("pps_stats.skel.rs");

    SkeletonBuilder::new()
        .source("src/bpf/pps_stats.bpf.c")
        .clang_args(["-Isrc/bpf"])
        .build_and_generate(&out)
        .unwrap();

    println!("cargo:rerun-if-changed=src/bpf/pps_stats.bpf.c");
}
