Example program using Kfunc :

1. Avoid multiple header includes in bpf code to prevent types miss matching.
2. Generate vmlinux.h header using bpftool, if you wish to build the bpf code with it.
