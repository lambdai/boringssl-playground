# Prerequisite
1. kernel header 
1. kernel source 
including bpftools, vmlinux.h, libbpf.a
1. local zlib, libelf
1. clang for kernel bpf program
1. gcc and bazel for user space loader


# Test
1. build bpf kernel program
$ make -C source/bpf

1. build loader_test
$ bazel build --verbose_failures source/loader:loader_test --verbose_failures 

1. run loader_test
$ sudo bazel-bin/source/loader/loader_test
