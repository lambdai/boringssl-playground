# Prerequisite

1. kernel header
1. kernel source

   including bpftools, [vmlinux.h](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html), libbpf.a

   ```
   cd $KSRC/tools/lib/bpf/
   make  # libbpf.a

   cd $KSRC/tools/bpf/
   make -C bpftool # bpftool/bpftool

   bpftool/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux-`uname -r`.h
   ln -s vmlinux-`uname -r`.h vmlinux.h
   ```

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
