load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

cc_library(
    name = "bpf_loader",
    srcs = ["loader.cc"],
    hdrs = ["loader.h"],
    copts = [
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"-I/home/lambdai/workspace/ubuntu-focal/tools/lib",
        "-lbpf",
        "-lelf",
        "-lz",
    ],
    deps = [
        "@kernel_src_tools_lib//:headers",
        "@glog",
        "@elf//:lib",
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"@kernelheaders//:headers",
    ],
)

cc_binary(
    name = "loader_test",
    srcs = ["loader_test.cc"],
    data = [
        "//source/bpf:stream_bpf_o",
    ],
    deps = [
        ":bpf_loader",
        "@elf//:lib",
        "@glog",
        "@kernel_src_tools_lib//:bpflib",
    ],
)
