load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "bpf_loader",
    srcs = ["loader.cc"],
    hdrs = ["loader.h"],
    copts = [
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"-I/home/lambdai/workspace/linux5.8/tools/lib",
        "-lbpf",
        "-lelf",
        "-lz",
    ],
    deps = [
        "@kernel_src_tools_lib//:headers",
        "@glog",
        "@elf//:lib",
        "@zlib//:lib",
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"@kernelheaders//:headers",
    ],
)

cc_library(
    name = "sock_cluster",
    srcs = ["cluster.cc"],
    hdrs = ["cluster.h"],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@kernel_src_tools_lib//:headers",
        "@glog",
        ":bpf_loader",
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
        ":sock_cluster",
        "@elf//:lib",
        "@glog",
        "@kernel_src_tools_lib//:bpflib",
    ],
)
