load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    data = [
        "//data:server_data",
        "//source/bpf:stream_bpf_o",
    ],
    deps = [
        "//source/loader:bpf_loader",
        "//source/loader:sock_cluster",
        "@elf//:lib",
        "@kernel_src_tools_lib//:bpflib",
        "@boringssl//:crypto",
        "@boringssl//:ssl",
        "@glog",

        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"@kernelheaders//:headers",
    ],
)
