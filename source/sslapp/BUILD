load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    data = [
        "//data:server_data",
    ],
    deps = [
        "@boringssl//:crypto",
        "@boringssl//:ssl",
        "@glog",
    ],
)
