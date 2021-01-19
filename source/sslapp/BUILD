load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "main",
    srcs = ["main.cc"],
    copts = [
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        # "-Iexternal/kernelheaders",
    ],
    data = [
        "//data:server_data",
    ],
    deps = [
        "@boringssl//:crypto",
        "@boringssl//:ssl",
        "@glog",
        # TODO(lambdai): cannot directly include kernel headers in userspace app.
        #"@kernelheaders//:headers",
    ],
)
