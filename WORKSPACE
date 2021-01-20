workspace(name = "boringsslapp")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository") 

# Rule repository
http_archive(
   name = "rules_foreign_cc",
   sha256 = "7ca49ac5b0bc8f5a2c9a7e87b7f86aca604bda197259c9b96f8b7f0a4f38b57b",
   strip_prefix = "rules_foreign_cc-f54b7ae56dcf1b81bcafed3a08d58fc08ac095a7",
   url = "https://github.com/bazelbuild/rules_foreign_cc/archive/f54b7ae56dcf1b81bcafed3a08d58fc08ac095a7.tar.gz",
)
   
load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies([])


http_archive(
    name = "libevent",
    urls = [
        "https://github.com/libevent/libevent/archive/release-2.1.12-stable.tar.gz"
    ],
    sha256 = "7180a979aaa7000e1264da484f712d403fcf7679b1e9212c4e3d09f5c93efc24",
    strip_prefix = "libevent-release-2.1.12-stable",
    build_file = "//bazel:libevent.BUILD"
)

http_archive(
    name = "gtest",
    url = "https://github.com/google/googletest/archive/release-1.10.0.tar.gz",
    sha256 = "9dc9157a9a1551ec7a7e43daea9a694a0bb5fb8bec81235d8a1e6ef64c716dcb",
    strip_prefix = "googletest-release-1.10.0",
    build_file = "//bazel:gtest.BUILD",
)


http_archive(
    name = "com_github_gflags_gflags",
    sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
    strip_prefix = "gflags-2.2.2",
    urls = ["https://github.com/gflags/gflags/archive/v2.2.2.tar.gz"],
)

http_archive(
    name = "glog",
    sha256 = "62efeb57ff70db9ea2129a16d0f908941e355d09d6d83c9f7b18557c0a7ab59e",
    strip_prefix = "glog-d516278b1cd33cd148e8989aec488b6049a4ca0b",
    urls = ["https://github.com/google/glog/archive/d516278b1cd33cd148e8989aec488b6049a4ca0b.zip"],
)

# http_archive(
#     name = "glog",
#     url = "https://github.com/google/glog/archive/v0.4.0.tar.gz",
#     sha256 = "f28359aeba12f30d73d9e4711ef356dc842886968112162bc73002645139c39c",
#     strip_prefix = "glog-0.4.0",
#     build_file = "//bazel:glog.BUILD",
# )

# git_repository(
#     name = "boringssl",
#     commit = "bdbe37905216bea8dd4d0fdee93f6ee415d3aa15",
#     remote = "https://boringssl.googlesource.com/boringssl",
# )

local_repository(
    name = "boringssl",
    path = "/home/lambdai/workspace/boringssl",
)

new_local_repository(
    name = "kernelheaders",
    path = "/usr/src/linux-headers-5.4.0-58/include",
    build_file_content = """
package(default_visibility = ["//visibility:public"])
cc_library(
    name = "headers",
    hdrs = glob(["**/*.h"])
)
"""
)