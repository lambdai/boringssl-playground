load("@rules_foreign_cc//tools/build_defs:cmake.bzl", "cmake_external")

package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "gtest_source",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)

licenses(["notice"])  # BSD

exports_files(["LICENSE"])

cmake_external(
    name = "gtest",
    # Values to be passed as -Dkey=value on the CMake command line;
    # here are serving to provide some CMake script configuration options
    cache_entries = {
    },
    lib_source = ":gtest_source",

    # We are selecting the resulting static library to be passed in C/C++ provider
    # as the result of the build;
    # However, the cmake_external dependants could use other artefacts provided by the build,
    # according to their CMake script
    static_libraries = [
        "libgtest.a",
        "libgmock.a",
    ],
)

cmake_external(
    name = "gtest_main",
    # Values to be passed as -Dkey=value on the CMake command line;
    # here are serving to provide some CMake script configuration options
    cache_entries = {
    },
    lib_source = ":gtest_source",

    # We are selecting the resulting static library to be passed in C/C++ provider
    # as the result of the build;
    # However, the cmake_external dependants could use other artefacts provided by the build,
    # according to their CMake script
    static_libraries = [
        "libgtest_main.a",
        "libgmock_main.a",
    ],
)
