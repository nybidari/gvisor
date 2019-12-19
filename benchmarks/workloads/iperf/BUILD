load("//javascript/tools/tarball:builddefs.bzl", "Tarball", "TarballEntry")
load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "iperf",
    srcs = ["__init__.py"],
)

py_test(
    name = "iperf_test",
    srcs = ["iperf_test.py"],
    python_version = "PY3",
    deps = [
        ":iperf",
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pathlib2", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
        requirement("six", False),
    ],
)

Tarball(
    name = "tar",
    entries = [
        TarballEntry(
            srcs = [
                "Dockerfile",
            ],
            strip_prefix = "third_party/gvisor/benchmarks/workloads/iperf",
        ),
    ],
)
