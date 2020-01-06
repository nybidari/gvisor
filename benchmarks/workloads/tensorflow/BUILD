load("//javascript/tools/tarball:builddefs.bzl", "Tarball", "TarballEntry")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "tensorflow",
    srcs = ["__init__.py"],
)

Tarball(
    name = "tar",
    entries = [
        TarballEntry(
            srcs = [
                "Dockerfile",
            ],
            strip_prefix = "third_party/gvisor/benchmarks/workloads/tensorflow",
        ),
    ],
)
