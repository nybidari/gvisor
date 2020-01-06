load("//javascript/tools/tarball:builddefs.bzl", "Tarball", "TarballEntry")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

Tarball(
    name = "tar",
    entries = [
        TarballEntry(
            srcs = [
                "Dockerfile",
            ],
            strip_prefix = "third_party/gvisor/benchmarks/workloads/netcat",
        ),
    ],
)
