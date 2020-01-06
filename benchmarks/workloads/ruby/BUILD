load("//javascript/tools/tarball:builddefs.bzl", "Tarball", "TarballEntry")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

filegroup(
    name = "files",
    srcs = [
        "Dockerfile",
        "Gemfile",
        "Gemfile.lock",
        "config.ru",
        "index.rb",
    ],
)

Tarball(
    name = "tar",
    entries = [
        TarballEntry(
            srcs = [
                "Dockerfile",
                "Gemfile",
                "Gemfile.lock",
                "config.ru",
                "index.rb",
            ],
            strip_prefix = "third_party/gvisor/benchmarks/workloads/ruby",
        ),
    ],
)
