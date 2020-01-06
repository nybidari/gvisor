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
                "Gemfile",
                "Gemfile.lock",
                "config.ru",
                "index.erb",
                "main.rb",
            ],
            strip_prefix = "third_party/gvisor/benchmarks/workloads/ruby_template",
        ),
    ],
)
