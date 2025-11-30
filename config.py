"""Configuration for building the Pulsar C++ client artifact bundle."""

# Default version to download if not specified
DEFAULT_VERSION = "3.8.0"

# Platform configurations
PLATFORMS = {
    "macos-arm64": {
        "triples": ["arm64-apple-macosx"],
        "candidates": [
            "macos-arm64.zip",
        ],
    },
    "macos-x64": {
        "triples": ["x86_64-apple-macosx"],
        "candidates": [
            "macos-x86_64.zip",
        ],
    },
   "linux-x64": {
       "triples": ["x86_64-unknown-linux-gnu"],
       "candidates": [
            "apk-x86_64/x86_64/apache-pulsar-client-dev-{v}-r0.apk"
       ],
   },
    "linux-arm64": {
        "triples": ["aarch64-unknown-linux-gnu"],
        "candidates": [
            "apk-arm64/aarch64/apache-pulsar-client-dev-{v}-r0.apk"
        ],
    },
    "windows-x64": {
        "triples": ["x86_64-unknown-windows-msvc"],
        "candidates": [
            "x64-windows-static.tar.gz",
        ],
    }
}

# Download base URLs
DOWNLOAD_BASES = [
    "https://downloads.apache.org/pulsar/pulsar-client-cpp-{v}/",
    "https://archive.apache.org/dist/pulsar/pulsar-client-cpp-{v}/",
]
