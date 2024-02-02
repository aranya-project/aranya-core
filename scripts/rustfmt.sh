#!/bin/sh

# You can use this in place of rustfmt, for your editor's formatter.
#
# VSCode:
#     "rust-analyzer.rustfmt.overrideCommand": [ "${workspaceFolder}/scripts/rustfmt.sh" ],

set -eu

base=$(realpath "$0/../../")
nightly=$(cat "$base/rust-nightly.txt")

rustup run "$nightly" true || rustup toolchain install "$nightly" >/dev/null
rustup run "$nightly" rustfmt "$@"
