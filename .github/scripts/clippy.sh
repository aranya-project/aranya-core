#!/usr/bin/env bash
set -xeuo pipefail

if command -v shellcheck &>/dev/null; then
    shellcheck "${0}"
fi

# Iterate over crates found in the working directory and run clippy on each,
# separately. Running clippy separately on crates ensures that features are
# not pulled in when compiling the entire workspace. (see:
# https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)
# `mindepth` and `maxdepth` ensures we are looking in a single level, aren't
# finding the working directory itself ('.').
# `-type d` means we are only looking for directories.
# `sed 's|^\./||g` replaces instances of './' with ''.
for crate in $(find . -mindepth 1 -maxdepth 1 -type d | sed 's|^\./||g'); do
    cargo clippy -p "$crate" -- -Dwarnings
    cargo clippy -p "$crate" --tests --benches -- -Dwarnings
    cargo clippy -p "$crate" --no-default-features -- -Dwarnings
done
