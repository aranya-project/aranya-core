#!/usr/bin/env bash

set -euo pipefail

here="$(dirname "${BASH_SOURCE[0]}")"
cd "$here"

this="$(basename "${BASH_SOURCE[0]}")"
input=policy.pest
output=keywords.rs

cat <<EOF > "$output"
// This file contains the extracted keywords from $input by $this

pub const KEYWORDS: &[&str] = &[
$(
    grep -v '//' "$input" | # Filter out comments
    grep -oE '"\w{2,}"' |   # Extract quoted words
    sort --ignore-case |    # Sort keywords
    uniq |                  # Deduplicate
    sed 's/.*/    &,/'      # Indent and add comma
)
];
EOF
