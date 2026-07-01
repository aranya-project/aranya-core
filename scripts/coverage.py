#!/usr/bin/env python3
#
# Branch-coverage reports, split into four buckets. This file is the single
# source of truth for which crate belongs to which report.
#
#   coverage.py local <bucket>   run the instrumented suite, print one bucket's table
#   coverage.py ci               run the suite once, emit txt+html+lcov per bucket
#
# Buckets:
#   capi       - the C API tooling / codegen layer
#   tools      - developer-facing binaries (policy-runner)
#   compiler   - the policy source -> module pipeline
#   core-prod  - everything else that ships
#
# A handful of crates exist only to exercise other crates (test/dev harnesses).
# They are scored in no bucket, but still run as part of the suite and credit
# their coverage to the crates they exercise (e.g. aranya-capi-codegen-test ->
# aranya-capi-codegen, aranya-model -> aranya-runtime).

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# --- crate -> bucket mapping (single source of truth) -----------------------

BUCKETS = {
    "capi": [
        "aranya-capi-core",
        "aranya-capi-codegen",
        "aranya-capi-macro",
    ],
    "tools": [
        "aranya-policy-runner",
    ],
    "compiler": [
        "aranya-policy-compiler",
        "aranya-policy-lang",
        "aranya-policy-ast",
        "aranya-policy-module",
    ],
    "core-prod": [
        "aranya-afc-util",
        "aranya-core",
        "aranya-crypto",
        "aranya-crypto-ffi",
        "aranya-device-ffi",
        "aranya-envelope-ffi",
        "aranya-fast-channels",
        "aranya-id",
        "aranya-idam-ffi",
        "aranya-libc",
        "aranya-perspective-ffi",
        "aranya-policy-derive",
        "aranya-policy-ifgen",
        "aranya-policy-ifgen-build",
        "aranya-policy-ifgen-macro",
        "aranya-policy-text",
        "aranya-policy-text-macro",
        "aranya-policy-vm",
        "aranya-runtime",
        "aranya-tcp-syncer",
    ],
}

# Test/dev harnesses, scored in no bucket. Listed so the union below spans the
# whole workspace -- that is how we know what to ignore for a given bucket.
EXCLUDED_CRATES = [
    "aranya-capi-codegen-test",
    "aranya-core-example",
    "aranya-model",
    "aranya-policy-vm-explorer",
]

# Every crate in the workspace, in a stable order (bucket order, then the
# excluded harnesses). Dict insertion order is guaranteed, so this matches the
# order the buckets are declared above.
ALL_CRATES = [c for crates in BUCKETS.values() for c in crates] + EXCLUDED_CRATES

# `cargo +nightly llvm-cov` -- nightly + llvm-tools-preview are required for
# branch coverage; see the install-* tasks in Makefile.toml.
LLVM_COV = ["cargo", "+nightly", "llvm-cov"]


def ignore_regex_for(bucket: str) -> str:
    """Build the ``--ignore-filename-regex`` for a bucket.

    The regex matches the source path of every crate that is *not* in the
    bucket, so llvm-cov drops those files and the report is left with only the
    bucket's crates. (llvm-cov has no positive "include" filter.)

    The value is one big alternation -- one ``/crates/<name>/`` term per
    non-bucket crate, OR-ed together with ``|``. For the ``capi`` bucket it
    looks like::

        /crates/aranya-policy-runner/|/crates/aranya-policy-compiler/|...
    """
    keep = set(BUCKETS[bucket])
    return "|".join(f"/crates/{c}/" for c in ALL_CRATES if c not in keep)


# --- modes ------------------------------------------------------------------


def run_local(bucket: str) -> None:
    """Run the instrumented suite and print one bucket's per-file table."""
    subprocess.run(
        [*LLVM_COV, "--branch", "--ignore-filename-regex", ignore_regex_for(bucket)],
        check=True,
    )


def run_ci() -> None:
    """Instrument and run the whole suite once, then report per bucket from the
    stored profdata (avoids rebuilding/retesting four times over)."""
    out = Path("target/llvm-cov")
    subprocess.run([*LLVM_COV, "--branch", "--no-report"], check=True)
    out.mkdir(parents=True, exist_ok=True)
    for bucket in BUCKETS:
        ignore = ignore_regex_for(bucket)
        bucket_dir = out / bucket
        bucket_dir.mkdir(parents=True, exist_ok=True)
        report = [*LLVM_COV, "report", "--branch", "--ignore-filename-regex", ignore]
        # Per-file branch coverage table (the data); also echo to the build log.
        result = subprocess.run(report, check=True, stdout=subprocess.PIPE, text=True)
        (bucket_dir / "coverage.txt").write_text(result.stdout)
        sys.stdout.write(result.stdout)
        # Browsable HTML report (the chart) -> <bucket_dir>/html/index.html.
        subprocess.run(report + ["--html", "--output-dir", str(bucket_dir)], check=True)
        # Machine-readable lcov for downstream tooling.
        subprocess.run(
            report + ["--lcov", "--output-path", str(bucket_dir / "lcov.info")],
            check=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Per-bucket branch coverage reports.",
    )
    modes = parser.add_subparsers(dest="mode", required=True)

    local = modes.add_parser(
        "local", help="run the suite, print one bucket's table"
    )
    local.add_argument("bucket", choices=list(BUCKETS), help="which bucket to report")

    modes.add_parser("ci", help="run the suite once, emit txt+html+lcov per bucket")

    args = parser.parse_args()
    if args.mode == "local":
        run_local(args.bucket)
    else:
        run_ci()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as err:
        # A cargo/llvm-cov step failed; surface its exit code (like `set -e`).
        sys.exit(err.returncode)
