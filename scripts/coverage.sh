#!/usr/bin/env bash
#
# Branch-coverage reports, split into four buckets. This file is the single
# source of truth for which crate belongs to which report.
#
#   coverage.sh local <bucket>   run the instrumented suite, print one bucket's table
#   coverage.sh ci               run the suite once, emit txt+html+lcov per bucket
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

set -euo pipefail

# --- crate -> bucket mapping (single source of truth) -----------------------

CAPI_CRATES="
aranya-capi-core
aranya-capi-codegen
aranya-capi-macro
"

TOOLS_CRATES="
aranya-policy-runner
"

COMPILER_CRATES="
aranya-policy-compiler
aranya-policy-lang
aranya-policy-ast
aranya-policy-module
"

CORE_PROD_CRATES="
aranya-afc-util
aranya-core
aranya-crypto
aranya-crypto-ffi
aranya-device-ffi
aranya-envelope-ffi
aranya-fast-channels
aranya-id
aranya-idam-ffi
aranya-libc
aranya-perspective-ffi
aranya-policy-derive
aranya-policy-ifgen
aranya-policy-ifgen-build
aranya-policy-ifgen-macro
aranya-policy-text
aranya-policy-text-macro
aranya-policy-vm
aranya-runtime
aranya-tcp-syncer
"

# Test/dev harnesses, scored in no bucket. Listed so the union below spans the
# whole workspace -- that is how we know what to ignore for a given bucket.
EXCLUDED_CRATES="
aranya-capi-codegen-test
aranya-core-example
aranya-model
aranya-policy-vm-explorer
"

ALL_CRATES="$CAPI_CRATES $TOOLS_CRATES $COMPILER_CRATES $CORE_PROD_CRATES $EXCLUDED_CRATES"

BUCKETS="capi tools compiler core-prod"

crates_for() {
	case "$1" in
		capi)      printf '%s' "$CAPI_CRATES" ;;
		tools)     printf '%s' "$TOOLS_CRATES" ;;
		compiler)  printf '%s' "$COMPILER_CRATES" ;;
		core-prod) printf '%s' "$CORE_PROD_CRATES" ;;
		*) echo "coverage.sh: unknown bucket '$1' (want: $BUCKETS)" >&2; exit 1 ;;
	esac
}

# Build the `--ignore-filename-regex` for a bucket: a regex matching the source
# path of every crate that is NOT in the bucket, so llvm-cov drops those files
# and the report is left with only the bucket's crates. (llvm-cov has no
# positive "include" filter, and the regex engine has no negative lookahead, so
# "keep only X" has to be written as "ignore the whole complement of X".)
#
# The value returned is one big alternation -- one term per non-bucket crate,
# OR-ed together with `|`. For the `capi` bucket it looks like:
#
#     /crates/aranya-policy-runner/|/crates/aranya-policy-compiler/|...|/crates/aranya-policy-vm-explorer/
#
# Each term `/crates/<crate>/` matches that crate's source directory:
#
#   /crates/  every workspace member lives under crates/, so this pins the match
#             to the crate directory itself.
#   <crate>/  the directory name plus a trailing slash, so the match spans the
#             whole component -- `aranya-core` does not also match
#             `aranya-core-example` (no slash after "core" there), likewise
#             aranya-policy-vm vs *-vm-explorer, aranya-id vs aranya-idam-ffi.
ignore_regex_for() {
	local keep re="" c
	# Space-pad the bucket's crate list ("<sp>name<sp>name<sp>...") so the glob
	# below can test membership against whole names -- the surrounding spaces
	# stop " $c " from matching a substring of a longer crate name.
	keep=" $(crates_for "$1" | tr '\n' ' ') "
	for c in $ALL_CRATES; do
		case "$keep" in
			*" $c "*) ;;  # in this bucket: keep it (do not ignore)
			# Not in the bucket: append this crate's term to the alternation.
			# `${re:+$re|}` expands to "<re>|" only when re is already non-empty,
			# which OR-joins the terms while leaving the first one without a
			# leading "|".
			*) re="${re:+$re|}/crates/$c/" ;;
		esac
	done
	printf '%s' "$re"
}

# --- modes ------------------------------------------------------------------

run_local() {
	local bucket="$1"
	cargo +nightly llvm-cov --branch \
		--ignore-filename-regex "$(ignore_regex_for "$bucket")"
}

run_ci() {
	local out=target/llvm-cov bucket ignore dir
	# Instrument and run the whole suite once; report per bucket from the
	# stored profdata (avoids rebuilding/retesting four times over).
	cargo +nightly llvm-cov --branch --no-report
	mkdir -p "$out"
	for bucket in $BUCKETS; do
		ignore="$(ignore_regex_for "$bucket")"
		dir="$out/$bucket"
		mkdir -p "$dir"
		# Per-file branch coverage table (the data); also echo to the build log.
		cargo +nightly llvm-cov report --branch \
			--ignore-filename-regex "$ignore" | tee "$dir/coverage.txt"
		# Browsable HTML report (the chart) -> <dir>/html/index.html.
		cargo +nightly llvm-cov report --branch \
			--ignore-filename-regex "$ignore" --html --output-dir "$dir"
		# Machine-readable lcov for downstream tooling.
		cargo +nightly llvm-cov report --branch \
			--ignore-filename-regex "$ignore" --lcov --output-path "$dir/lcov.info"
	done
}

case "${1:-}" in
	local) run_local "${2:?usage: coverage.sh local <bucket>}" ;;
	ci)    run_ci ;;
	*) echo "usage: coverage.sh {local <bucket>|ci}" >&2; exit 1 ;;
esac
