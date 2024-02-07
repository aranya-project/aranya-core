# Aranya

`aranya` is the Rust library implementation for Aranya

# Building Aranya

MAC:
`cargo make build-code`
LINUX:
`cargo make --env FEATURES="posix" build-code`

# Running unit tests

From root:

`cargo make unit-tests`

# Correctness checks

From root:

`cargo make correctness`

# Formatting code

From root:

`cargo make fmt`
