# Aranya Core

Aranya is lovingly crafted and supported by [SpiderOak](https://spideroak.com/).
Aranya is licensed under the [AGPL](LICENSE.md)- if you want to use it
commercially, drop us a line!

## What's Contained In This Repo

This repo is a cargo workspace for the Rust implementation for the core of the
Aranya platform. This is a library that includes the storage module (for DAG
and FactDB), crypto module (with default crypto engine automatically selected),
sync engine, and runtime client (including policy VM).

It also includes [Aranya Fast Channels](crates/aranya-fast-channels/) to enable
encrypted channels between 2 peers allowing unidirectional communication.

More documentation on Aranya is provided here:
[Aranya Documentation](https://aranya-project.github.io/aranya-docs/).

## Get Started

Aranya Core is written in Rust. Additionally, this repo contains tools for our
C API wrappers. The full list of dependencies is below.

### Dependencies

- [Rust](https://www.rust-lang.org/tools/install) (Find version info in the
[rust-toolchain.toml](rust-toolchain.toml))
> NOTE: When building with Rust, rustup will automatically download and
> use the version specified by the `rust-toolchain.toml`.
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation) (v0.37.23)

> NOTE: we have tested using the specified versions above. Other versions of
> these tools may also work.

### Install `cargo-make`

This repo uses `cargo-make` as a task runner.

```
cargo install cargo-make --locked
```

### Usage

`cargo-make` can be used as a cargo plugin via `cargo make <task>` or directly as `makers <task>`.

Note that you must be in the root directory of the repo to run tasks. To view all tasks, run `cargo make` or see [`Makefile.toml`](Makefile.toml).

```sh
# lists all tasks
makers

# auto-format files
makers fmt

# run all unit tests
makers unit-tests

# run correctness checks
makers correctness
```

## Contributing

Find information on contributing to the Aranya project in
[`CONTRIBUTING.md`](https://github.com/aranya-project/.github/blob/main/CONTRIBUTING.md).

## Maintainers

This repository is maintained by software engineers employed at [SpiderOak](https://spideroak.com/)
