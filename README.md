# flow3-rs

This repo is a cargo workspace for the Rust implementation for Aranya.

## Cargo Make

This repo uses `cargo-make` as a task runner.

### Install

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

### Tools


For Policy development, the [VSCode Policy extension](https://git.spideroak-inc.com/spideroak-inc/policy-lang-vscode-ext)
is available for installation. The extension provides syntax highlighting for
Policy code blocks in markdown files.

