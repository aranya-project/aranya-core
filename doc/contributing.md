---
title: Contributing
---
# `flow3-rs` Overview

`flow3-rs` mirrors in some ways its earlier [Go counterpart](https://github.com/spideroak-inc/flow3) in that it provides a C library interface to the Flow3 Policy Engine and Weave Engine. This repo is still heavily in-progress, so it does not yet form a coherent whole.

You will find:

- The skeletal C library under [src/](../src/) which includes [no_std support](../src/no_std.rs) and [memory management routines](../src/mmap.rs) for VxWorks.

- The Policy Engine v3 compiler, which lives in its own crate under [policy-lang](../src/policy-lang/src/) and currently lives in the `4-policy-parser` branch.

- The Weave Engine, which lives in [src/engine.rs](../src/engine.rs), its storage layer in [src/storage.rs](../src/storage.rs), and the memory storage implementation in [src/storage/mem_storage.rs](../src/storage/mem_storage.rs). All of this is currently in branch `moore_reference`.

# Releases

TBD

# Issues

`flow3-rs` repo issues can be viewed/created here:
[`flow3-rs` Issues](https://github.com/spideroak-inc/flow3-rs/issues)

Organization and tracking of these issues are done simultaneously with main Flow3 issues in the [Platform Scrum Project](https://github.com/orgs/spideroak-inc/projects/3).

Please refer to the [Flow3 Issues instructions](https://github.com/spideroak-inc/flow3/tree/main/doc/contributing.md#issues) for details on creating issues.

# PRs

Likewise, the [Flow3 PRs section](https://github.com/spideroak-inc/flow3/tree/main/doc/contributing.md#prs) and [Flow3 Reviewing PRs](https://github.com/spideroak-inc/flow3/tree/main/doc/contributing.md#reviewing-prs) describes details for creating and reviewing PRs.

# Coding Standards

The rust code in this repo follows the usual rusty ways of doing things. CI will enforce that commits are properly formatted with `rustfmt`.

Write tests using the standard Cargo tooling.

# Running Tests/Builds Locally

We're using standard Cargo-based tooling for builds and tests. Currently tests have to be run in each sub-crate since they are not dependents of the main library.

Due to the main library being a `no_std` project, tests for it have to be run with `cargo test --features std` to enable the `std` feature that the tests require.

# Continuous Integration

Github CI/CD is set up to run main library tests on several platforms.

# Development Environment

We recommend setting up some kind of editor tooling to annotate types, as it really helps with understanding the complexity of Rust's type system. Visual Studio Code has excellent Rust support and can be configured to show many helpful annotations.

# Platform Team

The flow3 repo is owned by the Platform team.
For more information about the Platform team, refer to:
[Platform Team](https://github.com/spideroak-inc/platform-meta)
