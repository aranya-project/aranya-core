# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when
working with code in this repository.

## Overview

`aranya-core` contains Aranya's core Rust libraries and tooling.
It provides libraries for building secure distributed systems
with Aranya policy enforcement. This is a cargo workspace
containing multiple crates for storage (DAG and FactDB),
cryptography, sync engine, policy VM, and runtime client, plus
Aranya Fast Channels (AFC) for encrypted peer-to-peer
communication.

## Build System & Common Commands

This project uses `cargo-make` as the primary task runner. You
must be in the root directory to run tasks.

### Essential Commands

```bash
# List all available tasks
cargo make

# Build the project
cargo make build-code

# Run all unit tests
cargo make unit-tests

# Run correctness checks (formatting, linting, feature checks)
cargo make correctness

# Format all code
cargo make fmt

# Security checks (audit, deny, vet)
cargo make security
```

### Testing Commands

```bash
# Run tests for all features
cargo make unit tests

# Run tests for a specific crate
cargo test -p aranya-crypto

# Run tests with specific features
cargo test --no-default-features

# Run tests faster on Linux (use tmpfs to avoid slow fsync)
# If /tmp is not already tmpfs, mount one:
#   sudo mkdir -p /mnt/tmpfs && sudo mount -t tmpfs tmpfs /mnt/tmpfs
TMPDIR=/mnt/tmpfs cargo test -p aranya-runtime
```

### Linting & Quality

```bash
# Run all linting and quality tests.
cargo make correctness

# Run clippy on all targets and feature combinations
cargo make clippy

# Check feature compatibility
cargo make check-features

# Check no-std/no-alloc support
cargo make check-canaries

# Format check without making changes
cargo make check-fmt
```

## Architecture Overview

### Core Components

**Runtime (`aranya-runtime/`)**: Main integration point providing
high-level interface to Engine, StorageProvider, and sync
capabilities. Handles graph commands, policy enforcement, and
peer synchronization.

**Crypto (`aranya-crypto/`)**: Centralized cryptography engine
supporting multiple cipher suites. Implements AEAD, key
management, HPKE, and various other cryptographic primitives.

**Policy VM (`aranya-policy-vm/`)**: Virtual machine for
executing Aranya policies. Works with policy compiler and AST
modules to enforce access control rules.

**Fast Channels (`aranya-fast-channels/`)**: High-throughput,
low-latency encryption for out-of-band data streams using
client-daemon model with shared memory backend.

### Policy System

- **Policy Language (`aranya-policy-lang/`)**: Parser and
  compiler for policy definitions written in custom DSL
- **Policy Compiler (`aranya-policy-compiler/`)**: Compiles
  policy source to bytecode for VM execution
- **Policy AST (`aranya-policy-ast/`)**: Abstract syntax tree
  representation for policy parsing
- Multiple `*-ffi` crates provide policy FFI bindings for
  specific modules.

### FFI & Language Bindings

- **CAPI Codegen (`aranya-capi-codegen/`)**: Generates C API
  bindings from Rust code using build scripts
- **CAPI Core (`aranya-capi-core/`)**: Core types and utilities
  for C interop

### Storage & Sync

- **Storage**: Linear storage implementation with DAG support.
- **Sync**: Bidirectional synchronization between peers using
  QUIC transport.
- **Memory management**: Shared memory implementations for
  high-performance scenarios.

## Development Practices

### Rust Configuration

- **Toolchain**: Specified in `rust-toolchain.toml`.
- **Profiles**: Multiple build profiles including
  `release-small`, `dev-std`, `release-std`.
- **No-std support**: Many crates support `no_std` environments,
  validated by canary crates.

### Code Quality Standards

- Clippy linting with custom rules in `clippy.toml`.
- Comprehensive security checks via `cargo-deny`, `cargo-audit`,
  `cargo-vet`.
- Strict linting: arithmetic side effects warnings, unwrap/panic
  restrictions.
- Feature compatibility testing across all crate feature
  combinations.

### Testing Strategy

- Unit tests in each crate with `makers unit-tests`.
- Integration tests in `tests/` directories.
- Property-based testing using `proptest`.
- No-std/no-alloc validation via canary crates.
- Security and supply chain auditing.

### FFI Development

When working with FFI crates, use `capi-codegen` rather than
writing manual bindings. The codegen operates from build scripts
and generates both Rust boilerplate and C headers.
