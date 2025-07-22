# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.10.0...aranya-runtime-v0.11.0) - 2025-06-18

### Other

- feature gate test protocol engine and ID test hashing ([#221](https://github.com/aranya-project/aranya-core/pull/221))
- use `CS::tuple_hash` for merge ID ([#219](https://github.com/aranya-project/aranya-core/pull/219))
- use custom types for identifiers and text ([#231](https://github.com/aranya-project/aranya-core/pull/231))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.9.0...aranya-runtime-v0.10.0) - 2025-06-12

### Other

- check for multiple finalize commands in braid ([#172](https://github.com/aranya-project/aranya-core/pull/172))
- remove_graph ([#268](https://github.com/aranya-project/aranya-core/pull/268))
- update base58 ([#270](https://github.com/aranya-project/aranya-core/pull/270))
- update to spideroak-crypto v0.5.x ([#263](https://github.com/aranya-project/aranya-core/pull/263))
- clean up dependencies ([#251](https://github.com/aranya-project/aranya-core/pull/251))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.8.0...aranya-runtime-v0.9.0) - 2025-05-28

### Other

- updated the following local packages: aranya-crypto, aranya-policy-vm, aranya-libc

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.7.0...aranya-runtime-v0.8.0) - 2025-05-15

### Other

- Switch to 32 byte IDs ([#220](https://github.com/aranya-project/aranya-core/pull/220))
- Close #194: Allow enums in key values. ([#222](https://github.com/aranya-project/aranya-core/pull/222))
- dedup dsl test list ([#217](https://github.com/aranya-project/aranya-core/pull/217))
- implement finalization priority ([#171](https://github.com/aranya-project/aranya-core/pull/171))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.6.0...aranya-runtime-v0.7.0) - 2025-04-21

### Fixed

- make linear storage checksum more portable ([#191](https://github.com/aranya-project/aranya-core/pull/191))

### Other

- Expose Graph IDs via StorageProvider ([#203](https://github.com/aranya-project/aranya-core/pull/203))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.5.0...aranya-runtime-v0.6.0) - 2025-04-10

### Other

- updated the following local packages: aranya-crypto, aranya-policy-vm

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.4.0...aranya-runtime-v0.5.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.3.0...aranya-runtime-v0.4.0) - 2025-03-11

### Other

- convert some `bug!`s to regular errors ([#124](https://github.com/aranya-project/aranya-core/pull/124))
- Add VM benchmarking
- update cache after commit ([#75](https://github.com/aranya-project/aranya-core/pull/75))
- Close #18: Switch policy lang support to V2.
- Publish multiple commands ([#16](https://github.com/aranya-project/aranya-core/pull/16))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- Remove limit on session command ([#85](https://github.com/aranya-project/aranya-core/pull/85))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
- update references from flow3-docs to aranya-docs ([#7](https://github.com/aranya-project/aranya-core/pull/7))
- open sync requests ([#57](https://github.com/aranya-project/aranya-core/pull/57))
