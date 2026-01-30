# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.18.0...aranya-runtime-v0.19.0) - 2026-01-23

### Other

- rename `storage_id` to `graph_id` ([#546](https://github.com/aranya-project/aranya-core/pull/546))
- add graph ID to more of protocol ([#543](https://github.com/aranya-project/aranya-core/pull/543))
- update to rust 1.90 ([#550](https://github.com/aranya-project/aranya-core/pull/550))
- remove server address from protocol ([#541](https://github.com/aranya-project/aranya-core/pull/541))
- rename policy engine to policy store ([#519](https://github.com/aranya-project/aranya-core/pull/519))

## [0.18.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.17.0...aranya-runtime-v0.18.0) - 2026-01-06

### Other

- Give a trace error when the action is not found ([#516](https://github.com/aranya-project/aranya-core/pull/516))

## [0.17.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.16.1...aranya-runtime-v0.17.0) - 2025-12-11

### Other

- 473 sync failures ([#511](https://github.com/aranya-project/aranya-core/pull/511))
- Low mem ([#491](https://github.com/aranya-project/aranya-core/pull/491))

## [0.16.1](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.16.0...aranya-runtime-v0.16.1) - 2025-11-12

### Other

- updated the following local packages: aranya-policy-vm

## [0.16.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.15.0...aranya-runtime-v0.16.0) - 2025-11-05

### Other

- Change hello subscription to use Duration types and add schedule_delay ([#461](https://github.com/aranya-project/aranya-core/pull/461))
- use tagged ID type ([#327](https://github.com/aranya-project/aranya-core/pull/327))
- Close #420: Replace infix arithmetic operators with checked and saturating internal functions. ([#435](https://github.com/aranya-project/aranya-core/pull/435))
- require command priority ([#354](https://github.com/aranya-project/aranya-core/pull/354))

## [0.15.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.14.0...aranya-runtime-v0.15.0) - 2025-10-16

### Other

- rename `Id` to `BaseId` ([#329](https://github.com/aranya-project/aranya-core/pull/329))
- Separate out crate for IDs ([#318](https://github.com/aranya-project/aranya-core/pull/318))
- clean up VM policy command protocol ([#426](https://github.com/aranya-project/aranya-core/pull/426))
- Enforce More Clippy Lints ([#385](https://github.com/aranya-project/aranya-core/pull/385))

## [0.14.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.13.0...aranya-runtime-v0.14.0) - 2025-09-18

### Other

- check persistence when calling actions ([#380](https://github.com/aranya-project/aranya-core/pull/380))

## [0.13.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.12.0...aranya-runtime-v0.13.0) - 2025-09-17

### Other

- add duration to hello subscription ([#404](https://github.com/aranya-project/aranya-core/pull/404))
- clean up API ([#403](https://github.com/aranya-project/aranya-core/pull/403))
- clean up calling interface and check context ([#388](https://github.com/aranya-project/aranya-core/pull/388))
- add `NamedMap` and def types for action and command ([#387](https://github.com/aranya-project/aranya-core/pull/387))
- add sync hello to dispatcher ([#372](https://github.com/aranya-project/aranya-core/pull/372))
- Use more typed ids ([#368](https://github.com/aranya-project/aranya-core/pull/368))

## [0.12.0](https://github.com/aranya-project/aranya-core/compare/aranya-runtime-v0.11.0...aranya-runtime-v0.12.0) - 2025-08-19

### Other

- update `yoke@0.8.0` ([#325](https://github.com/aranya-project/aranya-core/pull/325))
- fix syncing with multiple messages ([#345](https://github.com/aranya-project/aranya-core/pull/345))
- Format code in doc comments ([#341](https://github.com/aranya-project/aranya-core/pull/341))
- remove unused method `MachineIO::publish` ([#367](https://github.com/aranya-project/aranya-core/pull/367))
- improve type checking of None and Indeterminate ([#321](https://github.com/aranya-project/aranya-core/pull/321))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))

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
