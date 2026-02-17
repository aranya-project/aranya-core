# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.18.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.17.2...aranya-fast-channels-v0.18.0) - 2026-02-17

### Other

- use shared rng and make engine shared ([#563](https://github.com/aranya-project/aranya-core/pull/563))

## [0.17.2](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.17.1...aranya-fast-channels-v0.17.2) - 2026-01-23

### Other

- update to rust 1.90 ([#550](https://github.com/aranya-project/aranya-core/pull/550))

## [0.17.1](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.17.0...aranya-fast-channels-v0.17.1) - 2026-01-06

### Other

- updated the following local packages: aranya-crypto

## [0.17.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.16.0...aranya-fast-channels-v0.17.0) - 2025-12-11

### Other

- clean up dev profile and some feature sets ([#507](https://github.com/aranya-project/aranya-core/pull/507))
- Pass `OpenCtx` to client methods ([#485](https://github.com/aranya-project/aranya-core/pull/485))

## [0.16.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.15.0...aranya-fast-channels-v0.16.0) - 2025-11-12

### Other

- add `SealCtx` to fix `Seq` tracking ([#480](https://github.com/aranya-project/aranya-core/pull/480))

## [0.15.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.14.0...aranya-fast-channels-v0.15.0) - 2025-11-05

### Other

- Add channel direction to `RemoveIfParams` ([#466](https://github.com/aranya-project/aranya-core/pull/466))
- rename local channel ID ([#453](https://github.com/aranya-project/aranya-core/pull/453))

## [0.14.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.13.0...aranya-fast-channels-v0.14.0) - 2025-10-16

### Other

- Remove AFC Bidi channel related items ([#428](https://github.com/aranya-project/aranya-core/pull/428))
- rename `Id` to `BaseId` ([#329](https://github.com/aranya-project/aranya-core/pull/329))
- Remove AFC channel by peer and/or label ([#432](https://github.com/aranya-project/aranya-core/pull/432))
- Separate out crate for IDs ([#318](https://github.com/aranya-project/aranya-core/pull/318))
- Enforce More Clippy Lints ([#385](https://github.com/aranya-project/aranya-core/pull/385))

## [0.13.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.12.0...aranya-fast-channels-v0.13.0) - 2025-09-18

### Other

- generate `ChannelId`s internally ([#410](https://github.com/aranya-project/aranya-core/pull/410))

## [0.12.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.11.0...aranya-fast-channels-v0.12.0) - 2025-09-17

### Other

- update crate docs ([#408](https://github.com/aranya-project/aranya-core/pull/408))
- use label id in ffis and shm ([#383](https://github.com/aranya-project/aranya-core/pull/383))
- add serde impls to shm path ([#406](https://github.com/aranya-project/aranya-core/pull/406))
- Use more typed ids ([#368](https://github.com/aranya-project/aranya-core/pull/368))

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.10.0...aranya-fast-channels-v0.11.0) - 2025-08-19

### Other

- Format code in doc comments ([#341](https://github.com/aranya-project/aranya-core/pull/341))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.9.0...aranya-fast-channels-v0.10.0) - 2025-06-18

### Other

- update to `spideroak-crypto` v0.6 ([#300](https://github.com/aranya-project/aranya-core/pull/300))
- use derive-where for better derive bounds ([#297](https://github.com/aranya-project/aranya-core/pull/297))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.8.0...aranya-fast-channels-v0.9.0) - 2025-06-12

### Other

- migrate to Rust edition 2024 ([#254](https://github.com/aranya-project/aranya-core/pull/254))
- update to spideroak-crypto v0.5.x ([#263](https://github.com/aranya-project/aranya-core/pull/263))

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.7.0...aranya-fast-channels-v0.8.0) - 2025-05-28

### Other

- use workspace lints (#247)
- Use errno crate ([#246](https://github.com/aranya-project/aranya-core/pull/246))
- update to Rust 1.85 (#248)

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.6.0...aranya-fast-channels-v0.7.0) - 2025-05-15

### Other

- updated the following local packages: aranya-crypto

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.5.0...aranya-fast-channels-v0.6.0) - 2025-04-10

### Other

- updated the following local packages: aranya-crypto

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.4.0...aranya-fast-channels-v0.5.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-fast-channels-v0.3.0...aranya-fast-channels-v0.4.0) - 2025-03-11

### Other

- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
- update references from flow3-docs to aranya-docs ([#7](https://github.com/aranya-project/aranya-core/pull/7))
