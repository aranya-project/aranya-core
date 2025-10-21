# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.10.0...aranya-crypto-v0.11.0) - 2025-10-16

### Other

- Remove AFC Bidi channel related items ([#428](https://github.com/aranya-project/aranya-core/pull/428))
- rename `Id` to `BaseId` ([#329](https://github.com/aranya-project/aranya-core/pull/329))
- Separate out crate for IDs ([#318](https://github.com/aranya-project/aranya-core/pull/318))
- Enforce More Clippy Lints ([#385](https://github.com/aranya-project/aranya-core/pull/385))
- Implement `rkyv` traits for policy modules ([#344](https://github.com/aranya-project/aranya-core/pull/344))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.9.0...aranya-crypto-v0.10.0) - 2025-09-17

### Other

- use label id in ffis and shm ([#383](https://github.com/aranya-project/aranya-core/pull/383))
- simplify rustix `raw_os_error` handling ([#384](https://github.com/aranya-project/aranya-core/pull/384))
- Use more typed ids ([#368](https://github.com/aranya-project/aranya-core/pull/368))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.8.0...aranya-crypto-v0.9.0) - 2025-08-19

### Other

- Format code in doc comments ([#341](https://github.com/aranya-project/aranya-core/pull/341))
- improve keystore typed ID usage ([#361](https://github.com/aranya-project/aranya-core/pull/361))
- impl `Display` for keystore error kind ([#346](https://github.com/aranya-project/aranya-core/pull/346))
- make PSK IDs `repr(C)` ([#353](https://github.com/aranya-project/aranya-core/pull/353))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))
- do not use `stringify!(...)` as context for generating IDs ([#307](https://github.com/aranya-project/aranya-core/pull/307))

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.7.1...aranya-crypto-v0.8.0) - 2025-06-18

### Other

- "simplify" key pair creation ([#313](https://github.com/aranya-project/aranya-core/pull/313))
- add PSK importer ([#302](https://github.com/aranya-project/aranya-core/pull/302))
- update to `spideroak-crypto` v0.6 ([#300](https://github.com/aranya-project/aranya-core/pull/300))
- hide DhKemP256HkdfSha256 in private module ([#306](https://github.com/aranya-project/aranya-core/pull/306))
- use derive-where for better derive bounds ([#297](https://github.com/aranya-project/aranya-core/pull/297))
- encrypt PSK seeds for other devices ([#296](https://github.com/aranya-project/aranya-core/pull/296))
- add routines to compute label and role IDs ([#294](https://github.com/aranya-project/aranya-core/pull/294))
- cache computed IDs ([#285](https://github.com/aranya-project/aranya-core/pull/285))
- use `CS::tuple_hash` for merge ID ([#219](https://github.com/aranya-project/aranya-core/pull/219))

## [0.7.1](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.7.0...aranya-crypto-v0.7.1) - 2025-06-13

### Other

- patch release v0.7.1
- fix references to `__unwrapped_inner` ([#284](https://github.com/aranya-project/aranya-core/pull/284))
- add generic PSK type ([#279](https://github.com/aranya-project/aranya-core/pull/279))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.6.1...aranya-crypto-v0.7.0) - 2025-06-12

### Other

- migrate to Rust edition 2024 ([#254](https://github.com/aranya-project/aranya-core/pull/254))
- update base58 ([#270](https://github.com/aranya-project/aranya-core/pull/270))
- update to spideroak-crypto v0.5.x ([#263](https://github.com/aranya-project/aranya-core/pull/263))
- clean up dependencies ([#251](https://github.com/aranya-project/aranya-core/pull/251))
- impl `Hash` for `CipherSuiteId` and rename serde repr ([#257](https://github.com/aranya-project/aranya-core/pull/257))

## [0.6.1](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.6.0...aranya-crypto-v0.6.1) - 2025-05-28

### Other

- update to Rust 1.85 (#248)

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.5.0...aranya-crypto-v0.6.0) - 2025-05-15

### Other

- pair PSKs with cipher suites ([#238](https://github.com/aranya-project/aranya-core/pull/238))
- Switch to 32 byte IDs ([#220](https://github.com/aranya-project/aranya-core/pull/220))

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.4.0...aranya-crypto-v0.5.0) - 2025-04-10

### Other

- implement aranya-crypto support, FFI, handler (#184)

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.3.0...aranya-crypto-v0.4.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.3.0](https://github.com/aranya-project/aranya-core/compare/aranya-crypto-v0.2.1...aranya-crypto-v0.3.0) - 2025-03-11

### Other

- remove ciphersuite ID ([#93](https://github.com/aranya-project/aranya-core/pull/93))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- remove `aranya-crypto-core` and `aranya-crypto-derive` ([#76](https://github.com/aranya-project/aranya-core/pull/76))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
- Remove trouble crate ([#64](https://github.com/aranya-project/aranya-core/pull/64))
- update references from flow3-docs to aranya-docs ([#7](https://github.com/aranya-project/aranya-core/pull/7))
- move low level crypto into `aranya-crypto-core` ([#34](https://github.com/aranya-project/aranya-core/pull/34))
- clean up SHA-3 code ([#91](https://github.com/aranya-project/aranya-core/pull/91))
