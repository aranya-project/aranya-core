# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.11.0...aranya-policy-vm-v0.12.0) - 2025-08-19

### Fixed

- fix update statement ([#370](https://github.com/aranya-project/aranya-core/pull/370))

### Other

- Close #193: Allow a struct to be cast to another struct with the same schema ([#261](https://github.com/aranya-project/aranya-core/pull/261))
- Add struct composition ([#116](https://github.com/aranya-project/aranya-core/pull/116))
- Format code in doc comments ([#341](https://github.com/aranya-project/aranya-core/pull/341))
- remove unused method `MachineIO::publish` ([#367](https://github.com/aranya-project/aranya-core/pull/367))
- remove `Typeish::Probably` and use `Never` type ([#347](https://github.com/aranya-project/aranya-core/pull/347))
- short circuit for boolean operators ([#349](https://github.com/aranya-project/aranya-core/pull/349))
- improve type checking of None and Indeterminate ([#321](https://github.com/aranya-project/aranya-core/pull/321))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))
- add `cfg_attr` for `bench` feature ([#304](https://github.com/aranya-project/aranya-core/pull/304))

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.10.0...aranya-policy-vm-v0.11.0) - 2025-06-18

### Other

- use custom types for identifiers and text ([#231](https://github.com/aranya-project/aranya-core/pull/231))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.9.0...aranya-policy-vm-v0.10.0) - 2025-06-12

### Other

- migrate to Rust edition 2024 ([#254](https://github.com/aranya-project/aranya-core/pull/254))
- Close #115: Support enums in ffi ([#244](https://github.com/aranya-project/aranya-core/pull/244))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.8.0...aranya-policy-vm-v0.9.0) - 2025-05-28

### Other

- box error and refactor tests (#245)

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.7.0...aranya-policy-vm-v0.8.0) - 2025-05-15

### Other

- Close #194: Allow enums in key values. ([#222](https://github.com/aranya-project/aranya-core/pull/222))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.6.0...aranya-policy-vm-v0.7.0) - 2025-04-21

### Other

- Add struct subselection ([#120](https://github.com/aranya-project/aranya-core/pull/120))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.5.0...aranya-policy-vm-v0.6.0) - 2025-04-10

### Other

- allow block expressions in `if` expressions. (#176)
- Close [#110](https://github.com/aranya-project/aranya-core/pull/110): Add match expressions. ([#119](https://github.com/aranya-project/aranya-core/pull/119))

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.4.0...aranya-policy-vm-v0.5.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-vm-v0.3.1...aranya-policy-vm-v0.4.0) - 2025-03-11

### Other

- More type checking ([#99](https://github.com/aranya-project/aranya-core/pull/99))
- Close #73: Change enum representation to be orderable ([#95](https://github.com/aranya-project/aranya-core/pull/95))
- Add VM benchmarking
- Close #18: Switch policy lang support to V2.
- Publish multiple commands ([#16](https://github.com/aranya-project/aranya-core/pull/16))
- Implement Block Expressions ([#91](https://github.com/aranya-project/aranya-core/pull/91))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
- update references from flow3-docs to aranya-docs ([#7](https://github.com/aranya-project/aranya-core/pull/7))
