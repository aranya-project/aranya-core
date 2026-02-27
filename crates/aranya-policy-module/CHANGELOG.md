# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.18.1](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.18.0...aranya-policy-module-v0.18.1) - 2026-02-17

### Other

- updated the following local packages: aranya-policy-ast

## [0.18.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.17.0...aranya-policy-module-v0.18.0) - 2026-01-23

### Other

- abstract out `compile_function_like` ([#533](https://github.com/aranya-project/aranya-core/pull/533))

## [0.17.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.16.0...aranya-policy-module-v0.17.0) - 2026-01-06

### Other

- add return expression ([#501](https://github.com/aranya-project/aranya-core/pull/501))

## [0.16.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.15.0...aranya-policy-module-v0.16.0) - 2025-12-11

### Other

- allow nested option ([#502](https://github.com/aranya-project/aranya-core/pull/502))
- remove `Typeish` and `NullableVType` ([#486](https://github.com/aranya-project/aranya-core/pull/486))

## [0.15.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.14.0...aranya-policy-module-v0.15.0) - 2025-11-05

### Other

- fix code map ([#472](https://github.com/aranya-project/aranya-core/pull/472))
- use tagged ID type ([#327](https://github.com/aranya-project/aranya-core/pull/327))
- Close #420: Replace infix arithmetic operators with checked and saturating internal functions. ([#435](https://github.com/aranya-project/aranya-core/pull/435))

## [0.14.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.13.0...aranya-policy-module-v0.14.0) - 2025-10-16

### Other

- rename `Id` to `BaseId` ([#329](https://github.com/aranya-project/aranya-core/pull/329))
- Enforce More Clippy Lints ([#385](https://github.com/aranya-project/aranya-core/pull/385))
- Implement `rkyv` traits for policy modules ([#344](https://github.com/aranya-project/aranya-core/pull/344))

## [0.13.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.12.0...aranya-policy-module-v0.13.0) - 2025-09-17

### Other

- add `NamedMap` and def types for action and command ([#387](https://github.com/aranya-project/aranya-core/pull/387))
- add location info to all AST items ([#366](https://github.com/aranya-project/aranya-core/pull/366))
- Use more typed ids ([#368](https://github.com/aranya-project/aranya-core/pull/368))

## [0.12.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.11.0...aranya-policy-module-v0.12.0) - 2025-08-19

### Other

- Close #193: Allow a struct to be cast to another struct with the same schema ([#261](https://github.com/aranya-project/aranya-core/pull/261))
- Format code in doc comments ([#341](https://github.com/aranya-project/aranya-core/pull/341))
- short circuit for boolean operators ([#349](https://github.com/aranya-project/aranya-core/pull/349))
- improve keystore typed ID usage ([#361](https://github.com/aranya-project/aranya-core/pull/361))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.10.0...aranya-policy-module-v0.11.0) - 2025-06-18

### Other

- use custom types for identifiers and text ([#231](https://github.com/aranya-project/aranya-core/pull/231))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.9.0...aranya-policy-module-v0.10.0) - 2025-06-12

### Other

- Close #115: Support enums in ffi ([#244](https://github.com/aranya-project/aranya-core/pull/244))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.8.0...aranya-policy-module-v0.9.0) - 2025-05-28

### Other

- updated the following local packages: aranya-crypto

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.7.0...aranya-policy-module-v0.8.0) - 2025-05-15

### Other

- Close #194: Allow enums in key values. ([#222](https://github.com/aranya-project/aranya-core/pull/222))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.6.0...aranya-policy-module-v0.7.0) - 2025-04-21

### Other

- Add struct subselection ([#120](https://github.com/aranya-project/aranya-core/pull/120))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.5.0...aranya-policy-module-v0.6.0) - 2025-04-10

### Other

- updated the following local packages: aranya-crypto, aranya-policy-ast

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.4.0...aranya-policy-module-v0.5.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-module-v0.3.0...aranya-policy-module-v0.4.0) - 2025-03-11

### Other

- Close #73: Change enum representation to be orderable ([#95](https://github.com/aranya-project/aranya-core/pull/95))
- Publish multiple commands ([#16](https://github.com/aranya-project/aranya-core/pull/16))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
