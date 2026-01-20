# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.10.0...aranya-policy-lang-v0.11.0) - 2026-01-06

### Other

- add return expression ([#501](https://github.com/aranya-project/aranya-core/pull/501))

## [0.10.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.9.0...aranya-policy-lang-v0.10.0) - 2025-12-11

### Other

- add custom error for `+` and `-` ops ([#508](https://github.com/aranya-project/aranya-core/pull/508))
- allow nested option ([#502](https://github.com/aranya-project/aranya-core/pull/502))
- format pest grammar with leading alternates ([#509](https://github.com/aranya-project/aranya-core/pull/509))
- improve parser testing ([#489](https://github.com/aranya-project/aranya-core/pull/489))
- split type checking and instruction generation ([#500](https://github.com/aranya-project/aranya-core/pull/500))
- add alternative parsing `option[T]` ([#499](https://github.com/aranya-project/aranya-core/pull/499))
- switch parser snapshots to simplified debug repr ([#492](https://github.com/aranya-project/aranya-core/pull/492))
- define math as builtin functions ([#439](https://github.com/aranya-project/aranya-core/pull/439))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.8.1...aranya-policy-lang-v0.9.0) - 2025-11-05

### Other

- Close #420: Replace infix arithmetic operators with checked and saturating internal functions. ([#435](https://github.com/aranya-project/aranya-core/pull/435))

## [0.8.1](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.8.0...aranya-policy-lang-v0.8.1) - 2025-10-16

### Other

- Enforce More Clippy Lints ([#385](https://github.com/aranya-project/aranya-core/pull/385))

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.7.0...aranya-policy-lang-v0.8.0) - 2025-09-17

### Other

- reduce public API ([#386](https://github.com/aranya-project/aranya-core/pull/386))
- add location info to all AST items ([#366](https://github.com/aranya-project/aranya-core/pull/366))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.6.0...aranya-policy-lang-v0.7.0) - 2025-08-19

### Other

- Close #193: Allow a struct to be cast to another struct with the same schema ([#261](https://github.com/aranya-project/aranya-core/pull/261))
- Add struct composition ([#116](https://github.com/aranya-project/aranya-core/pull/116))
- short circuit for boolean operators ([#349](https://github.com/aranya-project/aranya-core/pull/349))
- Add `ephemeral` keyword to actions and commands and enforce ephemeral/persistent rules at compile time. ([#338](https://github.com/aranya-project/aranya-core/pull/338))
- improve type checking of None and Indeterminate ([#321](https://github.com/aranya-project/aranya-core/pull/321))
- Fix #332: Show corect line number for errors in policy chunks. ([#340](https://github.com/aranya-project/aranya-core/pull/340))
- use rustfmt 2024 style ([#256](https://github.com/aranya-project/aranya-core/pull/256))
- Close #186: Implement struct field insertion. ([#192](https://github.com/aranya-project/aranya-core/pull/192))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.5.0...aranya-policy-lang-v0.6.0) - 2025-06-18

### Other

- use custom types for identifiers and text ([#231](https://github.com/aranya-project/aranya-core/pull/231))

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.4.2...aranya-policy-lang-v0.5.0) - 2025-06-12

### Other

- Close #115: Support enums in ffi ([#244](https://github.com/aranya-project/aranya-core/pull/244))

## [0.4.2](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.4.1...aranya-policy-lang-v0.4.2) - 2025-05-28

### Other

- update to Rust 1.85 (#248)

## [0.4.1](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.4.0...aranya-policy-lang-v0.4.1) - 2025-05-15

### Other

- updated the following local packages: aranya-policy-ast

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.3.0...aranya-policy-lang-v0.4.0) - 2025-04-21

### Other

- Add struct subselection ([#120](https://github.com/aranya-project/aranya-core/pull/120))

## [0.3.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.2.0...aranya-policy-lang-v0.3.0) - 2025-04-10

### Other

- allow block expressions in `if` expressions. (#176)
- Close [#110](https://github.com/aranya-project/aranya-core/pull/110): Add match expressions. ([#119](https://github.com/aranya-project/aranya-core/pull/119))

## [0.2.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-lang-v0.1.0...aranya-policy-lang-v0.2.0) - 2025-03-11

### Other

- More type checking ([#99](https://github.com/aranya-project/aranya-core/pull/99))
- Update syntax for "Some" optional literals ([#126](https://github.com/aranya-project/aranya-core/pull/126))
- Close #18: Switch policy lang support to V2.
- Implement Block Expressions ([#91](https://github.com/aranya-project/aranya-core/pull/91))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
