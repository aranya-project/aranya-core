# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.7.0...aranya-policy-ast-v0.8.0) - 2025-09-17

### Other

- add location info to all AST items ([#366](https://github.com/aranya-project/aranya-core/pull/366))

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.6.0...aranya-policy-ast-v0.7.0) - 2025-08-19

### Other

- Close #193: Allow a struct to be cast to another struct with the same schema ([#261](https://github.com/aranya-project/aranya-core/pull/261))
- Add struct composition ([#116](https://github.com/aranya-project/aranya-core/pull/116))
- Add `ephemeral` keyword to actions and commands and enforce ephemeral/persistent rules at compile time. ([#338](https://github.com/aranya-project/aranya-core/pull/338))
- improve type checking of None and Indeterminate ([#321](https://github.com/aranya-project/aranya-core/pull/321))
- Close #186: Implement struct field insertion. ([#192](https://github.com/aranya-project/aranya-core/pull/192))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.5.0...aranya-policy-ast-v0.6.0) - 2025-06-18

### Other

- Fix new text crates ([#286](https://github.com/aranya-project/aranya-core/pull/286))
- use custom types for identifiers and text ([#231](https://github.com/aranya-project/aranya-core/pull/231))

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.4.1...aranya-policy-ast-v0.5.0) - 2025-06-12

### Other

- Close #115: Support enums in ffi ([#244](https://github.com/aranya-project/aranya-core/pull/244))

## [0.4.1](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.4.0...aranya-policy-ast-v0.4.1) - 2025-05-15

### Other

- Close #194: Allow enums in key values. ([#222](https://github.com/aranya-project/aranya-core/pull/222))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.3.0...aranya-policy-ast-v0.4.0) - 2025-04-21

### Other

- Add struct subselection ([#120](https://github.com/aranya-project/aranya-core/pull/120))

## [0.3.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.2.0...aranya-policy-ast-v0.3.0) - 2025-04-10

### Other

- Close [#110](https://github.com/aranya-project/aranya-core/pull/110): Add match expressions. ([#119](https://github.com/aranya-project/aranya-core/pull/119))

## [0.2.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-ast-v0.1.0...aranya-policy-ast-v0.2.0) - 2025-03-11

### Other

- More type checking ([#99](https://github.com/aranya-project/aranya-core/pull/99))
- Close #18: Switch policy lang support to V2.
- Implement Block Expressions ([#91](https://github.com/aranya-project/aranya-core/pull/91))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
