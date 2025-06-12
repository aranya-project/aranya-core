# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.1](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.9.0...aranya-policy-compiler-v0.9.1) - 2025-06-12

### Other

- Close #115: Support enums in ffi ([#244](https://github.com/aranya-project/aranya-core/pull/244))

## [0.9.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.8.0...aranya-policy-compiler-v0.9.0) - 2025-05-28

### Other

- box error and refactor tests (#245)
- remove unused items (#241)

## [0.8.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.7.0...aranya-policy-compiler-v0.8.0) - 2025-05-15

### Other

- updated the following local packages: aranya-policy-ast, aranya-policy-module, aranya-policy-lang

## [0.7.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.6.0...aranya-policy-compiler-v0.7.0) - 2025-04-21

### Other

- Fix #168: Make sure function return types are actually defined. ([#213](https://github.com/aranya-project/aranya-core/pull/213))
- Add struct subselection ([#120](https://github.com/aranya-project/aranya-core/pull/120))

## [0.6.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.5.0...aranya-policy-compiler-v0.6.0) - 2025-04-10

### Other

- allow block expressions in `if` expressions. (#176)
- Close [#103](https://github.com/aranya-project/aranya-core/pull/103): `if`, `match` statements now limit scope to their blocks. ([#109](https://github.com/aranya-project/aranya-core/pull/109))
- Close [#110](https://github.com/aranya-project/aranya-core/pull/110): Add match expressions. ([#119](https://github.com/aranya-project/aranya-core/pull/119))

## [0.5.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.4.0...aranya-policy-compiler-v0.5.0) - 2025-03-19

### Other

- rename Aranya "user" to "device" ([#122](https://github.com/aranya-project/aranya-core/pull/122))

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-policy-compiler-v0.3.0...aranya-policy-compiler-v0.4.0) - 2025-03-11

### Other

- More type checking ([#99](https://github.com/aranya-project/aranya-core/pull/99))
- Update syntax for "Some" optional literals ([#126](https://github.com/aranya-project/aranya-core/pull/126))
- Close #73: Change enum representation to be orderable ([#95](https://github.com/aranya-project/aranya-core/pull/95))
- Close #18: Switch policy lang support to V2.
- Implement Block Expressions ([#91](https://github.com/aranya-project/aranya-core/pull/91))
- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
