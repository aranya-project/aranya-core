# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.4.0...aranya-capi-core-v0.4.1) - 2025-05-28

### Other

- fix `Opaque` use-after-free (#252)
- update to Rust 1.85 (#248)

## [0.4.0](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.3.0...aranya-capi-core-v0.4.0) - 2025-05-15

### Other

- make opaque types an exact size and alignment ([#239](https://github.com/aranya-project/aranya-core/pull/239))
- remove `Safe` `Alias` impl ([#226](https://github.com/aranya-project/aranya-core/pull/226))
- (capi-codegen) Restrict return types ([#214](https://github.com/aranya-project/aranya-core/pull/214))

## [0.3.0](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.2.3...aranya-capi-core-v0.3.0) - 2025-04-21

### Other

- updated the following local packages: aranya-libc

## [0.2.3](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.2.2...aranya-capi-core-v0.2.3) - 2025-04-10

### Other

- (capi-codegen) Implement ByMutPtr trait for Arrays ([#205](https://github.com/aranya-project/aranya-core/pull/205))

## [0.2.2](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.2.1...aranya-capi-core-v0.2.2) - 2025-04-07

### Other

- updated the following local packages: aranya-capi-macro

## [0.2.1](https://aranya.github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.2.0...aranya-capi-core-v0.2.1) - 2025-03-21

### Other

- Allow`Option<&T>` for fn args

## [0.2.0](https://github.com/aranya-project/aranya-core/compare/aranya-capi-core-v0.1.0...aranya-capi-core-v0.2.0) - 2025-03-11

### Other

- Migrate Errors to `thiserror` ([#68](https://github.com/aranya-project/aranya-core/pull/68))
- use `buggy` instead of `aranya-buggy` ([#81](https://github.com/aranya-project/aranya-core/pull/81))
