# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of aranya-msg-ffi
- Message encryption and group key management functions moved from aranya-idam-ffi
- Functions: generate_group_key, seal_group_key, open_group_key, encrypt_message, decrypt_message
- Types: StoredGroupKey, SealedGroupKey