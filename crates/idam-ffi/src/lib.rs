//! Identity and Access Management (IdAM) for Aranya.
//!
//! # Design
//!
//! Aranya's IdAM system is written in our proprietary language
//! for policy code. The language syntax and logic is described
//! in the [policy lang] spec, while an in-depth explanation of
//! the policy that makes up Aranya's IdAM system can be found
//! in the [IDAM] spec.
//!
//! Aranya's IdAM code makes use of several external functions
//! belonging to other modules, which are callable by the policy
//! via a foreign function interface (FFI) of the APIs made
//! available by a particular module. For details on the
//! cryptographic APIs used by IdAM, see [IDAM crypto].
//!
//! [IDAM crypto]: https://github.com/spideroak-inc/flow3-docs/blob/37bfddf39c37ae258615e8bf2617432aaf8d453a/idam_crypto.md
//! [IDAM]: https://github.com/spideroak-inc/flow3-docs/blob/8bf06fdfdb4521f96892de9eff8c7b2908413ace/src/idam.md
//! [policy lang]: https://git.spideroak-inc.com/spideroak-inc/flow3-docs/blob/main/src/policy-v3.md

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::wildcard_imports,
    missing_docs
)]

mod error;
mod ffi;
pub mod testing;
mod tests;

pub use ffi::*;
