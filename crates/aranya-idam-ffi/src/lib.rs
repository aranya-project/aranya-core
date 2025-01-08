//! Identity and Access Management (IdAM) for Aranya.
//!
//! # Design
//!
//! Aranya's IdAM system is written in our proprietary language
//! for policy code. The language syntax and logic is described
//! in the [policy lang] spec, while an in-depth explanation of
//! the policy that makes up Aranya's IdAM system can be found
//! in the [default policy].
//!
//! Aranya's IdAM code makes use of several external functions
//! belonging to other modules, which are callable by the policy
//! via a foreign function interface (FFI) of the APIs made
//! available by a particular module. For details on the
//! cryptographic APIs used by IdAM, see [IDAM crypto].
//!
// TODO: Once the idam_crypto doc gets open sourced this link should be updated. <https://github.com/aranya-project/aranya-docs/issues/17>
//! [IDAM crypto]: <https://git.spideroak-inc.com/spideroak-inc/aranya-docs/blob/idam-crypto-apis/src/idam_crypto.md>
//! [default policy]: <https://github.com/aranya-project/aranya/blob/main/crates/aranya-daemon/src/policy.md>
//! [policy lang]: <https://github.com/aranya-project/aranya-docs/blob/main/src/policy-v1.md>

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![warn(missing_docs)]

mod error;
mod ffi;
pub mod testing;
mod tests;

pub use ffi::*;
