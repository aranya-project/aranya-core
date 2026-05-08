//! Tagged cryptographic identifiers.
//!
//! [`Id`] is a 32-byte, tag-parameterized identifier. The tag is a zero-sized
//! marker type that makes distinct ID kinds incompatible at the type level
//! while preserving a common byte representation. [`BaseId`] is the untagged
//! form used when only the bytes matter.
//!
//! New tagged ID types are declared with the [`custom_id!`] macro:
//!
//! ```
//! use aranya_core::id::custom_id;
//!
//! custom_id! {
//!     /// Identifies a team.
//!     pub struct TeamId;
//! }
//! ```
//!
//! Each [`Id`] serializes as base58 in human-readable formats and as raw
//! bytes in binary formats, and implements [`Display`](core::fmt::Display),
//! [`FromStr`](core::str::FromStr), `serde::Serialize`/`serde::Deserialize`,
//! `rkyv::Archive`, and `subtle::ConstantTimeEq`.

#[doc(inline)]
pub use aranya_id::{BaseId, Id, IdTag, ParseIdError, custom_id};
