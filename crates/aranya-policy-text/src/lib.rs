//! Aranya Policy Lang's textual types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod error;
mod ident;
mod proptest_impls;
mod repr;
mod text;

pub use error::{InvalidIdentifier, InvalidText};
pub use ident::Identifier;
pub use text::Text;

#[doc(hidden)]
pub mod __hidden {
    pub use aranya_policy_text_macro::{validate_identifier, validate_text};
}
