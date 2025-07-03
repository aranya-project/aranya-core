//! [`Id`]s and generation of [`custom_id`] types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod id;

pub use spideroak_base58 as base58;

#[doc(inline)]
pub use crate::id::Id;

#[doc(hidden)]
pub mod __hidden {
    #[cfg(feature = "proptest")]
    pub use ::proptest;
    pub use ::serde;
    pub use ::subtle;
}
