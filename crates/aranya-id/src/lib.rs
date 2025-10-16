//! IDs and generation of [`custom_id`] types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![warn(missing_docs)]

mod id;

#[doc(inline)]
pub use crate::id::{BaseId, Id, IdTag, ParseIdError};

#[doc(hidden)]
pub mod __hidden {
    pub use ::paste::paste;

    pub use crate::id::Sealed;
}
