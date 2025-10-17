//! IDs and generation of [`custom_id`] types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![warn(missing_docs)]

mod id;

#[doc(inline)]
pub use crate::id::{BaseId, ParseIdError};

#[doc(hidden)]
pub mod __hidden {
    #[cfg(feature = "proptest")]
    pub use ::proptest;
    pub use ::serde;
    pub use ::spideroak_base58;
    pub use ::subtle;
}
