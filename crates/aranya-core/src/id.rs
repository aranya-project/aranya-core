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
//! [`FromStr`](core::str::FromStr), [`serde::Serialize`]/[`serde::Deserialize`],
//! [`rkyv::Archive`], and [`subtle::ConstantTimeEq`].

#[doc(inline)]
pub use aranya_id::{BaseId, Id, IdTag, ParseIdError};

#[doc(hidden)]
pub mod __hidden {
    pub use aranya_id::{
        __hidden::{Sealed, paste},
        Id, IdTag,
    };
}

/// Declares a new tagged [`Id`] type.
///
/// The generated type is a distinct alias of [`Id<Tag>`] with its own
/// zero-sized tag, so IDs of different kinds cannot be accidentally mixed.
///
/// # Example
///
/// ```
/// use aranya_core::id::custom_id;
///
/// custom_id! {
///     /// Identifies a device.
///     pub struct DeviceId;
/// }
/// ```
#[macro_export]
macro_rules! __aranya_core_custom_id {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $crate::id::__hidden::paste! {
            mod [< __private_ $name:snake >] {
                #[doc = "Tag for [`" $name "`][super::" $name "]"]
                pub struct [< $name Tag >];

                impl $crate::id::__hidden::Sealed for [< $name Tag >] {}
                impl $crate::id::__hidden::IdTag for [< $name Tag >] {
                    const __NAME: &str = stringify!($name);
                }
            }

            $(#[$meta])*
            $vis type $name = $crate::id::__hidden::Id<[< __private_ $name:snake >]::[< $name Tag >]>;
        }
    };
}

#[doc(inline)]
pub use crate::__aranya_core_custom_id as custom_id;
