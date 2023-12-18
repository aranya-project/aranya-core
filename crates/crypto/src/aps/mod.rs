//! Cryptography code for [APS].
//!
//! # Implementation Notes
//!
//! APS' policy works like this: channel secrets are created
//! inside of the policy action. The secrets are then added to
//! APS from inside the `finish` block.
//!
//! Unfortunately, the only way to move data from an action into
//! a `finish` block is by adding it to the command itself. In
//! other words, we have to somehow encrypt our HPKE context
//! such that only we can decrypt it.
//!
//! It's difficult to do this without obliterating [`Hpke`][crate::hpke::Hpke]'s
//! API. The current approach generates a random ephemeral key
//! and uses it to create the HPKE context. The ephemeral key is
//! then encrypted to ourself using HPKE and the encapsulation
//! and ciphertext are added to the command.
//!
//! [APS]: https://git.spideroak-inc.com/spideroak-inc/aps

mod bidi;
mod keys;
mod shared;
mod uni;

pub use bidi::*;
pub use keys::*;
pub use shared::RawKey;
pub use uni::*;

use crate::error::Error;

// This is different from the rest of the `crypto` API in that it
// allows users to directly access key material (`ChannelKeys`,
// `ChannelKey`). Unfortunately, we have to allow this since APS
// needs to store the raw key material.

impl Error {
    pub(crate) const fn same_user_id() -> Self {
        Self::InvalidArgument("same `UserId`")
    }
}
