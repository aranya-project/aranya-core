use alloc::{
    format,
    string::{String, ToString},
};

use serde::{Deserialize, Serialize};

use crate::Prior;

crypto::custom_id! {
    /// An ID constructed as a cryptographic hash of a serialized [`Command`].
    pub struct Id;
}

impl Id {
    /// Derives an [`Id`] from some data.
    ///
    /// This is for testing only. It's not `#[cfg(test)]` because
    /// (unfortunately) some code already depends on it.
    pub fn hash_for_testing_only(data: &[u8]) -> Self {
        use crypto::{hash::Hash, rust::Sha512};
        Sha512::hash(data).into_array().into()
    }

    pub fn short_b58(&self) -> String {
        #![allow(clippy::arithmetic_side_effects)]
        let b58 = self.to_string();
        let trimmed = b58.trim_start_matches('1');
        let len = trimmed.len();
        if len == 0 {
            "1".into()
        } else if len > 8 {
            format!("..{}", &trimmed[len - 6..])
        } else {
            trimmed.into()
        }
    }
}

#[cfg(test)]
impl From<u32> for Id {
    fn from(init: u32) -> Self {
        let mut value = [0u8; 64];
        value[60..].copy_from_slice(&init.to_be_bytes());
        Id(value.into())
    }
}

#[cfg(test)]
impl From<u64> for Id {
    fn from(init: u64) -> Self {
        let mut value = [0u8; 64];
        value[56..].copy_from_slice(&init.to_be_bytes());
        Id(value.into())
    }
}

/// Identify how the client will sort the associated [`Command`].
// Note: Order of variants affects derived Ord: Merge is least and Init is greatest.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Indicates two branches in the parent graph have been merged at this
    /// command. A command with this priority must have two parents,
    /// `Parent::Merge`.
    Merge,
    /// Indicates a user-specific action; the runtime uses the internal u32
    /// for ordering.
    Basic(u32),
    /// Indicates all preceding commands are ancestors of this command.
    Finalize,
    /// Indicates state is initialized; the associated command is a common
    /// ancestor to all other commands in the graph. A command with this
    /// priority must have no parents, `Parent::None`.
    Init,
}

/// An action message interpreted by its associated policy to affect state.
///
/// A [`Command`] is opaque to the runtime engine. When the engine receives a
/// message, it is validated and serialized by its policy. The policy
/// returns a command implementation to update the stored graph. A
/// policy will also emit effects once a command is verified,
/// which are sent to the client.
pub trait Command {
    /// Return this command's [`Priority`], determining how this event is
    /// ordered amongst others it does not have a causal relationship with.
    fn priority(&self) -> Priority;

    /// Uniquely identifies the serialized command.
    fn id(&self) -> Id;

    /// Return this command's parents, or command(s) that immediately
    /// precede(s) this.
    fn parent(&self) -> Prior<Id>;

    /// Return this command's associated policy.
    fn policy(&self) -> Option<&[u8]>;

    /// Return this command's serialized data.
    fn bytes(&self) -> &[u8];
}

impl<C: Command> Command for &C {
    fn priority(&self) -> Priority {
        (*self).priority()
    }

    fn id(&self) -> Id {
        (*self).id()
    }

    fn parent(&self) -> Prior<Id> {
        (*self).parent()
    }

    fn policy(&self) -> Option<&[u8]> {
        (*self).policy()
    }

    fn bytes(&self) -> &[u8] {
        (*self).bytes()
    }
}

/// A Command with an associated max cut. Max cut is the maximum distance from
/// the command to the init command.
pub trait MaxCut {
    /// Return this command's max cut. Max cut is the maximum distance to the init command.
    fn max_cut(&self) -> usize;
}

impl<M: MaxCut> MaxCut for &M {
    fn max_cut(&self) -> usize {
        (*self).max_cut()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn priority_ordering() {
        assert!(Priority::Merge < Priority::Basic(0));
        assert!(Priority::Basic(0) < Priority::Basic(1));
        assert!(Priority::Basic(1) < Priority::Basic(u32::MAX));
        assert!(Priority::Basic(u32::MAX) < Priority::Finalize);
        assert!(Priority::Finalize < Priority::Init);
    }
}
