use serde::{Deserialize, Serialize};

/// An action message interpreted by its associated [`Policy`] to affect state.
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
    /// Return this command's [`Parent`], or command(s) that immediately
    /// precede(s) this.
    fn parent(&self) -> Parent;
    /// Return this command's associated policy.
    fn policy(&self) -> Option<&[u8]>;
    /// Return this command's serialized data.
    fn bytes(&self) -> &[u8];
}

/// Identify how the engine will sort the associated [`Command`]. If a
/// command has `Priority::Message`, the engine will use the
/// variant's internal value to order the command.
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum Priority {
    /// Indicates state is initialized; the associated command is a common
    /// ancestor to all other commands in the graph. A command with this
    /// priority must have no parents, `Parent::None`.
    Init,
    /// Indicates two branches in the parent graph have been merged at this
    /// command. A command with this priority must have two parents,
    /// `Parent::Merge`.
    Merge,
    /// Indicates all preceding commands are ancestors of this command.
    Finalize,
    /// Indicates a user-specific action; the runtime uses the internal u32
    /// for ordering.
    Basic(u32),
}

/// Identify prior [`Command`](s).
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
// The `serde(untagged)` attribute causes Serde to serialize and
// deserialize this enum without specifying the variant. Serde
// uses the inner values to determine which variant is being represented.
// Since each `Parent` variant has a unique inner value, serde would be
// able to easily detect the represented variant. Making this enum
// untagged also makes test data human-readable and more concise.
#[cfg_attr(test, serde(untagged))]
pub enum Parent {
    None,
    Id(Id),
    Merge(Id, Id),
}

/// First 32-bytes of the cryptographic hash of a serialized [`Command`].
#[derive(Eq, Hash, PartialEq, Clone, Copy, Ord, PartialOrd, Debug, Serialize, Deserialize)]
// The `serde(from = "u64")` attribute causes serde to deserialize this
// type to a u64 and then converts it to an Id struct (`From<u64> for Id` must
// be implemented). This attribute is only used by tests. Representing an Id
// as a u64 is more human-readable and concise than the inner type as-written.
#[cfg_attr(test, serde(from = "u64"))]
pub struct Id([u8; 32]);

#[cfg(test)]
mod test {
    use super::Id;

    // Implements methods for the Id struct to be used in
    // testing.
    impl Id {
        pub fn new(val: [u8; 32]) -> Self {
            Self(val)
        }

        // The inner value of an Id should not be publicly accessible. This
        // method is implemented for test validation.
        pub fn into_inner(self) -> [u8; 32] {
            self.0
        }
    }

    // Serde requires this implementation to deserialize data as u64 to an Id.
    impl From<u64> for Id {
        fn from(init: u64) -> Self {
            let mut value: [u8; 32] = [0; 32];

            for (i, b) in init.to_be_bytes().iter_mut().enumerate() {
                value[i + 24] = *b;
            }
            Id(value)
        }
    }

    // Creates a readable version in case an error occurs pertaining to the Id.
    impl From<Id> for u64 {
        fn from(id: Id) -> Self {
            let mut id_buf: [u8; 8] = [0u8; 8];
            id_buf.copy_from_slice(&id.into_inner()[24..]);
            u64::from_be_bytes(id_buf)
        }
    }
}
