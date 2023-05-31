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
    Message(u32),
}

/// Identify prior [`Command`](s).
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum Parent {
    None,
    Id(Id),
    Merge(Id, Id),
}

/// First 32-bytes of the cryptographic hash of a serialized [`Command`].
#[derive(Eq, Hash, PartialEq, Clone, Copy, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub struct Id([u8; 32]);
