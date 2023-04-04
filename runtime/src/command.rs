/// Action message trait.
///
/// This trait defines a `Command`, a type of message sent by clients,
/// containing an action that is verified by a [`Policy`]. State-change events,
/// known as facts, are produced if the action is validated and evaluated
/// successfully.
pub trait Command {
    /// Action payload, consumed by a policy.
    type PolicyData;
    /// Return this command's [`Priority`], determining how this event is
    /// ordered amongst others it does not have a causal relationship with.
    fn priority(&self) -> Priority;
    ///
    fn id(&self) -> Id;
    /// Return this command's [`Parent`], or commands that have a causal
    /// relationship with self.
    fn parent(&self) -> Parent;
    /// Return this command's associated [`Policy`].
    fn policy(&self) -> Option<&Self::PolicyData>;
}

/// Returned by a [`Command`] to order it amongst other commands that
/// do not have a direct relationship to it.
#[derive(Debug)]
pub enum Priority {
    /// Indicates state is initialized at this command, making it a common
    /// ancestor to all other commands in the parent graph.
    /// A command with this priority must have no parents, `Parent::None`.
    Init,
    /// Indicates two branches in the parent graph have been merged at this
    /// command.
    /// A command with this priority must have two parents, `Parent::Merge`.
    Merge,
    /// Indicates all preceding commands are ancestors of this command.
    Finalize,
    /// Indicates the command is a user-specific action, so the runtime
    /// must use the command's ID for ordering.
    Basic(u32),
}

/// Returned by a [`Command`] to identify preceding commands.
#[derive(Clone, Debug)]
pub enum Parent {
    None,
    Id(Id),
    Merge(Id, Id),
}

/// Identifies a [`Command`], using the cryptographic hash of the command.
#[derive(Eq, Hash, PartialEq, Clone, Copy, Ord, PartialOrd, Debug)]
pub struct Id([u8; 32]);
