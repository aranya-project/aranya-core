use alloc::{collections::BinaryHeap, vec::Vec};
use core::fmt;

use buggy::{Bug, BugExt};
use tracing::trace;

use crate::{
    Command, CommandId, Engine, EngineError, GraphId, Location, Perspective, Policy, Prior,
    Priority, Segment, Sink, Storage, StorageError, StorageProvider,
};

mod session;
mod transaction;

pub use self::{session::Session, transaction::Transaction};

/// An error returned by the runtime client.
#[derive(Debug)]
pub enum ClientError {
    NoSuchParent(CommandId),
    EngineError(EngineError),
    StorageError(StorageError),
    InitError,
    NotAuthorized,
    SessionDeserialize(postcard::Error),
    Bug(Bug),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchParent(id) => write!(f, "no such parent: {id}"),
            Self::EngineError(e) => write!(f, "engine error: {e}"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
            Self::InitError => write!(f, "init error"),
            Self::NotAuthorized => write!(f, "not authorized"),
            Self::SessionDeserialize(e) => write!(f, "session deserialize error: {e}"),
            Self::Bug(bug) => write!(f, "{bug}"),
        }
    }
}

impl trouble::Error for ClientError {
    fn source(&self) -> Option<&(dyn trouble::Error + 'static)> {
        match self {
            Self::EngineError(e) => Some(e),
            Self::StorageError(e) => Some(e),
            Self::Bug(e) => Some(e),
            _ => None,
        }
    }
}

impl From<EngineError> for ClientError {
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Check => Self::NotAuthorized,
            _ => Self::EngineError(error),
        }
    }
}

impl From<StorageError> for ClientError {
    fn from(error: StorageError) -> Self {
        ClientError::StorageError(error)
    }
}

impl From<Bug> for ClientError {
    fn from(error: Bug) -> Self {
        ClientError::Bug(error)
    }
}

/// Keeps track of client graph state.
///
/// - `E` should be an implementation of [`Engine`].
/// - `SP` should be an implementation of [`StorageProvider`].
#[derive(Debug)]
pub struct ClientState<E, SP> {
    engine: E,
    provider: SP,
}

impl<E, SP> ClientState<E, SP> {
    /// Creates a `ClientState`.
    pub const fn new(engine: E, provider: SP) -> ClientState<E, SP> {
        ClientState { engine, provider }
    }

    /// Provide access to the [`StorageProvider`].
    pub fn provider(&mut self) -> &mut SP {
        &mut self.provider
    }
}

impl<E, SP> ClientState<E, SP>
where
    E: Engine,
    SP: StorageProvider,
{
    /// Create a new graph (AKA Team). This graph will start with the initial policy
    /// provided which must be compatible with the engine E. The `payload` is the initial
    /// init message that will bootstrap the graph facts. Effects produced when processing
    /// the payload are emitted to the sink.
    pub fn new_graph(
        &mut self,
        policy_data: &[u8],
        action: <E::Policy as Policy>::Action<'_>,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<GraphId, ClientError> {
        let policy_id = self.engine.add_policy(policy_data)?;
        let policy = self.engine.get_policy(&policy_id)?;

        let mut perspective = self.provider.new_perspective(&policy_id);
        sink.begin();
        policy
            .call_action(action, &mut perspective, sink)
            .inspect_err(|_| sink.rollback())?;
        sink.commit();

        let (graph_id, _) = self.provider.new_storage(perspective)?;

        Ok(graph_id)
    }

    /// Commit the [`Transaction`] to storage, after merging all temporary heads.
    pub fn commit(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<(), ClientError> {
        trx.commit(&mut self.provider, &mut self.engine, sink)
    }

    /// Add commands to the transaction, writing the results to
    /// `sink`.
    pub fn add_commands(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
        commands: &[impl Command],
    ) -> Result<(), ClientError> {
        trx.add_commands(commands, &mut self.provider, &mut self.engine, sink)?;
        Ok(())
    }

    /// Performs an `action`, writing the results to `sink`.
    pub fn action(
        &mut self,
        storage_id: &GraphId,
        sink: &mut impl Sink<E::Effect>,
        action: <E::Policy as Policy>::Action<'_>,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;

        let mut perspective = storage
            .get_linear_perspective(head)?
            .assume("can always get perspective at head")?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(&policy_id)?;

        // No need to checkpoint the perspective since it is only for this action.
        // Must checkpoint once we add action transactions.

        sink.begin();
        match policy.call_action(action, &mut perspective, sink) {
            Ok(_) => {
                let segment = storage.write(perspective)?;
                storage.commit(segment)?;
                sink.commit();
                Ok(())
            }
            Err(e) => {
                sink.rollback();
                Err(e.into())
            }
        }
    }
}

impl<E, SP> ClientState<E, SP>
where
    SP: StorageProvider,
{
    /// Create a new [`Transaction`], used to receive [`Command`]s when syncing.
    pub fn transaction(&mut self, storage_id: &GraphId) -> Transaction<SP, E> {
        Transaction::new(*storage_id)
    }

    /// Create an ephemeral [`Session`] associated with this client.
    pub fn session(&mut self, storage_id: GraphId) -> Result<Session<SP, E>, ClientError> {
        Session::new(&mut self.provider, storage_id)
    }
}

/// Enforces deterministic ordering for a set of [`Command`]s in a graph.
pub fn braid<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
) -> Result<Vec<Location>, ClientError> {
    struct Strand<S> {
        key: (Priority, CommandId),
        next: Location,
        segment: S,
    }

    impl<S: Segment> Strand<S> {
        fn new(
            storage: &mut impl Storage<Segment = S>,
            location: Location,
        ) -> Result<Self, ClientError> {
            let segment = storage.get_segment(location)?;

            let key = {
                let cmd = segment
                    .get_command(location)
                    .ok_or_else(|| StorageError::CommandOutOfBounds(location))?;
                (cmd.priority(), cmd.id())
            };

            Ok(Strand {
                key,
                next: location,
                segment,
            })
        }
    }

    impl<S> Eq for Strand<S> {}
    impl<S> PartialEq for Strand<S> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
        }
    }
    impl<S> Ord for Strand<S> {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.key.cmp(&other.key).reverse()
        }
    }
    impl<S> PartialOrd for Strand<S> {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    let mut strands = BinaryHeap::<Strand<S::Segment>>::new();

    trace!(%left, %right, "braiding");

    for head in [left, right] {
        strands.push(Strand::new(storage, head)?);
    }

    let mut braid = Vec::new();

    // Get latest command
    while let Some(strand) = strands.pop() {
        // Consume another command off the strand
        let prior = if let Some(previous) = strand.next.previous() {
            Prior::Single(previous)
        } else {
            strand.segment.prior()
        };
        if matches!(prior, Prior::Merge(..)) {
            trace!("skipping merge command");
        } else {
            trace!("adding {}", strand.next);
            braid.push(strand.next);
        }

        // Continue processing prior if not accessible from other strands.
        'location: for location in prior {
            for other in &strands {
                trace!("checking {}", other.next);
                if (location.same_segment(other.next) && location.command <= other.next.command)
                    || storage.is_ancestor(location, &other.segment)?
                {
                    trace!("found ancestor");
                    continue 'location;
                }
            }

            trace!("strand at {location}");
            strands.push(Strand::new(storage, location)?);
        }
        if strands.len() == 1 {
            // No concurrency left, done.
            let next = strands.pop().assume("strands not empty")?.next;
            trace!("adding {}", strand.next);
            braid.push(next);
            break;
        }
    }

    braid.reverse();
    Ok(braid)
}
