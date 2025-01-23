use alloc::{collections::BinaryHeap, vec::Vec};
use core::fmt;

use aranya_buggy::{Bug, BugExt};
use tracing::trace;

use crate::{
    Command, CommandId, Engine, EngineError, GraphId, Location, PeerCache, Perspective, Policy,
    Prior, Priority, Segment, Sink, Storage, StorageError, StorageProvider,
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

impl core::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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
        let policy = self.engine.get_policy(policy_id)?;

        let mut perspective = self.provider.new_perspective(policy_id);
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
        trx.commit(&mut self.provider, &mut self.engine, sink)?;
        Ok(())
    }

    /// Add commands to the transaction, writing the results to
    /// `sink`.
    /// Returns the number of commands that were added.
    pub fn add_commands(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effect>,
        commands: &[impl Command],
    ) -> Result<usize, ClientError> {
        let count = trx.add_commands(commands, &mut self.provider, &mut self.engine, sink)?;
        Ok(count)
    }

    pub fn update_heads(
        &mut self,
        storage_id: GraphId,
        commands: &[impl Command],
        request_heads: &mut PeerCache,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;
        for command in commands {
            if let Some(loc) = storage.get_location(command.address()?)? {
                request_heads.add_command(storage, command.address()?, loc)?;
            }
        }
        Ok(())
    }

    /// Performs an `action`, writing the results to `sink`.
    pub fn action(
        &mut self,
        storage_id: GraphId,
        sink: &mut impl Sink<E::Effect>,
        action: <E::Policy as Policy>::Action<'_>,
    ) -> Result<(), ClientError> {
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;

        let mut perspective = storage
            .get_linear_perspective(head)?
            .assume("can always get perspective at head")?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(policy_id)?;

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
    pub fn transaction(&mut self, storage_id: GraphId) -> Transaction<SP, E> {
        Transaction::new(storage_id)
    }

    /// Create an ephemeral [`Session`] associated with this client.
    pub fn session(&mut self, storage_id: GraphId) -> Result<Session<SP, E>, ClientError> {
        Session::new(&mut self.provider, storage_id)
    }
}

/// Returns the last common ancestor of two Locations.
///
/// This walks the graph backwards until the two locations meet. This
/// ensures that you can jump to the last common ancestor from
/// the merge command created using left and right and know that you
/// won't be jumping into a branch.
fn last_common_ancestor<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
) -> Result<(Location, usize), ClientError> {
    trace!(%left, %right, "finding least common ancestor");
    let mut left = left;
    let mut right = right;
    while left != right {
        let left_seg = storage.get_segment(left)?;
        let left_cmd = left_seg.get_command(left).assume("location must exist")?;
        let right_seg = storage.get_segment(right)?;
        let right_cmd = right_seg.get_command(right).assume("location must exist")?;
        // The command with the lower max cut could be our least common ancestor
        // so we keeping following the command with the higher max cut until
        // both sides converge.
        if left_cmd.max_cut()? > right_cmd.max_cut()? {
            left = if let Some(previous) = left.previous() {
                previous
            } else {
                match left_seg.prior() {
                    Prior::None => left,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        assert!(left.command == 0);
                        if let Some((l, _)) = left_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *l
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok((left, left_cmd.max_cut()?));
                        }
                    }
                }
            };
        } else {
            right = if let Some(previous) = right.previous() {
                previous
            } else {
                match right_seg.prior() {
                    Prior::None => right,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        assert!(right.command == 0);
                        if let Some((r, _)) = right_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *r
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok((right, right_cmd.max_cut()?));
                        }
                    }
                }
            };
        }
    }
    let left_seg = storage.get_segment(left)?;
    let left_cmd = left_seg.get_command(left).assume("location must exist")?;
    Ok((left, left_cmd.max_cut()?))
}

/// Enforces deterministic ordering for a set of [`Command`]s in a graph.
/// Returns the ordering.
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
            cached_segment: Option<S>,
        ) -> Result<Self, ClientError> {
            let segment = cached_segment.map_or_else(|| storage.get_segment(location), Ok)?;

            let key = {
                let cmd = segment
                    .get_command(location)
                    .ok_or(StorageError::CommandOutOfBounds(location))?;
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

    let mut braid = Vec::new();
    let mut strands = BinaryHeap::new();

    trace!(%left, %right, "braiding");

    for head in [left, right] {
        strands.push(Strand::new(storage, head, None)?);
    }

    // Get latest command
    while let Some(strand) = strands.pop() {
        // Consume another command off the strand
        let (prior, mut maybe_cached_segment) = if let Some(previous) = strand.next.previous() {
            (Prior::Single(previous), Some(strand.segment))
        } else {
            (strand.segment.prior(), None)
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
            strands.push(Strand::new(
                storage,
                location,
                // Taking is OK here because `maybe_cached_segment` is `Some` when
                // the current strand has a single parent that is in the same segment
                Option::take(&mut maybe_cached_segment),
            )?);
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
