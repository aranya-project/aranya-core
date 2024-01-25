use alloc::{collections::BinaryHeap, vec::Vec};
use core::fmt;

use buggy::{Bug, BugExt};

use crate::{
    Command, Engine, EngineError, Id, Location, Perspective, Policy, Prior, Priority, Segment,
    Sink, Storage, StorageError, StorageProvider, SyncError, SyncState, MAX_COMMAND_LENGTH,
};

mod session;
mod transaction;

pub use self::{session::Session, transaction::Transaction};

#[derive(Debug)]
pub enum ClientError {
    NoSuchParent(Id),
    EngineError(EngineError),
    StorageError(StorageError),
    InitError,
    NotAuthorized,
    SyncError,
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
            Self::SyncError => write!(f, "sync error"),
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
        ClientError::EngineError(error)
    }
}

impl From<StorageError> for ClientError {
    fn from(error: StorageError) -> Self {
        ClientError::StorageError(error)
    }
}

impl From<SyncError> for ClientError {
    fn from(_error: SyncError) -> Self {
        ClientError::SyncError
    }
}

impl From<Bug> for ClientError {
    fn from(error: Bug) -> Self {
        ClientError::Bug(error)
    }
}

#[derive(Debug)]
pub struct ClientState<E, SP> {
    engine: E,
    provider: SP,
}

/// This implements the top level client. It takes several generic arguments
/// The `E` parameter is the Policy engine to use. It will be specific to a
/// specific set of actions `A`.
impl<E, SP> ClientState<E, SP>
where
    E: Engine,
    SP: StorageProvider,
{
    pub fn new(engine: E, provider: SP) -> ClientState<E, SP> {
        ClientState { engine, provider }
    }

    /// Create a new graph (AKA Team). This graph will start with the initial policy
    /// provided which must be compatible with the engine E. The `payload` is the initial
    /// init message that will bootstrap the graph facts. Effects produced when processing
    /// the payload are emitted to the sink.
    pub fn new_graph(
        &mut self,
        policy_data: &[u8],
        payload: <E::Policy as Policy>::Payload<'_>,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<Id, ClientError> {
        let policy_id = self.engine.add_policy(policy_data)?;
        let policy = self.engine.get_policy(&policy_id)?;

        let mut buffer = [0u8; MAX_COMMAND_LENGTH];
        let target = buffer.as_mut_slice();
        let command = policy.init(target, policy_data, payload)?;

        let storage_id = command.id();

        let mut trx = self.transaction(&storage_id);
        trx.add_commands(&[command], &mut self.provider, &mut self.engine, sink)?;
        self.commit(&mut trx, sink)?;

        Ok(storage_id)
    }

    /// Create a new [`Transaction`], used to receive commands when syncing.
    pub fn transaction(&mut self, storage_id: &Id) -> Transaction<SP, E> {
        Transaction::new(*storage_id)
    }

    /// Commit the [`Transaction`] to storage, after merging all temporary heads.
    pub fn commit(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<(), ClientError> {
        trx.commit(&mut self.provider, &mut self.engine, sink)
    }

    pub fn sync_poll(
        &mut self,
        syncer: &mut impl SyncState,
        target: &mut [u8],
    ) -> Result<usize, ClientError> {
        Ok(syncer.poll(target, &mut self.provider)?)
    }

    pub fn sync_receive(
        &mut self,
        trx: &mut Transaction<SP, E>,
        sink: &mut impl Sink<E::Effects>,
        syncer: &mut impl SyncState,
        message: &[u8],
    ) -> Result<(), ClientError> {
        if let Some(commands) = syncer.receive(message)? {
            trx.add_commands(&commands, &mut self.provider, &mut self.engine, sink)?;
        }
        Ok(())
    }

    pub fn action(
        &mut self,
        storage_id: &Id,
        sink: &mut impl Sink<E::Effects>,
        action: <E::Policy as Policy>::Actions<'_>,
    ) -> Result<(), ClientError> {
        // Get storage
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;

        let parent = storage.get_command_id(&head)?;

        // Get the perspective
        let mut perspective = storage
            .get_linear_perspective(&head)?
            .assume("can always get perspective at head")?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(&policy_id)?;

        // No need to checkpoint the perspective since it is only for this action.
        // Must checkpoint once we add action transactions.

        sink.begin();
        match policy.call_action(&parent, action, &mut perspective, sink) {
            Ok(true) => {
                let segment = storage.write(perspective)?;
                storage.commit(segment)?;
                sink.commit();
                Ok(())
            }
            Ok(false) => {
                sink.rollback();
                Err(ClientError::NotAuthorized)
            }
            Err(e) => {
                sink.rollback();
                Err(e.into())
            }
        }
    }

    /// Create an ephemeral [`Session`] associated with this client.
    pub fn session(&mut self, storage_id: Id) -> Result<Session<SP, E>, ClientError> {
        Session::new(&mut self.provider, storage_id)
    }

    /// Provide access to the storage provider (mostly for tests)
    #[cfg(test)]
    pub(crate) fn provider(&mut self) -> &mut SP {
        &mut self.provider
    }
}

pub fn braid<S: Storage>(
    storage: &mut S,
    left: &Location,
    right: &Location,
) -> Result<Vec<Location>, ClientError> {
    struct Strand<S> {
        key: (Priority, Id),
        next: Location,
        segment: S,
    }

    impl<S: Segment> Strand<S> {
        fn new(
            storage: &mut impl Storage<Segment = S>,
            location: Location,
        ) -> Result<Self, ClientError> {
            let segment = storage.get_segment(&location)?;

            let key = {
                let cmd = segment
                    .get_command(&location)
                    .ok_or_else(|| StorageError::CommandOutOfBounds(location.clone()))?;
                (cmd.priority(), cmd.id())
            };

            Ok(Strand {
                key,
                next: location,
                segment,
            })
        }

        fn previous(&mut self) -> Result<bool, ClientError> {
            if !self.next.previous() {
                return Ok(false);
            }
            let cmd = self
                .segment
                .get_command(&self.next)
                .assume("can walk backward along segment")?;
            self.key = (cmd.priority(), cmd.id());
            Ok(true)
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

    for head in [left, right] {
        strands.push(Strand::new(storage, head.clone())?);
    }

    let mut braid = Vec::new();

    // Get latest command
    while let Some(mut strand) = strands.pop() {
        braid.push(strand.next.clone());

        // Consume another command off the strand
        if strand.previous()? {
            // Add modified strand back to heap
            strands.push(strand);
        } else {
            let prior = strand.segment.prior();
            if matches!(prior, Prior::Merge(..)) {
                // Skip merge commands
                braid.pop();
            }

            // Strand done, add parents if needed
            'location: for location in prior {
                for other in &strands {
                    if storage.is_ancestor(&location, &other.segment)? {
                        continue 'location;
                    }
                }

                strands.push(Strand::new(storage, location)?);
            }
            if strands.len() == 1 {
                // No concurrency left, done.
                braid.push(strands.pop().assume("strands not empty")?.next);
                break;
            }
        }
    }

    braid.reverse();
    Ok(braid)
}
