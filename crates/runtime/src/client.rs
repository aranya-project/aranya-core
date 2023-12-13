use alloc::{
    collections::{BTreeMap, BinaryHeap, VecDeque},
    vec::Vec,
};
use core::{fmt, marker::PhantomData};

use buggy::{Bug, BugExt};

use crate::{
    Command, Engine, EngineError, Id, Location, Perspective, Policy, PolicyId, Prior, Priority,
    Segment, Sink, Storage, StorageError, StorageProvider, SyncError, SyncState,
    MAX_COMMAND_LENGTH,
};

#[derive(Debug)]
pub enum ClientError {
    NoSuchParent(Id),
    EngineError(EngineError),
    StorageError(StorageError),
    InitError,
    NotAuthorized,
    SyncError,
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
        payload: &E::Payload,
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

    pub fn transaction(&mut self, storage_id: &Id) -> Transaction<SP, E> {
        Transaction::new(*storage_id)
    }

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
            .get_linear_perspective(&parent)?
            .assume("can always get perspective at head")?;

        let policy_id = perspective.policy();
        let policy = self.engine.get_policy(&policy_id)?;

        let checkpoint = perspective.checkpoint();

        sink.begin();
        let result = policy.call_action(&parent, action, &mut perspective, sink);

        match result {
            Ok(_) => {
                let segment = storage.write(perspective)?;
                storage.commit(segment)?;
                sink.commit();
            }
            Err(_e) => {
                perspective.revert(checkpoint);
                sink.rollback();
                return Err(ClientError::NotAuthorized);
            }
        }
        Ok(())
    }

    /// Provide access to the storage provider (mostly for tests)
    #[cfg(test)]
    pub(crate) fn provider(&mut self) -> &mut SP {
        &mut self.provider
    }
}

pub struct Transaction<SP: StorageProvider, E> {
    /// The ID of the associated storage
    storage_id: Id,
    /// Current working perspective
    perspective: Option<SP::Perspective>,
    /// Head of the current perspective
    phead: Option<Id>,
    /// Written but not committed heads
    heads: BTreeMap<Id, Location>,
    /// Tag for associated engine
    _engine: PhantomData<E>,
}

impl<SP: StorageProvider, E: Engine> Transaction<SP, E> {
    fn new(storage_id: Id) -> Self {
        Self {
            storage_id,
            perspective: None,
            phead: None,
            heads: BTreeMap::new(),
            _engine: PhantomData,
        }
    }

    fn commit(
        &mut self,
        provider: &mut SP,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<(), ClientError> {
        let storage = provider.get_storage(&self.storage_id)?;

        // Write pending perspective
        if let Some(p) = self.perspective.take() {
            self.phead = None;
            let segment = storage.write(p)?;
            self.heads
                .insert(segment.head().id(), segment.head_location());
        }

        let current_head = storage.get_head()?;
        for (id, location) in &self.heads {
            if id == &storage.get_command_id(&current_head)? {
                continue;
            }
            let segment = storage.get_segment(location)?;
            if !storage.is_ancestor(&current_head, &segment)? {
                self.heads
                    .insert(storage.get_command_id(&current_head)?, current_head);
                break;
            }
        }

        // Merge heads pairwise until single head left, then commit.
        // TODO(jdygert): Better pairings?
        let mut heads: VecDeque<_> = core::mem::take(&mut self.heads).into_iter().collect();
        while let Some((left_id, left_loc)) = heads.pop_front() {
            if let Some((right_id, right_loc)) = heads.pop_front() {
                let (policy, policy_id) = choose_policy(storage, engine, &left_loc, &right_loc)?;

                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let command = policy.merge(&mut buffer, left_id, right_id)?;

                let braid =
                    make_braid_segment::<_, E>(storage, &left_loc, &right_loc, sink, policy)?;

                let perspective = storage
                    .new_merge_perspective(&command, policy_id, braid)?
                    .assume("trx heads should exist in storage")?;

                let segment = storage.write(perspective)?;

                heads.push_back((segment.head().id(), segment.head_location()));
            } else {
                let segment = storage.get_segment(&left_loc)?;
                storage.commit(segment)?;
            }
        }

        Ok(())
    }

    /// Attempt to store the `command` in the graph with `storage_id`. Effects will be
    /// emitted to the `sink`. This interface is used when syncing with another device
    /// and integrating the new commands.
    fn add_commands<'a>(
        &mut self,
        commands: &[impl Command<'a>],
        provider: &mut SP,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<bool, ClientError> {
        let mut commands = commands.iter();
        // Get storage or try to initialize with first command.
        let storage = match provider.get_storage(&self.storage_id) {
            Ok(s) => s,
            Err(StorageError::NoSuchStorage) => {
                let command = commands.next().ok_or(ClientError::InitError)?;
                self.init(command, engine, provider, sink)?
            }
            Err(e) => return Err(e.into()),
        };
        // Handle remaining commands.
        for command in commands {
            if storage.get_location(&command.id())?.is_some() {
                // Command already added.
                continue;
            }
            match command.parent() {
                Prior::None => {
                    // This init command must have the wrong ID.
                }
                Prior::Single(parent) => {
                    self.add_message(storage, engine, sink, command, parent)?;
                }
                Prior::Merge(left, right) => {
                    self.add_merge(storage, engine, sink, command, left, right)?;
                }
            };
        }
        Ok(true)
    }

    fn add_message<'a>(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
        command: &impl Command<'a>,
        parent: Id,
    ) -> Result<(), ClientError> {
        let perspective = self.get_perspective(parent, storage)?;

        let policy_id = perspective.policy();
        let policy = engine.get_policy(&policy_id)?;

        sink.begin();
        let checkpoint = perspective.checkpoint();
        if !policy.call_rule(command, perspective, sink)? {
            perspective.revert(checkpoint);
            sink.rollback();
            return Err(ClientError::NotAuthorized);
        }
        perspective.add_command(command)?;
        sink.commit();

        self.phead = Some(command.id());

        Ok(())
    }

    fn add_merge<'a>(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
        command: &impl Command<'a>,
        left: Id,
        right: Id,
    ) -> Result<bool, ClientError> {
        if let Some(p) = self.perspective.take() {
            let seg = storage.write(p)?;
            self.heads.insert(seg.head().id(), seg.head_location());
        }

        let left_loc = storage
            .get_location(&left)?
            .ok_or(ClientError::NoSuchParent(left))?;
        let right_loc = storage
            .get_location(&right)?
            .ok_or(ClientError::NoSuchParent(right))?;

        let (policy, policy_id) = choose_policy(storage, engine, &left_loc, &right_loc)?;

        let braid = make_braid_segment::<_, E>(storage, &left_loc, &right_loc, sink, policy)?;

        let perspective = storage
            .new_merge_perspective(command, policy_id, braid)?
            .assume(
                "we already found left and right locations above and we only call this with merge command",
            )?;

        self.heads.remove(&left);
        self.heads.remove(&right);

        self.perspective = Some(perspective);
        self.phead = Some(command.id());

        Ok(true)
    }

    fn get_perspective(
        &mut self,
        parent: Id,
        storage: &mut <SP as StorageProvider>::Storage,
    ) -> Result<&mut <SP as StorageProvider>::Perspective, ClientError> {
        if self.phead == Some(parent) {
            // Command will append to current perspective.
            return Ok(self
                .perspective
                .as_mut()
                .assume("trx has perspective when has phead")?);
        }

        // Write out the perspective and get a new one
        if let Some(p) = self.perspective.take() {
            self.phead.take();
            let seg = storage.write(p)?;
            self.heads.insert(seg.head().id(), seg.head_location());
        }

        let p = self.perspective.insert(
            storage
                .get_linear_perspective(&parent)?
                .ok_or(ClientError::NoSuchParent(parent))?,
        );

        self.phead = Some(parent);
        self.heads.remove(&parent);

        Ok(p)
    }

    fn init<'cmd, 'sp>(
        &mut self,
        command: &impl Command<'cmd>,
        engine: &mut E,
        provider: &'sp mut SP,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<&'sp mut <SP as StorageProvider>::Storage, ClientError> {
        if self.storage_id != command.id() {
            return Err(ClientError::InitError);
        }
        let Some(policy_data) = command.policy() else {
            return Err(ClientError::InitError);
        };
        let policy_id = engine.add_policy(policy_data)?;
        let policy = engine.get_policy(&policy_id)?;
        let storage_id = command.id();
        let mut perspective = provider.new_perspective(&policy_id);
        sink.begin();
        if !policy.call_rule(command, &mut perspective, sink)? {
            sink.rollback();
            return Err(ClientError::NotAuthorized);
        }
        perspective.add_command(command)?;
        provider.new_storage(&storage_id, perspective)?;
        sink.commit();
        Ok(provider.get_storage(&self.storage_id)?)
    }
}

fn make_braid_segment<S: Storage, E: Engine>(
    storage: &mut S,
    left: &Location,
    right: &Location,
    sink: &mut impl Sink<E::Effects>,
    policy: &E::Policy,
) -> Result<S::FactIndex, ClientError> {
    let order = braid(storage, left, right)?;

    let (first, rest) = order.split_first().assume("braid is non-empty")?;

    let mut braid_perspective = storage.get_fact_perspective(first)?;

    sink.begin();

    for location in rest {
        let segment = storage.get_segment(location)?;
        let command = segment
            .get_command(location)
            .assume("braid only contains existing commands")?;
        if !policy.call_rule(&command, &mut braid_perspective, sink)? {
            sink.rollback();
            return Err(ClientError::NotAuthorized);
        }
    }

    let braid = storage.write_facts(braid_perspective)?;

    sink.commit();

    Ok(braid)
}

fn choose_policy<'a, E: Engine>(
    storage: &impl Storage,
    engine: &'a E,
    left: &Location,
    right: &Location,
) -> Result<(&'a E::Policy, PolicyId), ClientError> {
    Ok(core::cmp::max_by_key(
        get_policy(storage, engine, left)?,
        get_policy(storage, engine, right)?,
        |(p, _)| p.serial(),
    ))
}

fn get_policy<'a, E: Engine>(
    storage: &impl Storage,
    engine: &'a E,
    location: &Location,
) -> Result<(&'a E::Policy, PolicyId), ClientError> {
    let segment = storage.get_segment(location)?;
    let policy_id = segment.policy();
    let policy = engine.get_policy(&policy_id)?;
    Ok((policy, policy_id))
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
