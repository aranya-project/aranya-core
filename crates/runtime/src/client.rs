use alloc::{
    collections::{BTreeSet, BinaryHeap, VecDeque},
    vec::Vec,
};
use core::marker::PhantomData;

use super::*;

#[derive(Debug)]
pub enum ClientError {
    NoSuchParent(Id),
    ExtraStart(Id),
    UnknownCommand(Id),
    InitStorageMismatch,
    InternalError,
    EngineError,
    StorageError,
    Unreachable,
    InitError,
    NotAuthorized,
    CommandExists(Id),
    SyncError,
    HeadCount(usize),
}

#[derive(Debug)]
pub struct ClientState<E, SP>
where
    E: Engine,
    SP: StorageProvider,
{
    engine: E,
    provider: SP,
}

impl From<EngineError> for ClientError {
    fn from(_error: EngineError) -> Self {
        ClientError::EngineError
    }
}

impl From<StorageError> for ClientError {
    fn from(_error: StorageError) -> Self {
        ClientError::StorageError
    }
}

impl From<SyncError> for ClientError {
    fn from(_error: SyncError) -> Self {
        ClientError::SyncError
    }
}

/// This implements the top level client. It takes several generic arguments
/// The `E` parameter is the Policy engine to use. It will be specific to a
/// specific set of actions `A`. `T` is the commands of the protocol, with `K`,
///  and `V` being the types of the fact keys and values from the perspective of
/// the Storage engine `S`.
impl<E, SP, A> ClientState<E, SP>
where
    E: Engine<Actions = A>,
    SP: StorageProvider,
    <SP as StorageProvider>::Segment: Clone,
{
    pub fn new(engine: E, provider: SP) -> ClientState<E, SP> {
        ClientState { engine, provider }
    }

    /// Create a new graph (AKA Team). This graph will start with the initial policy
    /// provided which must be compatible with the engine E. The `payload` is the inital
    /// init message that will bootstrap the graph facts. Effects produced when processing
    /// the payload are emited to the sink.
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
        action: &A,
    ) -> Result<(), ClientError> {
        // Get storage
        let storage = self.provider.get_storage(storage_id)?;

        let head = storage.get_head()?;

        let parent = storage.get_command_id(&head)?;

        // Get the perspective
        let Some(mut perspective) = storage.get_linear_perspective(&parent)? else {
            return Err(ClientError::NoSuchParent(parent));
        };

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
}

pub struct Transaction<SP: StorageProvider, E> {
    /// The ID of the associated storage
    storage_id: Id,
    /// Current working perspective
    perspective: Option<SP::Perspective>,
    /// Head of the current perspective
    phead: Option<Id>,
    /// Written but not committed heads
    heads: BTreeSet<Id>,
    /// Tag for associated engine
    _engine: PhantomData<E>,
}

impl<SP: StorageProvider, E: Engine> Transaction<SP, E> {
    fn new(storage_id: Id) -> Self {
        Self {
            storage_id,
            perspective: None,
            phead: None,
            heads: BTreeSet::new(),
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
            self.heads.insert(segment.head().id());
        }

        // Merge heads pairwise until single head left, then commit.
        // TODO: Better pairings?
        let mut heads: VecDeque<_> = core::mem::take(&mut self.heads).into_iter().collect();
        while let Some(left) = heads.pop_front() {
            if let Some(right) = heads.pop_front() {
                let (policy, policy_id) = choose_policy(storage, engine, &left, &right)?;

                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let command = policy.merge(&mut buffer, left, right)?;

                let braid = make_braid_segment::<_, E>(storage, left, right, sink, policy)?;

                let perspective = storage
                    .new_merge_perspective(&command, policy_id, braid)?
                    .ok_or(ClientError::InitError)?;

                let segment = storage.write(perspective)?;

                heads.push_back(segment.head().id())
            } else {
                let location = storage
                    .get_location(&left)?
                    .ok_or(ClientError::InternalError)?;
                let segment = storage
                    .get_segment(&location)?
                    .ok_or(ClientError::InternalError)?;

                storage.commit(segment)?;
            }
        }

        Ok(())
    }

    /// Attempt to store the `command` in the graph with `storage_id`. Effects will be
    /// emmited to the `sink`. This interface is use when syncing with another device
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
                Parent::None => {
                    // This init command must have the wrong ID.
                }
                Parent::Id(parent) => {
                    self.add_message(storage, engine, sink, command, parent)?;
                }
                Parent::Merge(left, right) => {
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
            self.heads.insert(seg.head().id());
        }
        self.heads.remove(&left);
        self.heads.remove(&right);

        let (policy, policy_id) = choose_policy(storage, engine, &left, &right)?;

        let braid = make_braid_segment::<_, E>(storage, left, right, sink, policy)?;

        let perspective = storage
            .new_merge_perspective(command, policy_id, braid)?
            .ok_or(ClientError::InitError)?;

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
            return self.perspective.as_mut().ok_or(ClientError::InternalError);
        }

        // Write out the perspective and get a new one
        if let Some(p) = self.perspective.take() {
            let seg = storage.write(p)?;
            self.heads.insert(seg.head().id());
        }

        self.phead = Some(parent);
        self.heads.remove(&parent);

        let p = storage
            .get_linear_perspective(&parent)?
            .ok_or(ClientError::NoSuchParent(parent))?;
        Ok(self.perspective.insert(p))
    }

    fn init<'cmd, 'sp>(
        &mut self,
        command: &impl Command<'cmd>,
        engine: &mut E,
        provider: &'sp mut SP,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<&'sp mut <SP as StorageProvider>::Storage, ClientError> {
        if self.storage_id != command.id() {
            return Err(ClientError::InitStorageMismatch);
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
            return Err(ClientError::InitError);
        }
        perspective.add_command(command)?;
        provider.new_storage(&storage_id, perspective)?;
        sink.commit();
        Ok(provider.get_storage(&self.storage_id)?)
    }
}

fn make_braid_segment<S: Storage, E: Engine>(
    storage: &mut S,
    left: Id,
    right: Id,
    sink: &mut impl Sink<E::Effects>,
    policy: &E::Policy,
) -> Result<S::FactIndex, ClientError> {
    let order = braid(storage, &left, &right)?;

    let (first, rest) = order.split_first().ok_or(ClientError::Unreachable)?;

    let mut braid_perspective = storage.get_fact_perspective(first)?;

    sink.begin();

    for location in rest {
        let segment = storage
            .get_segment(location)?
            .ok_or(ClientError::InternalError)?;
        let command = segment
            .get_command(location)
            .ok_or(ClientError::InternalError)?;
        if !policy.call_rule(command, &mut braid_perspective, sink)? {
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
    left: &Id,
    right: &Id,
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
    command: &Id,
) -> Result<(&'a E::Policy, PolicyId), ClientError> {
    let location = storage
        .get_location(command)?
        .ok_or(ClientError::InternalError)?;
    let segment = storage
        .get_segment(&location)?
        .ok_or(ClientError::InternalError)?;
    let policy_id = segment.policy();
    let policy = engine.get_policy(&policy_id)?;
    Ok((policy, policy_id))
}

pub fn braid<S: Storage>(
    storage: &mut S,
    left: &Id,
    right: &Id,
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
            let segment = storage
                .get_segment(&location)?
                .ok_or(ClientError::InternalError)?;

            let cmd = segment
                .get_command(&location)
                .ok_or(ClientError::InternalError)?;

            Ok(Strand {
                key: (cmd.priority(), cmd.id()),
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
                .ok_or(ClientError::InternalError)?;
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
        let location = storage.get_location(head)?.ok_or(ClientError::InitError)?;
        strands.push(Strand::new(storage, location)?);
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
            if strand.segment.prior().len() == 2 {
                // Skip merge commands
                braid.pop();
            }

            // Strand done, add parents if needed
            'location: for location in strand.segment.prior() {
                for other in &strands {
                    if storage.is_ancestor(&location, &other.segment)? {
                        continue 'location;
                    }
                }

                strands.push(Strand::new(storage, location)?);
            }
            if strands.len() == 1 {
                // No concurrency left, done.
                braid.push(strands.pop().unwrap().next);
                break;
            }
        }
    }

    braid.reverse();
    Ok(braid)
}
