use alloc::collections::{BTreeMap, VecDeque};
use core::marker::PhantomData;

use buggy::{bug, BugExt};

use crate::{
    ClientError, Command, Engine, Id, Location, Perspective, Policy, PolicyId, Prior, Revertable,
    Segment, Sink, Storage, StorageError, StorageProvider, MAX_COMMAND_LENGTH,
};

/// Transaction used to receive many commands at once.
///
/// The transaction allows us to have many temporary heads at once, so we don't
/// need as many merges when adding commands. When the transaction is committed,
/// we will merge all temporary heads and the storage head, and then commit the
/// result as the new storage head.
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
    pub(super) fn new(storage_id: Id) -> Self {
        Self {
            storage_id,
            perspective: None,
            phead: None,
            heads: BTreeMap::new(),
            _engine: PhantomData,
        }
    }

    /// Find a given id if reachable within this transaction.
    ///
    /// Does not search `self.perspective`, which should be written out beforehand.
    fn locate(&self, storage: &mut SP::Storage, id: &Id) -> Result<Option<Location>, ClientError> {
        // Search from committed head.
        if let Some(found) = storage.get_location(id)? {
            return Ok(Some(found));
        }
        // Search from our temporary heads.
        for head in self.heads.values() {
            if let Some(found) = storage.get_location_from(head, id)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Write current perspective, merge transaction heads, and commit to graph.
    pub(super) fn commit(
        &mut self,
        provider: &mut SP,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<(), ClientError> {
        let storage = provider.get_storage(&self.storage_id)?;

        // Write out current perspective.
        if let Some(p) = self.perspective.take() {
            self.phead = None;
            let segment = storage.write(p)?;
            self.heads
                .insert(segment.head().id(), segment.head_location());
        }

        // Add graph head to transaction heads if not ancestor of any
        // transaction head, so that we will merge it in below.
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
        // TODO(#370): Merge deterministically
        let mut heads: VecDeque<_> = core::mem::take(&mut self.heads).into_iter().collect();
        while let Some((left_id, left_loc)) = heads.pop_front() {
            if let Some((right_id, right_loc)) = heads.pop_front() {
                let (policy, policy_id) = choose_policy(storage, engine, &left_loc, &right_loc)?;

                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let command = policy.merge(&mut buffer, left_id, right_id)?;

                let braid =
                    make_braid_segment::<_, E>(storage, &left_loc, &right_loc, sink, policy)?;

                let mut perspective = storage
                    .new_merge_perspective(&left_loc, &right_loc, policy_id, braid)?
                    .assume("trx heads should exist in storage")?;
                perspective.add_command(&command)?;

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
    pub(super) fn add_commands<'a>(
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
            if self.locate(storage, &command.id())?.is_some() {
                // Command already added.
                continue;
            }
            match command.parent() {
                Prior::None => {
                    if command.id() == self.storage_id {
                        // Graph already initialized, extra init just spurious
                    } else {
                        bug!("init command does not belong in graph");
                    }
                }
                Prior::Single(parent) => {
                    self.add_single(storage, engine, sink, command, &parent)?;
                }
                Prior::Merge(left, right) => {
                    self.add_merge(storage, engine, sink, command, left, right)?;
                }
            };
        }

        Ok(true)
    }

    fn add_single<'a>(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        engine: &mut E,
        sink: &mut impl Sink<E::Effects>,
        command: &impl Command<'a>,
        parent: &Id,
    ) -> Result<(), ClientError> {
        let perspective = self.get_perspective(parent, storage)?;

        let policy_id = perspective.policy();
        let policy = engine.get_policy(&policy_id)?;

        // Try to run command, or revert if failed.
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
        // Must always start a new perspective for merges.
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

        // Braid commands from left and right into an ordered sequence.
        let braid = make_braid_segment::<_, E>(storage, &left_loc, &right_loc, sink, policy)?;

        let mut perspective = storage
            .new_merge_perspective(&left_loc, &right_loc, policy_id, braid)?
            .assume(
                "we already found left and right locations above and we only call this with merge command",
            )?;
        perspective.add_command(command)?;

        // These are no longer heads of the transaction, since they are both covered by the merge
        self.heads.remove(&left);
        self.heads.remove(&right);

        self.perspective = Some(perspective);
        self.phead = Some(command.id());

        Ok(true)
    }

    /// Get a perspective to which we can add a command with the given parant.
    ///
    /// If parent is the head of the current perspective, we can just use it.
    /// Otherwise, we must write out the perspective and get a new one.
    fn get_perspective(
        &mut self,
        parent: &Id,
        storage: &mut <SP as StorageProvider>::Storage,
    ) -> Result<&mut <SP as StorageProvider>::Perspective, ClientError> {
        let loc = self
            .locate(storage, parent)?
            .ok_or(ClientError::NoSuchParent(*parent))?;

        if self.phead == Some(*parent) {
            // Command will append to current perspective.
            return Ok(self
                .perspective
                .as_mut()
                .assume("trx has perspective when has phead")?);
        }

        // Write out the current perspective.
        if let Some(p) = self.perspective.take() {
            self.phead.take();
            let seg = storage.write(p)?;
            self.heads.insert(seg.head().id(), seg.head_location());
        }

        // Get a new perspective and store it in the transaction.
        let p = self.perspective.insert(
            storage
                .get_linear_perspective(&loc)?
                .assume("location should already be in storage")?,
        );

        self.phead = Some(*parent);
        self.heads.remove(parent);

        Ok(p)
    }

    fn init<'cmd, 'sp>(
        &mut self,
        command: &impl Command<'cmd>,
        engine: &mut E,
        provider: &'sp mut SP,
        sink: &mut impl Sink<E::Effects>,
    ) -> Result<&'sp mut <SP as StorageProvider>::Storage, ClientError> {
        // Storage ID is the id of the init command by definition.
        if self.storage_id != command.id() {
            return Err(ClientError::InitError);
        }

        // The init command must not have a parent.
        if !matches!(command.parent(), Prior::None) {
            return Err(ClientError::InitError);
        }

        // The graph must have policy to start with.
        let Some(policy_data) = command.policy() else {
            return Err(ClientError::InitError);
        };

        let policy_id = engine.add_policy(policy_data)?;
        let policy = engine.get_policy(&policy_id)?;

        // Get an empty perspective and run the init command.
        let mut perspective = provider.new_perspective(&policy_id);
        sink.begin();
        if !policy.call_rule(command, &mut perspective, sink)? {
            sink.rollback();
            // We don't need to revert perspective since we just drop it.
            return Err(ClientError::NotAuthorized);
        }
        perspective.add_command(command)?;

        let storage = provider.new_storage(&self.storage_id, perspective)?;

        // Wait to commit until we are absolutely sure we've initialized.
        sink.commit();

        Ok(storage)
    }
}

/// Run the braid algorithm and evaluate the sequence to create a braided fact index.
fn make_braid_segment<S: Storage, E: Engine>(
    storage: &mut S,
    left: &Location,
    right: &Location,
    sink: &mut impl Sink<E::Effects>,
    policy: &E::Policy,
) -> Result<S::FactIndex, ClientError> {
    let order = super::braid(storage, left, right)?;

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

/// Select the policy from two locations with the greatest serial value.
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
