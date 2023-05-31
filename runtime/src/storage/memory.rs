use core::{borrow::Borrow, mem::swap};

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

use crate::{
    command::{Command, Id, Parent, Priority},
    engine::{Engine, Policy, PolicyId},
    storage::{Checkpoint, Location, Perspective, Segment, Storage, StorageError, StorageProvider},
};

const MAX_COMMAND_LENGTH: usize = 2048;

/// Data representing a [`Command`] in memory-backed storage
#[derive(Debug)]
pub struct MemCommand {
    priority: Priority,
    id: Id,
    parent: Parent,
    policy: Option<Vec<u8>>,
    data: Vec<u8>,
}

// Create a memory-backed command from any [`Command`]-implementing object
impl<C: Command> From<&C> for MemCommand {
    fn from(command: &C) -> Self {
        let policy = command.policy().map(|bytes| bytes.to_vec());
        MemCommand {
            priority: command.priority(),
            id: command.id(),
            parent: command.parent(),
            policy,
            data: command.bytes().to_vec(),
        }
    }
}

impl Command for MemCommand {
    fn priority(&self) -> Priority {
        self.priority
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Parent {
        self.parent
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy.as_deref()
    }

    fn bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

pub struct MemStorageProvider {
    storage: Vec<MemStorage>,
    graph: BTreeMap<Id, usize>,
}

impl MemStorageProvider {
    pub fn _new() -> MemStorageProvider {
        MemStorageProvider {
            storage: Vec::new(),
            graph: BTreeMap::new(),
        }
    }
}

impl StorageProvider for MemStorageProvider {
    type Perspective<'segment_storage> = MemPerspective<'segment_storage>
    where
        Self: 'segment_storage;
    type Update = Updates;
    type Segment = MemSegment;
    type Storage = MemStorage;

    fn new_perspective<'segment_storage, 'provider: 'segment_storage>(
        &'provider mut self,
        policy_id: &PolicyId,
    ) -> Self::Perspective<'segment_storage> {
        MemPerspective::new_unrooted(policy_id)
    }

    fn new_storage(
        &mut self,
        group: &Id,
        update: Self::Update,
    ) -> Result<&mut Self::Storage, StorageError> {
        let mut storage = MemStorage::new(group);

        storage.commit(update)?;

        let index = self.storage.len();
        self.storage.push(storage);
        self.graph.insert(*group, index);

        let Some(result) = self.storage.get_mut(index) else {
            return Err(StorageError::InternalError);
        };

        Ok(result)
    }

    fn get_storage(&mut self, group: &Id) -> Result<&mut Self::Storage, StorageError> {
        let index = self.graph.get(group).ok_or(StorageError::NoSuchStorage)?;
        self.storage
            .get_mut(*index)
            .ok_or(StorageError::InternalError)
    }
}

pub struct MemStorage {
    _storage_id: Id,
    segments: Vec<MemSegment>,
    commands: BTreeMap<Id, Location>,
    heads: BTreeSet<usize>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct Head {
    id: Id,
    policy_id: PolicyId,
    segment_index: usize,
}

impl MemStorage {
    pub fn new(storage_id: &Id) -> Self {
        MemStorage {
            _storage_id: *storage_id,
            segments: Vec::new(),
            commands: BTreeMap::new(),
            heads: BTreeSet::new(),
        }
    }

    fn new_segment(&mut self, policy: PolicyId, prior: Vec<usize>) -> usize {
        let index = self.segments.len();
        let segment = MemSegment::new(index, policy, prior, None);

        self.heads.insert(self.segments.len());
        self.segments.push(segment);

        index
    }

    fn _get_segment(&mut self, id: Id) -> Result<Option<&MemSegment>, StorageError> {
        let Some(location) = self.commands.get(&id) else {
            return Ok(None);
        };
        let segment = self
            .segments
            .get_mut(location.segment)
            .ok_or(StorageError::NoSuchStorage)?;
        Ok(Some(segment))
    }

    fn segment_head(&self, segment_index: &usize) -> Result<&MemCommand, StorageError> {
        // If we cannot find the segment, return an error.
        let segment = self
            .segments
            .get(*segment_index)
            .ok_or(StorageError::InternalError)?;

        let data = segment.commands.last().ok_or(StorageError::InternalError)?;

        Ok(&data.command)
    }

    fn do_merge(
        &mut self,
        engine: &impl Engine,
        left: &Head,
        right: &Head,
    ) -> Result<Head, StorageError> {
        let l_policy = engine.get_policy(&left.policy_id)?;
        let r_policy = engine.get_policy(&right.policy_id)?;

        let (policy, policy_id) = if l_policy.serial() > r_policy.serial() {
            (l_policy, left.policy_id)
        } else {
            (r_policy, right.policy_id)
        };

        if self.heads.contains(&left.segment_index) {
            self.heads.remove(&left.segment_index);
        }

        if self.heads.contains(&right.segment_index) {
            self.heads.remove(&right.segment_index);
        }

        let segment_index =
            self.new_segment(policy_id, vec![left.segment_index, right.segment_index]);

        // TODO: The serialization buffer created here for the new segment
        // should be coming from its backing perspective. However, at this
        // point, the merge command has not been created (a command is
        // required to instantiate a new perspective).
        let mut target = [0u8; 100000];

        let new = policy.merge(&mut target, left.id, right.id)?;

        let id = new.id();

        let Some(segment) = self.segments.get_mut(segment_index) else {
            return Err(StorageError::LocationOutOfBounds);
        };

        let command_index = segment.add_merge(&new);
        let location = Location::new(segment_index, command_index);
        self.commands.insert(id, location);

        let merge_head = Head {
            id,
            policy_id,
            segment_index,
        };

        Ok(merge_head)
    }
}

impl Storage for MemStorage {
    type Perspective<'segment_storage> = MemPerspective<'segment_storage>
    where
        Self: 'segment_storage;
    type Update = Updates;
    type Segment = MemSegment;

    fn get_location(&self, id: &Id) -> Result<Option<Location>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None)
        };

        Ok(Some(*location))
    }

    fn get_id(&self, location: &Location) -> Result<Id, StorageError> {
        let segment = self
            .segments
            .get(location.segment)
            .ok_or(StorageError::InternalError)?;

        let command = segment
            .get_command(location)
            .ok_or(StorageError::InternalError)?;

        Ok(command.id())
    }

    fn get_perspective<'segment_storage, 'storage: 'segment_storage>(
        &'storage self,
        id: &Id,
    ) -> Result<Option<Self::Perspective<'segment_storage>>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None);
        };

        let segment = self
            .segments
            .get(location.segment)
            .ok_or(StorageError::InternalError)?;

        let policy = segment.policy();
        let from = Some(location.segment);

        let perspective = MemPerspective::new(self, from, policy, *location);

        Ok(Some(perspective))
    }

    fn get_segment(&self, location: &Location) -> Result<Option<&Self::Segment>, StorageError> {
        Ok(self.segments.get(location.segment))
    }

    fn is_head(&self, location: &Location) -> Result<bool, StorageError> {
        if !self.heads.contains(&location.segment) {
            return Ok(false);
        }
        // We thought the segment contained a head but we can't find the
        // segment!
        let segment = self
            .segments
            .get(location.segment)
            .ok_or(StorageError::InternalError)?;

        Ok(segment.location_is_head(location))
    }

    fn get_heads(&self) -> Result<Vec<Location>, StorageError> {
        let result = self
            .heads
            .iter()
            .map(|segment_index| {
                let cmd_index = self
                    .segments
                    .get(*segment_index)
                    .map(|s| s.commands.len())
                    .ok_or(StorageError::InternalError)?
                    - 1;
                Ok(Location::new(*segment_index, cmd_index))
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        Ok(result)
    }

    fn split(&mut self, at: &Location) -> Result<bool, StorageError> {
        let index = self.segments.len();

        let to_split = self
            .segments
            .get_mut(at.segment)
            .ok_or(StorageError::LocationOutOfBounds)?;

        // Don't split if the location is the head of the segment.
        if to_split.location_is_head(at) {
            return Ok(false);
        }

        let new = to_split.split(index, at)?;

        // If the segment we split was a head we need to remove it and add the
        // index of the new head.
        if self.heads.remove(&at.segment) {
            self.heads.insert(self.segments.len());
        }

        self.segments.push(new);

        Ok(true)
    }

    fn merge_branches(&mut self, engine: &impl Engine) -> Result<Id, StorageError> {
        match self.heads.len() {
            0 => {
                return Err(StorageError::NoHeads);
            }
            1 => {
                let index = self.heads.get(&0).ok_or(StorageError::InternalError)?;
                let command = self.segment_head(index)?;
                let id = command.id();
                return Ok(id);
            }
            _ => {}
        };

        let mut sorted = Vec::with_capacity(self.heads.len());

        for segment_index in &self.heads {
            let segment = self
                .segments
                .get(*segment_index)
                .ok_or(StorageError::InternalError)?;
            let policy_id = segment.policy();

            let head = self.segment_head(segment_index)?;
            let id = head.id();

            let head = Head {
                id,
                policy_id,
                segment_index: *segment_index,
            };

            sorted.push(head);
        }

        // Sort heads by ID, in descending order (ancestors -> parent -> child)
        sorted.sort_by(|left, right| right.id.cmp(&left.id));

        while let (Some(left), Some(right)) = (sorted.pop(), sorted.pop()) {
            let merge_head = self.do_merge(engine, &left, &right)?;

            if sorted.is_empty() {
                return Ok(merge_head.id);
            }
            match sorted.binary_search(&merge_head) {
                Ok(_pos) => return Err(StorageError::InternalError),
                Err(pos) => sorted.insert(pos, merge_head),
            }
        }

        unreachable!()
    }

    fn commit(&mut self, update: Self::Update) -> Result<(), StorageError> {
        let mut is_head: bool = true;

        // Check if the update's specified location exists
        let segment_index = match &update.location {
            // If the update's location does not exist,
            // we need to create a new segment.
            None => {
                let policy_id = update.policy;
                self.new_segment(policy_id, vec![])
            }
            // If the location does exist, we need to check if
            // the specified location is the head of the segment.
            Some(location) => {
                // Check if the specified location contains the head of the
                // segment. If it does, the update will be applied to the existing
                // segment. If not, we must create a new segment for this update.
                is_head = self.is_head(location)?;
                if is_head {
                    location.segment
                } else {
                    let policy_id = update.policy;
                    self.new_segment(policy_id, vec![location.segment])
                }
            }
        };

        let segment = self
            .segments
            .get_mut(segment_index)
            .ok_or(StorageError::LocationOutOfBounds)?;

        // Update the facts for the segment
        for data in &update.updates {
            apply_updates(&data.updates, &mut segment.facts);
        }

        // Add the commands to the segment
        for data in update.updates {
            let command_index = segment.commands.len();
            let new_location = Location::new(segment_index, command_index);

            self.commands.insert(data.command.id, new_location);
            segment.commands.push(data);
        }

        // Split the segment at location if location
        // is not the head of the segment.
        if !is_head {
            if let Some(location) = update.location {
                self.split(&location)?;
            }
        }

        Ok(())
    }
}

type SegmentId = usize;

#[derive(Debug)]
struct CommandData {
    command: MemCommand,
    updates: Vec<Update>,
}

#[derive(Debug)]
pub struct MemSegment {
    index: SegmentId,
    prior: Vec<SegmentId>,
    policy: PolicyId,
    commands: Vec<CommandData>,
    prior_facts: Option<SegmentId>,
    facts: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl MemSegment {
    pub fn new(
        index: usize,
        policy: PolicyId,
        prior: Vec<usize>,
        prior_facts: Option<SegmentId>,
    ) -> MemSegment {
        let index: SegmentId = index;
        MemSegment {
            index,
            prior,
            policy,
            commands: Vec::new(),
            facts: BTreeMap::new(),
            prior_facts,
        }
    }

    fn check_add_merge(&mut self, command: &impl Command) {
        let Parent::Id(parent) = command.parent() else {
            panic!("can only add command with exactly one parent");
        };

        assert!(self.id_is_head(parent), "can't add non child command");
    }

    fn split(&mut self, new_index: usize, at: &Location) -> Result<MemSegment, StorageError> {
        if self.commands.len() >= at.command {
            return Err(StorageError::LocationOutOfBounds);
        }

        let next = at.command + 1;
        let commands = self.commands.split_off(next);
        let prior = vec![at.segment];
        let policy = self.policy();
        let mut facts = BTreeMap::new();

        // reset facts for existing segment
        self.facts.clear();
        for data in &self.commands {
            apply_updates(&data.updates, &mut self.facts);
        }

        // set facts for new segment
        for data in &commands {
            apply_updates(&data.updates, &mut facts);
        }

        Ok(MemSegment {
            index: new_index,
            facts,
            policy,
            prior,
            commands,
            prior_facts: Some(self.index),
        })
    }

    fn id_is_head(&self, id: Id) -> bool {
        match self.head() {
            Some(head) => id == head.id,
            None => false,
        }
    }
}

impl Segment for MemSegment {
    type Command = MemCommand;
    type Commands<'segment_cmd> = MemCommandIter<'segment_cmd>
    where
        Self: 'segment_cmd;

    fn head(&self) -> Option<&MemCommand> {
        match self.commands.last() {
            None => None,
            Some(c) => Some(&c.command),
        }
    }

    fn first(&self) -> Option<&MemCommand> {
        match self.commands.first() {
            None => None,
            Some(c) => Some(&c.command),
        }
    }

    fn first_location(&self) -> Option<Location> {
        if self.commands.is_empty() {
            return None;
        }

        Some(Location {
            segment: self.index,
            command: 0,
        })
    }

    fn location_is_head(&self, location: &Location) -> bool {
        if self.commands.is_empty() {
            return false;
        }

        self.commands.len() - 1 == location.command
    }

    fn contains(&self, location: &Location) -> bool {
        location.segment == self.index
    }

    // Extend the current partial order by adding a child of
    // current head to the order.
    fn add_merge(&mut self, command: &impl Command) -> usize {
        let local = command.into();
        #[cfg(debug_assertions)]
        self.check_add_merge(&local);
        // TODO: Segment should have updates when merging. May
        // need to accept this data as param.
        let data = CommandData {
            command: local,
            updates: Vec::new(),
        };

        self.commands.push(data);
        self.commands.len() - 1
    }

    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn prior(&self) -> Vec<Location> {
        let mut result = Vec::new();

        for p in &self.prior {
            let location = Location::new(*p, 0);
            result.push(location);
        }

        result
    }

    fn get_command(&self, location: &Location) -> Option<&MemCommand> {
        if location.segment != self.index {
            return None;
        }

        let data = self.commands.get(location.command);

        match data {
            None => None,
            Some(d) => Some(&d.command),
        }
    }

    fn get_from<'segment_cmd, 'segment: 'segment_cmd>(
        &'segment self,
        location: &Location,
    ) -> MemCommandIter<'segment_cmd> {
        if location.segment != self.index {
            // The provided location does not refer to self, so we return
            // an empty iterator.
            return MemCommandIter::new(vec![]);
        }
        // Create a list of references to this segment's commands
        let commands = self
            .commands
            // Iterate over references
            .iter()
            // Drop commands up to (and including) the value of location.command
            .skip(location.command)
            // Segment's hold onto `CommandData`, which stores a
            // Command and the updates produced by the Command.
            // As this segment "owns" the commands, the iterator
            // must explicitly borrow.
            .map(|data| data.command.borrow())
            // Reverse the order of the segment's commands,
            // so the returned iterator produces commands
            // from the provided location (`next` produces optional
            // values from the end of the iter's collection)
            .rev()
            .collect::<Vec<_>>();

        MemCommandIter::new(commands)
    }
}

pub struct MemCommandIter<'segment_cmd> {
    commands: Vec<&'segment_cmd MemCommand>,
}

impl<'segment_cmd> MemCommandIter<'segment_cmd> {
    pub fn new(commands: Vec<&'segment_cmd MemCommand>) -> Self {
        Self { commands }
    }
}

impl<'segment_cmd> Iterator for MemCommandIter<'segment_cmd> {
    type Item = &'segment_cmd MemCommand;

    fn next(&mut self) -> Option<Self::Item> {
        self.commands.pop()
    }
}

type PerspectiveIndex = usize;

#[derive(Debug)]
pub enum Update {
    Delete(Vec<u8>),
    Insert(Vec<u8>, Vec<u8>),
}

pub struct Updates {
    policy: PolicyId,
    location: Option<Location>,
    updates: Vec<CommandData>,
}

pub struct MemPerspective<'segment_storage> {
    location: Option<Location>,
    policy: PolicyId,
    from: Option<PerspectiveIndex>,
    temp: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    commands: Vec<CommandData>,
    current_updates: Vec<Update>,
    storage: Option<&'segment_storage MemStorage>,
    target: Box<[u8]>,
}

impl<'segment_storage> MemPerspective<'segment_storage> {
    fn new(
        storage: &'segment_storage MemStorage,
        from: Option<PerspectiveIndex>,
        policy: PolicyId,
        location: Location,
    ) -> MemPerspective<'segment_storage> {
        let mut result = MemPerspective {
            location: Some(location),
            policy,
            from,
            temp: BTreeMap::new(),
            commands: Vec::new(),
            current_updates: Vec::new(),
            storage: Some(storage),
            target: vec![0u8; 1048576].into_boxed_slice(),
        };

        result.apply_from();

        result
    }

    fn new_unrooted(policy: &PolicyId) -> MemPerspective<'segment_storage> {
        MemPerspective {
            location: None,
            policy: *policy,
            from: None,
            temp: BTreeMap::new(),
            commands: Vec::new(),
            current_updates: Vec::new(),
            storage: None,
            target: vec![0u8; 1048576].into_boxed_slice(),
        }
    }

    fn apply_from(&mut self) {
        let Some(index) = self.from else {return};
        let Some(storage) = self.storage else {return};
        let Some(location) = &self.location else {return};

        let segment = &storage.segments[index];
        for data in &segment.commands[0..(location.command + 1)] {
            apply_updates(&data.updates, &mut self.temp);
        }
    }
}

fn apply_updates(updates: &Vec<Update>, map: &mut BTreeMap<Vec<u8>, Option<Vec<u8>>>) {
    for update in updates {
        match update {
            Update::Delete(key) => {
                map.insert((*key).clone(), None);
            }
            Update::Insert(key, value) => {
                map.insert((*key).clone(), Some(value.clone()));
            }
        }
    }
}

impl<'segment_storage> Perspective<'segment_storage> for MemPerspective<'segment_storage> {
    type Update = Updates;

    fn location(&self) -> &Option<Location> {
        &self.location
    }

    fn query(&self, key: &[u8]) -> Result<Option<&[u8]>, StorageError> {
        if let Some(wrapped) = self.temp.get(key) {
            let result = wrapped.as_ref().map(|wrapped| wrapped.as_slice());
            return Ok(result);
        }

        let Some(storage) = self.storage else {
            return Ok(None)
        };

        let Some(from) = self.from else {
            return Ok(None)
        };

        let segment = storage
            .segments
            .get(from)
            .ok_or(StorageError::InternalError)?;

        let mut prior_option = &segment.prior_facts;

        while let Some(prior_index) = prior_option {
            let Some(prior_segment) = storage.segments.get(*prior_index) else {
                return Err(StorageError::InternalError)
            };

            match prior_segment.facts.get(key) {
                // TODO: Determine how to detect cycles in a corrupted graph.
                // Could possibly use the max_cut of the fact we are accessing
                // to verify it is going down as we walk down the graph.
                None => prior_option = &prior_segment.prior_facts,
                Some(wrapped) => {
                    return match wrapped {
                        Some(wrapped) => Ok(Some(wrapped.as_slice())),
                        None => Ok(None),
                    }
                }
            };
        }
        Ok(None)
    }

    fn add_command(&mut self, command: &impl Command) -> Result<usize, StorageError> {
        let mut temp = Vec::new();
        swap(&mut self.current_updates, &mut temp);
        let entry = CommandData {
            command: command.into(),
            updates: temp,
        };
        self.commands.push(entry);
        Ok(self.commands.len())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.temp.insert(key.to_vec(), Some(value.to_vec()));
        self.current_updates
            .push(Update::Insert(key.to_vec(), value.to_vec()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.temp.insert(key.to_vec(), None);
        self.current_updates.push(Update::Delete(key.to_vec()));
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            index: self.commands.len(),
        }
    }

    fn revert(&mut self, checkpoint: Checkpoint) {
        self.commands.truncate(checkpoint.index);
        self.temp.clear();
        self.current_updates.clear();
        self.apply_from();
        for data in &self.commands {
            apply_updates(&data.updates, &mut self.temp);
        }
    }

    fn to_update(self) -> Self::Update {
        Updates {
            policy: self.policy,
            location: self.location,
            updates: self.commands,
        }
    }

    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn get_target(&mut self) -> Result<Vec<u8>, StorageError> {
        let (requested_target, _) = self.target.split_at_mut(MAX_COMMAND_LENGTH);
        Ok(requested_target.to_vec())
    }
}
