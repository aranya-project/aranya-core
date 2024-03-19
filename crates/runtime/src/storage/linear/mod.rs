//! Persistant linear storage implemenatation.
//!
//! `LinearStorage` is a graph storage implementation backed by a file-like byte
//! storage interface. This is designed to be usable across many environments
//! with minimal assumptions on the underlying storage.
//!
//! # Layout
//!
//! `[x]` is page aligned.
//!
//! ```text
//! // Control section
//! [Base] [Root] [Root]
//! // Data section
//! [Segment or FactIndex]
//! |
//! V
//! ```
//!
//! The `LinearStorage` will exclusively modify the control section. The data
//! section is append-only but can be read concurrently. If written data is not
//! committed, it may be overwritten and will become unreachable by intended
//! means.

pub mod rustix;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::cmp::Ordering;

use buggy::{bug, BugExt};
use serde::{Deserialize, Serialize};
use vec1::Vec1;

use crate::{
    Checkpoint, Command, FactIndex, FactPerspective, Id, Location, Perspective, PolicyId, Prior,
    Priority, Revertable, Segment, Storage, StorageError, StorageProvider,
};

pub mod io;
pub use io::*;

const PAGE: u64 = 4096;

pub struct LinearStorageProvider<FM: FileManager> {
    manager: FM,
    storage: BTreeMap<Id, LinearStorage<FM::File>>,
}

pub struct LinearStorage<W> {
    writer: W,
    base: Base,
    root: Root,
}

#[derive(Debug, Serialize, Deserialize)]
struct Base {
    version: u64,
    // We store two roots so at least one should be valid even during writing.
    root_offset_a: u64,
    root_offset_b: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Root {
    /// Incremented each commit
    generation: u64,
    head: Location,
    free_head: u64,
    /// Used to ensure root is valid. Write could be interrupted or corrupted.
    checksum: u64,
}

#[derive(Debug)]
pub struct LinearSegment<R> {
    repr: SegmentRepr,
    reader: R,
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentRepr {
    /// Self offset in file.
    offset: usize,
    prior: Prior<Location>,
    parents: Prior<Id>,
    policy: PolicyId,
    /// Offset in file to associated fact index.
    facts: u64,
    commands: Vec1<CommandData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommandData {
    id: Id,
    priority: Priority,
    policy: Option<Bytes>,
    data: Bytes,
    updates: Vec<Update>,
}

pub struct LinearCommand<'a> {
    id: &'a Id,
    parent: Prior<&'a Id>,
    priority: Priority,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
}

type Bytes = Box<[u8]>;

#[derive(Debug, Serialize, Deserialize)]
struct Update {
    key: Bytes,
    value: Option<Bytes>,
}

#[derive(Debug)]
pub struct LinearFactIndex<R> {
    repr: FactIndexRepr,
    reader: R,
}

#[derive(Debug, Serialize, Deserialize)]
struct FactIndexRepr {
    /// Self offset in file.
    offset: u64,
    prior: Option<u64>,
    /// Sorted key/value pairs, where `None` is a deleted fact.
    facts: Vec<(Bytes, Option<Bytes>)>,
}

#[derive(Debug)]
pub struct LinearPerspective<R> {
    prior: Prior<Location>,
    parents: Prior<Id>,
    policy: PolicyId,
    facts: LinearFactPerspective<R>,
    commands: Vec<CommandData>,
    current_updates: Vec<Update>,
}

impl<R> LinearPerspective<R> {
    fn new(
        prior: Prior<Location>,
        parents: Prior<Id>,
        policy: PolicyId,
        prior_facts: FactPerspectivePrior<R>,
    ) -> Self {
        Self {
            prior,
            parents,
            policy,
            facts: LinearFactPerspective::new(prior_facts),
            commands: Vec::new(),
            current_updates: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct LinearFactPerspective<R> {
    map: BTreeMap<Bytes, Option<Bytes>>,
    prior: FactPerspectivePrior<R>,
}

impl<R> LinearFactPerspective<R> {
    fn new(prior: FactPerspectivePrior<R>) -> Self {
        Self {
            map: BTreeMap::new(),
            prior,
        }
    }
}

#[derive(Debug)]
enum FactPerspectivePrior<R> {
    None,
    FactPerspective(Box<LinearFactPerspective<R>>),
    FactIndex { offset: u64, reader: R },
}

impl<FM: FileManager> LinearStorageProvider<FM> {
    pub fn new(manager: FM) -> Self {
        Self {
            manager,
            storage: BTreeMap::new(),
        }
    }
}

impl<FM: FileManager> StorageProvider for LinearStorageProvider<FM> {
    type Perspective = LinearPerspective<<FM::File as Write>::ReadOnly>;
    type Segment = LinearSegment<<FM::File as Write>::ReadOnly>;
    type Storage = LinearStorage<FM::File>;

    fn new_perspective(&mut self, policy_id: &PolicyId) -> Self::Perspective {
        LinearPerspective::new(
            Prior::None,
            Prior::None,
            *policy_id,
            FactPerspectivePrior::None,
        )
    }

    fn new_storage<'a>(
        &'a mut self,
        group: &Id,
        init: Self::Perspective,
    ) -> Result<&'a mut Self::Storage, StorageError> {
        use alloc::collections::btree_map::Entry;

        let Entry::Vacant(entry) = self.storage.entry(*group) else {
            return Err(StorageError::StorageExists);
        };

        let file = self.manager.create(*group)?;
        Ok(entry.insert(LinearStorage::create(file, init)?))
    }

    fn get_storage<'a>(&'a mut self, group: &Id) -> Result<&'a mut Self::Storage, StorageError> {
        use alloc::collections::btree_map::Entry;

        let entry = match self.storage.entry(*group) {
            Entry::Vacant(v) => v,
            Entry::Occupied(o) => return Ok(o.into_mut()),
        };

        let file = self
            .manager
            .open(*group)?
            .ok_or(StorageError::NoSuchStorage)?;
        Ok(entry.insert(LinearStorage::open(file)?))
    }
}

impl<W: Write> LinearStorage<W> {
    fn create(mut writer: W, init: LinearPerspective<W::ReadOnly>) -> Result<Self, StorageError> {
        assert!(matches!(init.prior, Prior::None));
        assert!(matches!(init.parents, Prior::None));
        assert!(matches!(init.facts.prior, FactPerspectivePrior::None));

        let mut free_head = PAGE * 3;

        let facts = {
            let repr = FactIndexRepr {
                offset: free_head,
                prior: None,
                facts: init.facts.map.into_iter().collect(),
            };
            free_head = writer.dump(free_head, &repr)?;
            repr.offset
        };

        let segment = SegmentRepr {
            offset: free_head.try_into().assume("first segment is in bounds")?,
            prior: Prior::None,
            parents: Prior::None,
            policy: init.policy,
            facts,
            commands: init
                .commands
                .try_into()
                .map_err(|_| StorageError::EmptyPerspective)?,
        };
        free_head = writer.dump(free_head, &segment)?;

        let base = Base {
            version: 1,
            root_offset_a: PAGE,
            root_offset_b: PAGE * 2,
        };
        let mut root = Root {
            generation: 1,
            // vec1 length >= 1
            #[allow(clippy::arithmetic_side_effects)]
            head: Location::new(segment.offset, segment.commands.len() - 1),
            free_head,
            checksum: 0,
        };

        root.checksum = root.calc_checksum();
        writer.dump(base.root_offset_a, &root)?;
        writer.dump(base.root_offset_b, &root)?;
        writer.sync()?;

        writer.dump(0, &base)?;
        writer.sync()?;

        let storage = Self { writer, base, root };

        Ok(storage)
    }

    fn open(mut writer: W) -> Result<Self, StorageError> {
        let reader = writer.readonly();
        let base: Base = reader.load(0)?;
        assert_eq!(base.version, 1);

        let (root, overwrite) = match (
            reader.load(base.root_offset_a).and_then(Root::validate),
            reader.load(base.root_offset_b).and_then(Root::validate),
        ) {
            (Ok(root_a), Ok(root_b)) => match root_a.generation.cmp(&root_b.generation) {
                Ordering::Equal => (root_a, None),
                Ordering::Greater => (root_a, Some(base.root_offset_b)),
                Ordering::Less => (root_b, Some(base.root_offset_a)),
            },
            (Ok(root_a), Err(_)) => (root_a, Some(base.root_offset_b)),
            (Err(_), Ok(root_b)) => (root_b, Some(base.root_offset_a)),
            (Err(e), Err(_)) => return Err(e),
        };

        // Write other side if needed (corrupted or outdated)
        if let Some(offset) = overwrite {
            writer.dump(offset, &root)?;
        }

        let storage = Self { writer, base, root };

        Ok(storage)
    }

    fn write_root(&mut self) -> Result<(), StorageError> {
        self.root.generation = self
            .root
            .generation
            .checked_add(1)
            .assume("generation will not overflow u64")?;

        for offset in [self.base.root_offset_a, self.base.root_offset_b] {
            self.root.checksum = self.root.calc_checksum();
            self.writer.dump(offset, &self.root)?;
            self.writer.sync()?;
        }

        Ok(())
    }
}

impl Root {
    fn calc_checksum(&self) -> u64 {
        // TODO(jdygert): Use cheaper hash or error correcting code
        use crypto::hash::Hash;
        let mut hash = crypto::rust::Sha256::new();
        hash.update(&self.generation.to_be_bytes());
        // FIXME(jdygert): u64
        hash.update(&(self.head.segment as u64).to_be_bytes());
        hash.update(&(self.head.command as u64).to_be_bytes());
        hash.update(&self.free_head.to_be_bytes());
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash.digest()[..8]);
        u64::from_be_bytes(bytes)
    }

    fn validate(self) -> Result<Self, StorageError> {
        if self.checksum != self.calc_checksum() {
            // TODO(jdygert): Isn't really a bug.
            bug!("invalid checksum");
        }
        Ok(self)
    }
}

impl<F: Write> Storage for LinearStorage<F> {
    type Perspective = LinearPerspective<F::ReadOnly>;
    type FactPerspective = LinearFactPerspective<F::ReadOnly>;
    type Segment = LinearSegment<F::ReadOnly>;
    type FactIndex = LinearFactIndex<F::ReadOnly>;

    fn get_command_id(&self, location: Location) -> Result<Id, StorageError> {
        let seg = self.get_segment(location)?;
        let cmd = seg
            .get_command(location)
            .ok_or(StorageError::CommandOutOfBounds(location))?;
        Ok(cmd.id())
    }

    fn get_linear_perspective(
        &self,
        parent: Location,
    ) -> Result<Option<Self::Perspective>, StorageError> {
        let segment = self.get_segment(parent)?;
        let parent_id = segment
            .get_command(parent)
            .ok_or(StorageError::CommandOutOfBounds(parent))?
            .id();

        let policy = segment.repr.policy;
        let prior_facts: FactPerspectivePrior<F::ReadOnly> = if parent == segment.head_location() {
            FactPerspectivePrior::FactIndex {
                offset: segment.repr.facts,
                reader: self.writer.readonly(),
            }
        } else {
            let prior = match segment.facts()?.repr.prior {
                Some(offset) => FactPerspectivePrior::FactIndex {
                    offset,
                    reader: self.writer.readonly(),
                },
                None => FactPerspectivePrior::None,
            };
            let mut facts = LinearFactPerspective::new(prior);
            for data in &segment.repr.commands[..=parent.command] {
                facts.apply_updates(&data.updates);
            }
            if facts.map.is_empty() {
                facts.prior
            } else {
                FactPerspectivePrior::FactPerspective(Box::new(facts))
            }
        };
        let prior = Prior::Single(parent);

        let perspective =
            LinearPerspective::new(prior, Prior::Single(parent_id), policy, prior_facts);

        Ok(Some(perspective))
    }

    fn get_fact_perspective(
        &self,
        location: Location,
    ) -> Result<Self::FactPerspective, StorageError> {
        let segment = self.get_segment(location)?;

        if location == segment.head_location() {
            return Ok(LinearFactPerspective::new(
                FactPerspectivePrior::FactIndex {
                    offset: segment.repr.facts,
                    reader: self.writer.readonly(),
                },
            ));
        }

        let prior = match segment.facts()?.repr.prior {
            Some(offset) => FactPerspectivePrior::FactIndex {
                offset,
                reader: self.writer.readonly(),
            },
            None => FactPerspectivePrior::None,
        };
        let mut facts = LinearFactPerspective::new(prior);
        for data in &segment.repr.commands[..=location.command] {
            facts.apply_updates(&data.updates);
        }

        Ok(facts)
    }

    fn new_merge_perspective(
        &self,
        left: Location,
        right: Location,
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Option<Self::Perspective>, StorageError> {
        // TODO(jdygert): ensure braid belongs to this storage.
        // TODO(jdygert): ensure braid ends at given command?
        let left_segment = self.get_segment(left)?;
        let right_segment = self.get_segment(right)?;

        let parent = Prior::Merge(
            left_segment
                .get_command(left)
                .ok_or(StorageError::CommandOutOfBounds(left))?
                .id(),
            right_segment
                .get_command(right)
                .ok_or(StorageError::CommandOutOfBounds(right))?
                .id(),
        );

        if policy_id != left_segment.policy() && policy_id != right_segment.policy() {
            return Err(StorageError::PolicyMismatch);
        }

        let prior = Prior::Merge(left, right);

        let perspective = LinearPerspective::new(
            prior,
            parent,
            policy_id,
            FactPerspectivePrior::FactIndex {
                offset: braid.repr.offset,
                reader: braid.reader,
            },
        );

        Ok(Some(perspective))
    }

    fn get_segment(&self, location: Location) -> Result<Self::Segment, StorageError> {
        let reader = self.writer.readonly();
        let repr = reader.load(
            location
                .segment
                .try_into()
                .assume("segment usize fits into u64")?,
        )?;
        Ok(LinearSegment { repr, reader })
    }

    fn get_head(&self) -> Result<Location, StorageError> {
        Ok(self.root.head)
    }

    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError> {
        if !self.is_ancestor(self.root.head, &segment)? {
            return Err(StorageError::HeadNotAncestor);
        }

        self.root.head = segment.head_location();
        self.write_root()?;

        Ok(())
    }

    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError> {
        // TODO(jdygert): Validate prior?

        let facts = self.write_facts(perspective.facts)?.repr.offset;

        let commands: Vec1<CommandData> = perspective
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;

        let repr = SegmentRepr {
            offset: self.root.free_head.try_into().assume("offset in bounds")?,
            prior: perspective.prior,
            parents: perspective.parents,
            policy: perspective.policy,
            facts,
            commands,
        };

        self.root.free_head = self
            .writer
            .dump(repr.offset.try_into().assume("usize fits in u64")?, &repr)?;

        Ok(LinearSegment {
            repr,
            reader: self.writer.readonly(),
        })
    }

    fn write_facts(
        &mut self,
        facts: Self::FactPerspective,
    ) -> Result<Self::FactIndex, StorageError> {
        let prior = match facts.prior {
            FactPerspectivePrior::None => None,
            FactPerspectivePrior::FactPerspective(prior) => {
                let prior = self.write_facts(*prior)?;
                if facts.map.is_empty() {
                    return Ok(prior);
                }
                Some(prior.repr.offset)
            }
            FactPerspectivePrior::FactIndex { offset, reader } => {
                if facts.map.is_empty() {
                    let repr = reader.load(offset)?;
                    return Ok(LinearFactIndex { repr, reader });
                }
                Some(offset)
            }
        };
        let repr = FactIndexRepr {
            offset: self.root.free_head,
            prior,
            facts: facts.map.into_iter().collect(),
        };

        self.root.free_head = self.writer.dump(repr.offset, &repr)?;

        Ok(LinearFactIndex {
            repr,
            reader: self.writer.readonly(),
        })
    }
}

impl<R: Read> Segment for LinearSegment<R> {
    type FactIndex = LinearFactIndex<R>;
    type Command<'a> = LinearCommand<'a> where R: 'a;

    fn head(&self) -> Self::Command<'_> {
        let data = self.repr.commands.last();
        let parent = if let Some(prev) = usize::checked_sub(self.repr.commands.len(), 2) {
            Prior::Single(&self.repr.commands[prev].id)
        } else {
            self.repr.parents.as_ref()
        };
        LinearCommand {
            id: &data.id,
            parent,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
        }
    }

    fn first(&self) -> Self::Command<'_> {
        let data = self.repr.commands.first();
        let parent = self.repr.parents.as_ref();
        LinearCommand {
            id: &data.id,
            parent,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
        }
    }

    fn head_location(&self) -> Location {
        // vec1 length >= 1
        #[allow(clippy::arithmetic_side_effects)]
        Location::new(self.repr.offset, self.repr.commands.len() - 1)
    }

    fn first_location(&self) -> Location {
        Location::new(self.repr.offset, 0)
    }

    fn contains(&self, location: Location) -> bool {
        location.segment == self.repr.offset && location.command < self.repr.commands.len()
    }

    fn policy(&self) -> PolicyId {
        self.repr.policy
    }

    fn prior(&self) -> Prior<Location> {
        self.repr.prior
    }

    fn get_command(&self, location: Location) -> Option<Self::Command<'_>> {
        if self.repr.offset != location.segment {
            return None;
        }
        let data = self.repr.commands.get(location.command)?;
        let parent = if let Some(prev) = usize::checked_sub(location.command, 1) {
            Prior::Single(&self.repr.commands[prev].id)
        } else {
            self.repr.parents.as_ref()
        };
        Some(LinearCommand {
            id: &data.id,
            parent,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
        })
    }

    fn get_from(&self, location: Location) -> Vec<Self::Command<'_>> {
        if self.repr.offset != location.segment {
            // TODO(jdygert): Result?
            return Vec::new();
        }

        // TODO(jdygert): Optimize?
        (location.command..self.repr.commands.len())
            .map(|c| Location::new(location.segment, c))
            .map(|loc| {
                self.get_command(loc)
                    .expect("constructed location is valid")
            })
            .collect()
    }

    fn facts(&self) -> Result<Self::FactIndex, StorageError> {
        Ok(LinearFactIndex {
            repr: self.reader.load(self.repr.facts)?,
            reader: self.reader.clone(),
        })
    }
}

impl<R: Read> FactIndex for LinearFactIndex<R> {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        let mut prior = Some(&self.repr);
        let mut slot; // Need to store deserialized value.
        while let Some(facts) = prior {
            if let Ok(idx) = facts.facts.binary_search_by_key(&key, |(k, _)| k) {
                let (_, v) = &facts.facts[idx];
                return Ok(v.as_ref().cloned());
            }
            slot = facts.prior.map(|p| self.reader.load(p)).transpose()?;
            prior = slot.as_ref();
        }
        Ok(None)
    }
}

impl<R> LinearFactPerspective<R> {
    fn clear(&mut self) {
        self.map.clear();
    }

    fn apply_updates(&mut self, updates: &[Update]) {
        for update in updates {
            self.map.insert(update.key.clone(), update.value.clone());
        }
    }
}

impl<R: Read> FactPerspective for LinearFactPerspective<R> {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        if let Some(wrapped) = self.map.get(key) {
            return Ok(wrapped.as_deref().map(Box::from));
        }
        match &self.prior {
            FactPerspectivePrior::None => Ok(None),
            FactPerspectivePrior::FactPerspective(prior) => prior.query(key),
            FactPerspectivePrior::FactIndex { offset, reader } => {
                let repr: FactIndexRepr = reader.load(*offset)?;
                let prior = LinearFactIndex {
                    repr,
                    reader: reader.clone(),
                };
                prior.query(key)
            }
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.map.insert(key.into(), Some(value.into()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.map.insert(key.into(), None);
    }
}

impl<R: Read> FactPerspective for LinearPerspective<R> {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        self.facts.query(key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.facts.insert(key, value);
        self.current_updates.push(Update {
            key: key.into(),
            value: Some(value.into()),
        })
    }

    fn delete(&mut self, key: &[u8]) {
        self.facts.delete(key);
        self.current_updates.push(Update {
            key: key.into(),
            value: None,
        })
    }
}

impl<R: Read> Revertable for LinearPerspective<R> {
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            index: self.commands.len(),
        }
    }

    fn revert(&mut self, checkpoint: Checkpoint) {
        self.commands.truncate(checkpoint.index);
        self.facts.clear();
        self.current_updates.clear();
        for data in &self.commands {
            self.facts.apply_updates(&data.updates);
        }
    }
}

impl<R: Read> Perspective for LinearPerspective<R> {
    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn add_command(&mut self, command: &impl Command) -> Result<usize, StorageError> {
        self.commands.push(CommandData {
            id: command.id(),
            priority: command.priority(),
            policy: command.policy().map(Box::from),
            data: command.bytes().into(),
            updates: core::mem::take(&mut self.current_updates),
        });
        Ok(self.commands.len()) // FIXME(jdygert): Off by one?
    }

    fn includes(&self, id: &Id) -> bool {
        self.commands.iter().any(|cmd| cmd.id == *id)
    }
}

impl<'a> Command for LinearCommand<'a> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> Id {
        *self.id
    }

    fn parent(&self) -> Prior<Id> {
        self.parent.copied()
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}
