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

pub mod libc;

#[cfg(feature = "testing")]
pub mod testing;

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec, vec::Vec};

use aranya_crypto::{dangerous::spideroak_crypto::csprng::rand::Rng as _, Csprng, Rng};
use buggy::{bug, Bug, BugExt};
use serde::{Deserialize, Serialize};
use vec1::Vec1;

use crate::{
    Address, Checkpoint, Command, CommandId, Fact, FactIndex, FactPerspective, GraphId, Keys,
    Location, Perspective, PolicyId, Prior, Priority, Query, QueryMut, Revertable, Segment,
    Storage, StorageError, StorageProvider,
};

pub mod io;
pub use io::*;

/// Maximum depth of fact indices before compaction.
///
/// A lower value will speed up search queries but require more compaction,
/// slowing down fact index creation and using more storage space.
///
/// In the future, this may be configurable at runtime or dynamic based on
/// heuristics such as fact density.
///
/// 16 is our initial guess for balance.
///
/// This must be at least 2.
const MAX_FACT_INDEX_DEPTH: usize = 16;

pub struct LinearStorageProvider<FM: IoManager> {
    manager: FM,
    storage: BTreeMap<GraphId, LinearStorage<FM::Writer>>,
}

pub struct LinearStorage<W> {
    writer: W,
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
    parents: Prior<Address>,
    policy: PolicyId,
    /// Offset in file to associated fact index.
    facts: usize,
    commands: Vec1<CommandData>,
    max_cut: usize,
    skip_list: Vec<(Location, usize)>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommandData {
    id: CommandId,
    priority: Priority,
    policy: Option<Bytes>,
    data: Bytes,
    updates: Vec<Update>,
}

pub struct LinearCommand<'a> {
    id: &'a CommandId,
    parent: Prior<Address>,
    priority: Priority,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
    max_cut: usize,
}

type Bytes = Box<[u8]>;

type Update = (String, Keys, Option<Bytes>);
type FactMap = BTreeMap<Keys, Option<Box<[u8]>>>;
type NamedFactMap = BTreeMap<String, FactMap>;

#[derive(Debug)]
pub struct LinearFactIndex<R> {
    repr: FactIndexRepr,
    reader: R,
}

#[derive(Debug, Serialize, Deserialize)]
struct FactIndexRepr {
    /// Self offset in file.
    offset: usize,
    /// Offset of prior fact index.
    prior: Option<usize>,
    /// Depth of this fact index.
    ///
    /// `prior.depth + 1`, or just `1` if no prior
    depth: usize,
    /// Facts in sorted order
    facts: NamedFactMap,
}

#[derive(Debug)]
pub struct LinearPerspective<R> {
    prior: Prior<Location>,
    parents: Prior<Address>,
    policy: PolicyId,
    facts: LinearFactPerspective<R>,
    commands: Vec<CommandData>,
    current_updates: Vec<Update>,
    max_cut: usize,
    last_common_ancestor: Option<(Location, usize)>,
}

impl<R> LinearPerspective<R> {
    fn new(
        prior: Prior<Location>,
        parents: Prior<Address>,
        policy: PolicyId,
        prior_facts: FactPerspectivePrior<R>,
        max_cut: usize,
        last_common_ancestor: Option<(Location, usize)>,
    ) -> Self {
        Self {
            prior,
            parents,
            policy,
            facts: LinearFactPerspective::new(prior_facts),
            commands: Vec::new(),
            current_updates: Vec::new(),
            max_cut,
            last_common_ancestor,
        }
    }
}

#[derive(Debug)]
pub struct LinearFactPerspective<R> {
    map: BTreeMap<String, BTreeMap<Keys, Option<Bytes>>>,
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
    FactIndex { offset: usize, reader: R },
}

impl<R> FactPerspectivePrior<R> {
    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl<FM: IoManager + Default> Default for LinearStorageProvider<FM> {
    fn default() -> Self {
        Self {
            manager: FM::default(),
            storage: BTreeMap::new(),
        }
    }
}

impl<FM: IoManager> LinearStorageProvider<FM> {
    pub fn new(manager: FM) -> Self {
        Self {
            manager,
            storage: BTreeMap::new(),
        }
    }
}

impl<FM: IoManager> StorageProvider for LinearStorageProvider<FM> {
    type Perspective = LinearPerspective<<FM::Writer as Write>::ReadOnly>;
    type Segment = LinearSegment<<FM::Writer as Write>::ReadOnly>;
    type Storage = LinearStorage<FM::Writer>;

    fn new_perspective(&mut self, policy_id: PolicyId) -> Self::Perspective {
        LinearPerspective::new(
            Prior::None,
            Prior::None,
            policy_id,
            FactPerspectivePrior::None,
            0,
            None,
        )
    }

    fn new_storage(
        &mut self,
        init: Self::Perspective,
    ) -> Result<(GraphId, &mut Self::Storage), StorageError> {
        use alloc::collections::btree_map::Entry;

        if init.commands.is_empty() {
            return Err(StorageError::EmptyPerspective);
        }
        let graph_id = GraphId::from(init.commands[0].id.into_id());
        let Entry::Vacant(entry) = self.storage.entry(graph_id) else {
            return Err(StorageError::StorageExists);
        };

        let file = self.manager.create(graph_id)?;
        Ok((graph_id, entry.insert(LinearStorage::create(file, init)?)))
    }

    fn get_storage(&mut self, graph: GraphId) -> Result<&mut Self::Storage, StorageError> {
        use alloc::collections::btree_map::Entry;

        let entry = match self.storage.entry(graph) {
            Entry::Vacant(v) => v,
            Entry::Occupied(o) => return Ok(o.into_mut()),
        };

        let file = self
            .manager
            .open(graph)?
            .ok_or(StorageError::NoSuchStorage)?;
        Ok(entry.insert(LinearStorage::open(file)?))
    }

    fn remove_storage(&mut self, graph: GraphId) -> Result<(), StorageError> {
        self.manager.remove(graph)?;

        let _ = self
            .storage
            .remove(&graph)
            .ok_or(StorageError::NoSuchStorage);

        Ok(())
    }

    fn list_graph_ids(
        &mut self,
    ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
        self.manager.list()
    }
}

impl<W: Write> LinearStorage<W> {
    fn get_skip(
        &self,
        segment: <LinearStorage<W> as Storage>::Segment,
        max_cut: usize,
    ) -> Result<Option<(Location, usize)>, StorageError> {
        let mut head = segment;
        let mut current = None;
        'outer: loop {
            if max_cut > head.longest_max_cut()? {
                return Ok(current);
            }
            current = Some((head.first_location(), head.shortest_max_cut()));
            if max_cut >= head.shortest_max_cut() {
                return Ok(current);
            }
            // Assumes skip list is sorted in ascending order.
            // We always want to skip as close to the root as possible.
            for (skip, skip_max_cut) in head.skip_list() {
                if skip_max_cut <= &max_cut {
                    head = self.get_segment(*skip)?;
                    continue 'outer;
                }
            }
            head = match head.prior() {
                Prior::None | Prior::Merge(_, _) => {
                    return Ok(current);
                }
                Prior::Single(l) => self.get_segment(l)?,
            }
        }
    }
}

impl<W: Write> LinearStorage<W> {
    fn create(mut writer: W, init: LinearPerspective<W::ReadOnly>) -> Result<Self, StorageError> {
        assert!(matches!(init.prior, Prior::None));
        assert!(matches!(init.parents, Prior::None));
        assert!(matches!(init.facts.prior, FactPerspectivePrior::None));

        let mut map = init.facts.map;
        map.retain(|_, kv| !kv.is_empty());

        let facts = writer
            .append(|offset| FactIndexRepr {
                offset,
                prior: None,
                depth: 1,
                facts: map,
            })?
            .offset;

        let commands = init
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;
        let segment = writer.append(|offset| SegmentRepr {
            offset,
            prior: Prior::None,
            parents: Prior::None,
            policy: init.policy,
            facts,
            commands,
            max_cut: 0,
            skip_list: vec![],
        })?;

        let head = Location::new(
            segment.offset,
            segment
                .commands
                .len()
                .checked_sub(1)
                .assume("vec1 length >= 1")?,
        );

        writer.commit(head)?;

        let storage = Self { writer };

        Ok(storage)
    }

    fn open(writer: W) -> Result<Self, StorageError> {
        Ok(Self { writer })
    }

    fn compact(&mut self, mut repr: FactIndexRepr) -> Result<FactIndexRepr, StorageError> {
        let mut map = NamedFactMap::new();
        let reader = self.writer.readonly();
        loop {
            for (name, kv) in repr.facts {
                let sub = map.entry(name).or_default();
                for (k, v) in kv {
                    sub.entry(k).or_insert(v);
                }
            }
            let Some(offset) = repr.prior else { break };
            repr = reader.fetch(offset)?;
        }

        // Since there's no prior, we can remove tombstones
        map.retain(|_, kv| {
            kv.retain(|_, v| v.is_some());
            !kv.is_empty()
        });

        Ok(self
            .write_facts(LinearFactPerspective {
                map,
                prior: FactPerspectivePrior::None,
            })?
            .repr)
    }
}

impl<F: Write> Storage for LinearStorage<F> {
    type Perspective = LinearPerspective<F::ReadOnly>;
    type FactPerspective = LinearFactPerspective<F::ReadOnly>;
    type Segment = LinearSegment<F::ReadOnly>;
    type FactIndex = LinearFactIndex<F::ReadOnly>;

    fn get_command_id(&self, location: Location) -> Result<CommandId, StorageError> {
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
        let command = segment
            .get_command(parent)
            .ok_or(StorageError::CommandOutOfBounds(parent))?;
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
            if facts.prior.is_none() {
                facts.map.retain(|_, kv| !kv.is_empty());
            }
            if facts.map.is_empty() {
                facts.prior
            } else {
                FactPerspectivePrior::FactPerspective(Box::new(facts))
            }
        };
        let prior = Prior::Single(parent);

        let perspective = LinearPerspective::new(
            prior,
            Prior::Single(command.address()?),
            policy,
            prior_facts,
            command
                .max_cut()?
                .checked_add(1)
                .assume("must not overflow")?,
            None,
        );

        Ok(Some(perspective))
    }

    fn get_fact_perspective(
        &self,
        location: Location,
    ) -> Result<Self::FactPerspective, StorageError> {
        let segment = self.get_segment(location)?;

        // If at head of segment, or no facts in segment,
        // we don't need to apply updates.
        if location == segment.head_location()
            || segment
                .repr
                .commands
                .iter()
                .all(|cmd| cmd.updates.is_empty())
        {
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
        last_common_ancestor: (Location, usize),
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Option<Self::Perspective>, StorageError> {
        // TODO(jdygert): ensure braid belongs to this storage.
        // TODO(jdygert): ensure braid ends at given command?
        let left_segment = self.get_segment(left)?;
        let left_command = left_segment
            .get_command(left)
            .ok_or(StorageError::CommandOutOfBounds(left))?;
        let right_segment = self.get_segment(right)?;
        let right_command = right_segment
            .get_command(right)
            .ok_or(StorageError::CommandOutOfBounds(right))?;

        let parent = Prior::Merge(left_command.address()?, right_command.address()?);

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
            left_command
                .max_cut()?
                .max(right_command.max_cut()?)
                .checked_add(1)
                .assume("must not overflow")?,
            Some(last_common_ancestor),
        );

        Ok(Some(perspective))
    }

    fn get_segment(&self, location: Location) -> Result<Self::Segment, StorageError> {
        let reader = self.writer.readonly();
        let repr = reader.fetch(location.segment)?;
        let seg = LinearSegment { repr, reader };

        Ok(seg)
    }

    fn get_head(&self) -> Result<Location, StorageError> {
        self.writer.head()
    }

    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError> {
        if !self.is_ancestor(self.get_head()?, &segment)? {
            return Err(StorageError::HeadNotAncestor);
        }

        self.writer.commit(segment.head_location())
    }

    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError> {
        // TODO(jdygert): Validate prior?

        let facts = self.write_facts(perspective.facts)?.repr.offset;

        let commands: Vec1<CommandData> = perspective
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;

        let get_skips =
            |l: Location, count: usize| -> Result<Vec<(Location, usize)>, StorageError> {
                let mut rng = &mut Rng as &mut dyn Csprng;
                let mut skips = vec![];
                for _ in 0..count {
                    let segment = self.get_segment(l)?;
                    let l_max_cut = segment
                        .get_command(l)
                        .assume("location must exist")?
                        .max_cut;
                    if l_max_cut > 0 {
                        let max_cut = rng.gen_range(0..l_max_cut);
                        if let Some(skip) = self.get_skip(segment, max_cut)? {
                            if !skips.contains(&skip) {
                                skips.push(skip);
                            }
                        } else {
                            break;
                        }
                    }
                }
                Ok(skips)
            };

        let skip_list = match perspective.prior {
            Prior::None => vec![],
            Prior::Merge(_, _) => {
                let (lca, max_cut) = perspective.last_common_ancestor.assume("lca must exist")?;
                let mut skips = get_skips(lca, 2)?;
                if !skips.contains(&(lca, max_cut)) {
                    skips.push((lca, max_cut));
                }
                skips.sort();
                skips
            }
            Prior::Single(l) => {
                let mut skips = get_skips(l, 3)?;
                skips.sort();
                skips
            }
        };
        let repr = self.writer.append(|offset| SegmentRepr {
            offset,
            prior: perspective.prior,
            parents: perspective.parents,
            policy: perspective.policy,
            facts,
            commands,
            max_cut: perspective.max_cut,
            skip_list,
        })?;

        Ok(LinearSegment {
            repr,
            reader: self.writer.readonly(),
        })
    }

    fn write_facts(
        &mut self,
        facts: Self::FactPerspective,
    ) -> Result<Self::FactIndex, StorageError> {
        let mut prior = match facts.prior {
            FactPerspectivePrior::None => None,
            FactPerspectivePrior::FactPerspective(prior) => {
                let prior = self.write_facts(*prior)?;
                if facts.map.is_empty() {
                    return Ok(prior);
                }
                Some(prior.repr)
            }
            FactPerspectivePrior::FactIndex { offset, reader } => {
                let repr = reader.fetch(offset)?;
                if facts.map.is_empty() {
                    return Ok(LinearFactIndex { repr, reader });
                }
                Some(repr)
            }
        };

        let depth = if let Some(mut p) = prior.take() {
            if p.depth > MAX_FACT_INDEX_DEPTH - 1 {
                p = self.compact(p)?;
            }
            prior.insert(p).depth
        } else {
            0
        };

        let depth = depth.checked_add(1).assume("depth won't overflow")?;

        if depth > MAX_FACT_INDEX_DEPTH {
            bug!("fact index too deep");
        }

        let repr = self.writer.append(|offset| FactIndexRepr {
            offset,
            prior: prior.map(|p| p.offset),
            depth,
            facts: facts.map,
        })?;

        Ok(LinearFactIndex {
            repr,
            reader: self.writer.readonly(),
        })
    }
}

impl<R: Read> Segment for LinearSegment<R> {
    type FactIndex = LinearFactIndex<R>;
    type Command<'a>
        = LinearCommand<'a>
    where
        R: 'a;

    fn head(&self) -> Result<Self::Command<'_>, StorageError> {
        let data = self.repr.commands.last();
        let parent = if let Some(prev) = usize::checked_sub(self.repr.commands.len(), 2) {
            Prior::Single(Address {
                id: self.repr.commands[prev].id,
                max_cut: self
                    .repr
                    .max_cut
                    .checked_add(prev)
                    .assume("must not overflow")?,
            })
        } else {
            self.repr.parents
        };
        Ok(LinearCommand {
            id: &data.id,
            parent,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
            max_cut: self
                .repr
                .max_cut
                .checked_add(self.repr.commands.len())
                .assume("must not overflow")?
                .checked_sub(1)
                .assume("must not overflow")?,
        })
    }

    fn first(&self) -> Self::Command<'_> {
        let data = self.repr.commands.first();
        LinearCommand {
            id: &data.id,
            parent: self.repr.parents,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
            max_cut: self.repr.max_cut,
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
            if let Some(max_cut) = self.repr.max_cut.checked_add(prev) {
                Prior::Single(Address {
                    id: self.repr.commands[prev].id,
                    max_cut,
                })
            } else {
                return None;
            }
        } else {
            self.repr.parents
        };
        self.repr
            .max_cut
            .checked_add(location.command)
            .map(|max_cut| LinearCommand {
                id: &data.id,
                parent,
                priority: data.priority.clone(),
                policy: data.policy.as_deref(),
                data: &data.data,
                max_cut,
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

    fn get_from_max_cut(&self, max_cut: usize) -> Result<Option<Location>, StorageError> {
        if max_cut >= self.repr.max_cut
            && max_cut
                <= self
                    .repr
                    .max_cut
                    .checked_add(self.repr.commands.len())
                    .assume("must not overflow")?
        {
            return Ok(Some(Location::new(
                self.repr.offset,
                max_cut
                    .checked_sub(self.repr.max_cut)
                    .assume("must not overflow")?,
            )));
        }
        Ok(None)
    }

    fn facts(&self) -> Result<Self::FactIndex, StorageError> {
        Ok(LinearFactIndex {
            repr: self.reader.fetch(self.repr.facts)?,
            reader: self.reader.clone(),
        })
    }

    fn skip_list(&self) -> &[(Location, usize)] {
        &self.repr.skip_list
    }

    fn shortest_max_cut(&self) -> usize {
        self.repr.max_cut
    }

    fn longest_max_cut(&self) -> Result<usize, StorageError> {
        Ok(self
            .repr
            .max_cut
            .checked_add(self.repr.commands.len())
            .assume("must not overflow")?
            .checked_sub(1)
            .assume("must not overflow")?)
    }
}

impl<R: Read> FactIndex for LinearFactIndex<R> {}

type MapIter = alloc::collections::btree_map::IntoIter<Keys, Option<Bytes>>;
pub struct QueryIterator {
    it: MapIter,
}

impl QueryIterator {
    fn new(it: MapIter) -> Self {
        Self { it }
    }
}

impl Iterator for QueryIterator {
    type Item = Result<Fact, StorageError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // filter out tombstones
            if let (key, Some(value)) = self.it.next()? {
                return Some(Ok(Fact { key, value }));
            }
        }
    }
}

impl<R: Read> Query for LinearFactIndex<R> {
    fn query(&self, name: &str, keys: &[Box<[u8]>]) -> Result<Option<Box<[u8]>>, StorageError> {
        let mut prior = Some(&self.repr);
        let mut slot; // Need to store deserialized value.
        while let Some(facts) = prior {
            if let Some(v) = facts.facts.get(name).and_then(|m| m.get(keys)) {
                return Ok(v.as_ref().cloned());
            }
            slot = facts.prior.map(|p| self.reader.fetch(p)).transpose()?;
            prior = slot.as_ref();
        }
        Ok(None)
    }

    type QueryIterator = QueryIterator;
    fn query_prefix(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<QueryIterator, StorageError> {
        Ok(QueryIterator::new(
            self.query_prefix_inner(name, prefix)?.into_iter(),
        ))
    }
}

impl<R: Read> LinearFactIndex<R> {
    fn query_prefix_inner(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<FactMap, StorageError> {
        let mut matches = BTreeMap::new();
        let mut prior = Some(&self.repr);
        let mut slot; // Need to store deserialized value.
        while let Some(facts) = prior {
            if let Some(map) = facts.facts.get(name) {
                for (k, v) in super::memory::find_prefixes(map, prefix) {
                    // don't override, if we've already found the fact (including deletions)
                    if !matches.contains_key(k) {
                        matches.insert(k.clone(), v.map(Into::into));
                    }
                }
            }
            slot = facts.prior.map(|p| self.reader.fetch(p)).transpose()?;
            prior = slot.as_ref();
        }
        Ok(matches)
    }
}

impl<R> LinearFactPerspective<R> {
    fn clear(&mut self) {
        self.map.clear();
    }

    fn apply_updates(&mut self, updates: &[Update]) {
        for (name, key, value) in updates {
            if self.prior.is_none() {
                if let Some(value) = value {
                    self.map
                        .entry(name.clone())
                        .or_default()
                        .insert(key.clone(), Some(value.clone()));
                } else if let Some(e) = self.map.get_mut(name) {
                    e.remove(key);
                }
            } else {
                self.map
                    .entry(name.clone())
                    .or_default()
                    .insert(key.clone(), value.clone());
            }
        }
    }
}

impl<R: Read> FactPerspective for LinearFactPerspective<R> {}

impl<R: Read> Query for LinearFactPerspective<R> {
    fn query(&self, name: &str, keys: &[Box<[u8]>]) -> Result<Option<Box<[u8]>>, StorageError> {
        if let Some(wrapped) = self.map.get(name).and_then(|m| m.get(keys)) {
            return Ok(wrapped.as_deref().map(Box::from));
        }
        match &self.prior {
            FactPerspectivePrior::None => Ok(None),
            FactPerspectivePrior::FactPerspective(prior) => prior.query(name, keys),
            FactPerspectivePrior::FactIndex { offset, reader } => {
                let repr: FactIndexRepr = reader.fetch(*offset)?;
                let prior = LinearFactIndex {
                    repr,
                    reader: reader.clone(),
                };
                prior.query(name, keys)
            }
        }
    }

    type QueryIterator = QueryIterator;
    fn query_prefix(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<QueryIterator, StorageError> {
        Ok(QueryIterator::new(
            self.query_prefix_inner(name, prefix)?.into_iter(),
        ))
    }
}

impl<R: Read> LinearFactPerspective<R> {
    fn query_prefix_inner(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<FactMap, StorageError> {
        let mut matches = match &self.prior {
            FactPerspectivePrior::None => BTreeMap::new(),
            FactPerspectivePrior::FactPerspective(prior) => {
                prior.query_prefix_inner(name, prefix)?
            }
            FactPerspectivePrior::FactIndex { offset, reader } => {
                let repr: FactIndexRepr = reader.fetch(*offset)?;
                let prior = LinearFactIndex {
                    repr,
                    reader: reader.clone(),
                };
                prior.query_prefix_inner(name, prefix)?
            }
        };
        if let Some(map) = self.map.get(name) {
            for (k, v) in super::memory::find_prefixes(map, prefix) {
                // overwrite "earlier" facts
                matches.insert(k.clone(), v.map(Into::into));
            }
        }
        Ok(matches)
    }
}

impl<R: Read> QueryMut for LinearFactPerspective<R> {
    fn insert(&mut self, name: String, keys: Keys, value: Bytes) {
        self.map.entry(name).or_default().insert(keys, Some(value));
    }

    fn delete(&mut self, name: String, keys: Keys) {
        if self.prior.is_none() {
            // No need for tombstones with no prior.
            if let Some(kv) = self.map.get_mut(&name) {
                kv.remove(&keys);
            }
        } else {
            self.map.entry(name).or_default().insert(keys, None);
        }
    }
}

impl<R: Read> FactPerspective for LinearPerspective<R> {}

impl<R: Read> Query for LinearPerspective<R> {
    fn query(&self, name: &str, keys: &[Box<[u8]>]) -> Result<Option<Box<[u8]>>, StorageError> {
        self.facts.query(name, keys)
    }

    type QueryIterator = QueryIterator;
    fn query_prefix(
        &self,
        name: &str,
        prefix: &[Box<[u8]>],
    ) -> Result<QueryIterator, StorageError> {
        self.facts.query_prefix(name, prefix)
    }
}

impl<R: Read> QueryMut for LinearPerspective<R> {
    fn insert(&mut self, name: String, keys: Keys, value: Bytes) {
        self.facts.insert(name.clone(), keys.clone(), value.clone());
        self.current_updates.push((name, keys, Some(value)));
    }

    fn delete(&mut self, name: String, keys: Keys) {
        self.facts.delete(name.clone(), keys.clone());
        self.current_updates.push((name, keys, None))
    }
}

impl<R: Read> Revertable for LinearPerspective<R> {
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            index: self.commands.len(),
        }
    }

    fn revert(&mut self, checkpoint: Checkpoint) -> Result<(), Bug> {
        if checkpoint.index == self.commands.len() {
            return Ok(());
        }

        if checkpoint.index > self.commands.len() {
            bug!("A checkpoint's index should always be less than or equal to the length of a perspective's command history!");
        }

        self.commands.truncate(checkpoint.index);
        self.facts.clear();
        self.current_updates.clear();
        for data in &self.commands {
            self.facts.apply_updates(&data.updates);
        }

        Ok(())
    }
}

impl<R: Read> Perspective for LinearPerspective<R> {
    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn add_command(&mut self, command: &impl Command) -> Result<usize, StorageError> {
        if command.parent() != self.head_address()? {
            return Err(StorageError::PerspectiveHeadMismatch);
        }

        self.commands.push(CommandData {
            id: command.id(),
            priority: command.priority(),
            policy: command.policy().map(Box::from),
            data: command.bytes().into(),
            updates: core::mem::take(&mut self.current_updates),
        });
        Ok(self.commands.len())
    }

    fn includes(&self, id: CommandId) -> bool {
        self.commands.iter().any(|cmd| cmd.id == id)
    }

    fn head_address(&self) -> Result<Prior<Address>, Bug> {
        Ok(if let Some(last) = self.commands.last() {
            Prior::Single(Address {
                id: last.id,
                max_cut: self
                    .max_cut
                    .checked_add(self.commands.len())
                    .assume("must not overflow")?
                    .checked_sub(1)
                    .assume("must not overflow")?,
            })
        } else {
            self.parents
        })
    }
}

impl From<Prior<Address>> for Prior<CommandId> {
    fn from(p: Prior<Address>) -> Self {
        match p {
            Prior::None => Prior::None,
            Prior::Single(l) => Prior::Single(l.id),
            Prior::Merge(l, r) => Prior::Merge(l.id, r.id),
        }
    }
}

impl Command for LinearCommand<'_> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CommandId {
        *self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.parent
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }

    fn max_cut(&self) -> Result<usize, Bug> {
        Ok(self.max_cut)
    }
}

#[cfg(test)]
mod test {
    use testing::Manager;

    use super::*;
    use crate::testing::dsl::{test_suite, StorageBackend};

    #[test]
    fn test_query_prefix() {
        let mut provider = LinearStorageProvider::new(Manager::new());
        let mut fp = provider.new_perspective(PolicyId::new(0));

        let name = "x";

        let keys: &[&[&str]] = &[
            &["aa", "xy", "123"],
            &["aa", "xz", "123"],
            &["bb", "ccc"],
            &["bc", ""],
        ];
        let keys: Vec<Keys> = keys
            .iter()
            .map(|ks| ks.iter().map(|k| k.as_bytes()).collect())
            .collect();

        for ks in &keys {
            fp.insert(
                name.into(),
                ks.clone(),
                format!("{ks:?}").into_bytes().into(),
            );
        }

        let prefixes: &[&[&str]] = &[
            &["aa", "xy", "12"],
            &["aa", "xy"],
            &["aa", "xz"],
            &["aa", "x"],
            &["bb", ""],
            &["bb", "ccc"],
            &["bc", ""],
            &["bc", "", ""],
        ];

        for prefix in prefixes {
            let prefix: Keys = prefix.iter().map(|k| k.as_bytes()).collect();
            let found: Vec<_> = fp.query_prefix(name, &prefix).unwrap().collect();
            let mut expected: Vec<_> = keys.iter().filter(|k| k.starts_with(&prefix)).collect();
            expected.sort();
            assert_eq!(found.len(), expected.len());
            for (a, b) in std::iter::zip(found, expected) {
                let a = a.unwrap();
                assert_eq!(&a.key, b);
                assert_eq!(a.value.as_ref(), format!("{b:?}").as_bytes());
            }
        }
    }

    struct LinearBackend;
    impl StorageBackend for LinearBackend {
        type StorageProvider = LinearStorageProvider<Manager>;

        fn provider(&mut self, _client_id: u64) -> Self::StorageProvider {
            LinearStorageProvider::new(Manager::new())
        }
    }
    test_suite!(|| LinearBackend);
}
