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
use core::ops::Bound;

use buggy::{Bug, BugExt as _, bug};
use serde::{Deserialize, Serialize};
use vec1::Vec1;

use crate::{
    Address, Bytes, Checkpoint, CmdId, Command, Fact, FactIndex, FactPerspective, GraphId, HeadSet,
    Keys, LocatedAddress, Location, MaxCut, Perspective, PolicyId, Prior, Priority, Query,
    QueryMut, Revertable, Segment, SegmentIndex, Storage, StorageError, StorageProvider,
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
const MAX_FACT_INDEX_DEPTH: u64 = 16;

pub struct LinearStorageProvider<FM: IoManager> {
    manager: FM,
    storage: BTreeMap<GraphId, LinearStorage<FM::Writer>>,
}

pub struct LinearStorage<W> {
    writer: W,
    /// In-memory copy of the committed head set, kept in sync on every commit.
    /// Lets [`get_heads`](Storage::get_heads) hand out a borrow without
    /// re-reading or deserializing the set on hot paths.
    cached_heads: HeadSet,
}

#[derive(Debug)]
pub struct LinearSegment<R> {
    repr: SegmentRepr,
    reader: R,
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentRepr {
    /// Self offset in file.
    offset: SegmentIndex,
    prior: Prior<Location>,
    parents: Prior<Address>,
    policy: PolicyId,
    /// Offset in file to associated fact index.
    facts: u64,
    commands: Vec1<CommandData>,
    max_cut: MaxCut,
    skip_list: Vec<Location>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CommandData {
    id: CmdId,
    priority: Priority,
    policy: Option<Bytes>,
    data: Bytes,
    updates: Vec<Update>,
}

pub struct LinearCommand<'a> {
    id: &'a CmdId,
    parent: Prior<Address>,
    priority: Priority,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
    max_cut: MaxCut,
}

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
    offset: u64,
    /// Offset of prior fact index.
    prior: Option<u64>,
    /// Depth of this fact index.
    ///
    /// `prior.depth + 1`, or just `1` if no prior
    depth: u64,
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
    max_cut: MaxCut,
    last_common_ancestor: Option<Location>,
}

impl<R> LinearPerspective<R> {
    fn new(
        prior: Prior<Location>,
        parents: Prior<Address>,
        policy: PolicyId,
        prior_facts: FactPerspectivePrior<R>,
        max_cut: MaxCut,
        last_common_ancestor: Option<Location>,
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
    FactIndex { offset: u64, reader: R },
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
            MaxCut::new(0),
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
        let graph_id = GraphId::transmute(init.commands[0].id);
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

        self.storage
            .remove(&graph)
            .ok_or(StorageError::NoSuchStorage)?;

        Ok(())
    }

    fn list_graph_ids(
        &mut self,
    ) -> Result<impl Iterator<Item = Result<GraphId, StorageError>>, StorageError> {
        self.manager.list()
    }
}

/// Maximum segment-walk distance for skip-list construction. Below this
/// threshold the segments are cheap enough to walk one-by-one, so neither
/// the rich-anchor probe nor a freshly built skip list pay for themselves.
const MIN_SKIP_GAP: u64 = 10;

/// Skip-list target boundaries for a segment of length `n`: `n/2`, `3n/4`,
/// `7n/8`, ..., halving the remaining gap each step. Continues until the
/// gap from the final boundary to `n` is ≤ [`MIN_SKIP_GAP`], so the walk
/// from head to the first skip entry never exceeds the cheap-walk
/// threshold. Returned ascending; callers walk backwards and pop
/// highest-first. Empty when `n < 2`.
fn skip_target_boundaries(n: u64) -> Result<Vec<MaxCut>, StorageError> {
    let mut targets = vec![];
    let mut boundary = n / 2;
    while boundary > 0 {
        targets.push(MaxCut::new(boundary));
        let gap = n
            .checked_sub(boundary)
            .assume("boundary < n by loop invariant")?;
        if gap <= MIN_SKIP_GAP {
            break;
        }
        boundary = boundary
            .checked_add(gap / 2)
            .assume("boundary + gap/2 <= n <= u64::MAX")?;
    }
    Ok(targets)
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
            offset: SegmentIndex::new(offset),
            prior: Prior::None,
            parents: Prior::None,
            policy: init.policy,
            facts,
            commands,
            max_cut: MaxCut::new(0),
            skip_list: vec![],
        })?;

        let max_cut = segment
            .max_cut
            .checked_add(
                segment
                    .commands
                    .len()
                    .checked_sub(1)
                    .assume("vec1 length >= 1")? as u64,
            )
            .assume("valid max cut")?;
        let head = LocatedAddress {
            id: segment.commands.last().id,
            segment: segment.offset,
            max_cut,
        };

        // Seed both the one-element head set and the fact cache (the init
        // segment's fact index, stored at `facts`).
        let cached_heads = HeadSet::single(head);
        writer.commit(&cached_heads, facts)?;

        let storage = Self {
            writer,
            cached_heads,
        };

        Ok(storage)
    }

    fn open(writer: W) -> Result<Self, StorageError> {
        let cached_heads = writer.heads()?;
        Ok(Self {
            writer,
            cached_heads,
        })
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

    /// Whether an ancestor within [`MIN_SKIP_GAP`] segments of `start` already
    /// carries a rich skip list (`len > 1`). The walk crosses merges via the
    /// LCA recorded as the sole entry in a merge segment's LCA-only skip list,
    /// so a rich anchor past a merge is still reachable.
    fn has_nearby_rich_anchor(&self, start: Location) -> Result<bool, StorageError> {
        let mut check = start;
        for _ in 0..MIN_SKIP_GAP {
            let seg = self.get_segment(check)?;
            if seg.skip_list().len() > 1 {
                return Ok(true);
            }
            match seg.prior() {
                Prior::Single(p) => check = p,
                Prior::Merge(_, _) => {
                    check = seg
                        .skip_list()
                        .last()
                        .copied()
                        .assume("merge skip list must end with LCA")?;
                }
                Prior::None => return Ok(false),
            }
        }
        Ok(false)
    }

    /// Build the skip list for a new segment with the given `prior`,
    /// `last_common_ancestor` (required for merges), and length `n`.
    ///
    /// Returns:
    /// - empty for `Prior::None`,
    /// - `[lca]` (or empty for non-merges) when a nearby ancestor already
    ///   has a rich skip list or `n < MIN_SKIP_GAP`,
    /// - otherwise, a list of skip targets at `n/2, 3n/4, 7n/8, ...` plus
    ///   the LCA for merges. See [`skip_target_boundaries`].
    fn build_skip_list(
        &self,
        prior: Prior<Location>,
        last_common_ancestor: Option<Location>,
        n: u64,
    ) -> Result<Vec<Location>, StorageError> {
        let (walk_start, lca) = match prior {
            Prior::None => return Ok(vec![]),
            Prior::Merge(_, _) => {
                let lca = last_common_ancestor.assume("lca must exist")?;
                (lca, Some(lca))
            }
            Prior::Single(l) => (l, None),
        };

        if self.has_nearby_rich_anchor(walk_start)? || n < MIN_SKIP_GAP {
            return Ok(lca.into_iter().collect());
        }

        let targets = skip_target_boundaries(n)?;
        let mut skips = self.walk_collecting_skips(walk_start, targets)?;

        // Always include the LCA for merge segments.
        if let Some(lca) = lca
            && !skips.contains(&lca)
        {
            skips.push(lca);
        }

        skips.sort_by_key(|loc| loc.max_cut);
        skips.dedup();
        Ok(skips)
    }

    /// Walk backwards from `start`, recording the `first_location` of each
    /// segment as it crosses a target in `targets` (ascending; consumed
    /// highest-first via `pop`). At each segment, jump along the smallest
    /// available skip entry that still stays at or above the next target;
    /// otherwise step to the parent. Stops when targets are exhausted or
    /// no further progress toward them is possible.
    fn walk_collecting_skips(
        &self,
        start: Location,
        mut targets: Vec<MaxCut>,
    ) -> Result<Vec<Location>, StorageError> {
        let mut skips = vec![];
        let mut current = start;

        loop {
            let seg = self.get_segment(current)?;
            let seg_min = seg.shortest_max_cut();

            // Record any targets we've reached or passed.
            while let Some(&t) = targets.last() {
                if t >= seg_min {
                    skips.push(seg.first_location());
                    targets.pop();
                } else {
                    break;
                }
            }

            let Some(&next_target) = targets.last() else {
                break;
            };

            // Smallest skip entry at or above next_target (and below
            // current), i.e. the tightest jump that still makes progress.
            let best = seg
                .skip_list()
                .iter()
                .copied()
                .filter(|s| s.max_cut >= next_target && s.max_cut < current.max_cut)
                .min_by_key(|s| s.max_cut);
            if let Some(skip) = best {
                current = skip;
                continue;
            }

            match seg.prior() {
                Prior::Single(p) if p.max_cut >= next_target => current = p,
                _ => break,
            }
        }

        Ok(skips)
    }
}

impl<F: Write> Storage for LinearStorage<F> {
    type Perspective = LinearPerspective<F::ReadOnly>;
    type FactPerspective = LinearFactPerspective<F::ReadOnly>;
    type Segment = LinearSegment<F::ReadOnly>;
    type FactIndex = LinearFactIndex<F::ReadOnly>;

    fn get_linear_perspective(&self, parent: Location) -> Result<Self::Perspective, StorageError> {
        let segment = self.get_segment(parent)?;
        let command = segment
            .get_command(parent)
            .ok_or(StorageError::CommandOutOfBounds(parent))?;
        let policy = segment.repr.policy;
        let prior_facts: FactPerspectivePrior<F::ReadOnly> = if parent == segment.head_location()? {
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
            for data in &segment.repr.commands[..=segment.repr.cmd_index(parent.max_cut)?] {
                facts.apply_updates(&data.updates)?;
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

        Ok(perspective)
    }

    fn get_fact_perspective(
        &self,
        location: Location,
    ) -> Result<Self::FactPerspective, StorageError> {
        let segment = self.get_segment(location)?;

        // If at head of segment, or no facts in segment,
        // we don't need to apply updates.
        if location == segment.head_location()?
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
        for data in &segment.repr.commands[..=segment.repr.cmd_index(location.max_cut)?] {
            facts.apply_updates(&data.updates)?;
        }

        Ok(facts)
    }

    fn new_merge_perspective(
        &self,
        left: Location,
        right: Location,
        last_common_ancestor: Location,
        policy_id: PolicyId,
        braid: Self::FactIndex,
    ) -> Result<Self::Perspective, StorageError> {
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

        Ok(perspective)
    }

    fn get_segment(&self, location: Location) -> Result<Self::Segment, StorageError> {
        let reader = self.writer.readonly();
        let repr = reader.fetch(location.segment.get())?;
        let seg = LinearSegment { repr, reader };

        Ok(seg)
    }

    fn get_heads(&self) -> Result<&HeadSet, StorageError> {
        Ok(&self.cached_heads)
    }

    fn fact_cache(&self) -> Result<Self::FactIndex, StorageError> {
        let offset = self.writer.fact_cache()?;
        Ok(LinearFactIndex {
            repr: self.writer.readonly().fetch(offset)?,
            reader: self.writer.readonly(),
        })
    }

    fn commit_heads(
        &mut self,
        heads: HeadSet,
        fact_cache: Self::FactIndex,
    ) -> Result<(), StorageError> {
        self.writer.commit(&heads, fact_cache.repr.offset)?;
        self.cached_heads = heads;
        Ok(())
    }

    fn write(&mut self, perspective: Self::Perspective) -> Result<Self::Segment, StorageError> {
        // TODO(jdygert): Validate prior?

        let facts = self.write_facts(perspective.facts)?.repr.offset;

        let commands: Vec1<CommandData> = perspective
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;

        let skip_list = self.build_skip_list(
            perspective.prior,
            perspective.last_common_ancestor,
            perspective.max_cut.get(),
        )?;

        let repr = self.writer.append(|offset| SegmentRepr {
            offset: SegmentIndex::new(offset),
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

    fn index(&self) -> SegmentIndex {
        self.repr.offset
    }

    fn head_id(&self) -> CmdId {
        self.repr.commands.last().id
    }

    fn first_location(&self) -> Location {
        Location::new(self.repr.offset, self.repr.max_cut)
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
        let cmd_idx = self.repr.cmd_index(location.max_cut).ok()?;
        let data = self.repr.commands.get(cmd_idx)?;
        let parent = if let Some(prev) = usize::checked_sub(cmd_idx, 1) {
            if let Some(max_cut) = self.repr.max_cut.checked_add(prev as u64) {
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
        Some(LinearCommand {
            id: &data.id,
            parent,
            priority: data.priority.clone(),
            policy: data.policy.as_deref(),
            data: &data.data,
            max_cut: location.max_cut,
        })
    }

    fn facts(&self) -> Result<Self::FactIndex, StorageError> {
        Ok(LinearFactIndex {
            repr: self.reader.fetch(self.repr.facts)?,
            reader: self.reader.clone(),
        })
    }

    fn skip_list(&self) -> &[Location] {
        &self.repr.skip_list
    }

    fn shortest_max_cut(&self) -> MaxCut {
        self.repr.max_cut
    }

    fn longest_max_cut(&self) -> Result<MaxCut, StorageError> {
        Ok(self
            .repr
            .max_cut
            .checked_add(
                self.repr
                    .commands
                    .len()
                    .checked_sub(1)
                    .assume("must not overflow")? as u64,
            )
            .assume("must not overflow")?)
    }
}

impl SegmentRepr {
    fn cmd_index(&self, max_cut: MaxCut) -> Result<usize, StorageError> {
        max_cut
            .distance_from(self.max_cut)
            .and_then(|x| usize::try_from(x).ok())
            .ok_or(StorageError::CommandOutOfBounds(Location::new(
                self.offset,
                max_cut,
            )))
    }
}

impl<R: Read> FactIndex for LinearFactIndex<R> {}

#[cfg(all(test, feature = "graphviz"))]
impl<R: Read> crate::storage::FactIndexExtra for LinearFactIndex<R> {
    fn name(&self) -> String {
        use alloc::string::ToString as _;
        self.repr.offset.to_string()
    }

    fn prior(&self) -> Result<Option<Self>, StorageError> {
        self.repr
            .prior
            .map(|p| {
                let repr = self.reader.fetch(p)?;
                Ok(Self {
                    repr,
                    reader: self.reader.clone(),
                })
            })
            .transpose()
    }
}

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
    fn query(&self, name: &str, keys: &[Bytes]) -> Result<Option<Bytes>, StorageError> {
        let mut prior = Some(&self.repr);
        let mut slot; // Need to store deserialized value.
        while let Some(facts) = prior {
            if let Some(v) = facts.facts.get(name).and_then(|m| m.get(keys)) {
                return Ok(v.clone());
            }
            slot = facts.prior.map(|p| self.reader.fetch(p)).transpose()?;
            prior = slot.as_ref();
        }
        Ok(None)
    }

    type QueryIterator = QueryIterator;
    fn query_prefix(&self, name: &str, prefix: &[Bytes]) -> Result<QueryIterator, StorageError> {
        Ok(QueryIterator::new(
            self.query_prefix_inner(name, prefix)?.into_iter(),
        ))
    }
}

impl<R: Read> LinearFactIndex<R> {
    fn query_prefix_inner(&self, name: &str, prefix: &[Bytes]) -> Result<FactMap, StorageError> {
        let mut matches = BTreeMap::new();
        let mut prior = Some(&self.repr);
        let mut slot; // Need to store deserialized value.
        while let Some(facts) = prior {
            if let Some(map) = facts.facts.get(name) {
                for (k, v) in find_prefixes(map, prefix) {
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

    fn apply_updates(&mut self, updates: &[Update]) -> Result<(), StorageError> {
        for (name, keys, value) in updates {
            if self.prior.is_none() {
                if let Some(value) = value {
                    self.map
                        .entry(name.clone())
                        .or_default()
                        .insert(keys.clone(), Some(value.clone()));
                } else if let Some(e) = self.map.get_mut(name) {
                    e.remove(keys);
                }
            } else {
                self.map
                    .entry(name.clone())
                    .or_default()
                    .insert(keys.clone(), value.clone());
            }
        }
        Ok(())
    }
}

impl<R: Read> FactPerspective for LinearFactPerspective<R> {}

impl<R: Read> Query for LinearFactPerspective<R> {
    fn query(&self, name: &str, keys: &[Bytes]) -> Result<Option<Bytes>, StorageError> {
        if let Some(wrapped) = self.map.get(name).and_then(|m| m.get(keys)) {
            return Ok(wrapped.as_deref().map(Bytes::from));
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
    fn query_prefix(&self, name: &str, prefix: &[Bytes]) -> Result<QueryIterator, StorageError> {
        Ok(QueryIterator::new(
            self.query_prefix_inner(name, prefix)?.into_iter(),
        ))
    }
}

impl<R: Read> LinearFactPerspective<R> {
    fn query_prefix_inner(&self, name: &str, prefix: &[Bytes]) -> Result<FactMap, StorageError> {
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
            for (k, v) in find_prefixes(map, prefix) {
                // overwrite "earlier" facts
                matches.insert(k.clone(), v.map(Into::into));
            }
        }
        Ok(matches)
    }
}

impl<R: Read> QueryMut for LinearFactPerspective<R> {
    fn insert(&mut self, name: String, keys: Keys, value: Bytes) -> Result<(), StorageError> {
        self.map.entry(name).or_default().insert(keys, Some(value));
        Ok(())
    }

    fn delete(&mut self, name: String, keys: Keys) -> Result<(), StorageError> {
        if self.prior.is_none() {
            // No need for tombstones with no prior.
            if let Some(kv) = self.map.get_mut(&name) {
                kv.remove(&keys);
            }
        } else {
            self.map.entry(name).or_default().insert(keys, None);
        }
        Ok(())
    }
}

impl<R: Read> FactPerspective for LinearPerspective<R> {}

impl<R: Read> Query for LinearPerspective<R> {
    fn query(&self, name: &str, keys: &[Bytes]) -> Result<Option<Bytes>, StorageError> {
        self.facts.query(name, keys)
    }

    type QueryIterator = QueryIterator;
    fn query_prefix(&self, name: &str, prefix: &[Bytes]) -> Result<QueryIterator, StorageError> {
        self.facts.query_prefix(name, prefix)
    }
}

impl<R: Read> QueryMut for LinearPerspective<R> {
    fn insert(&mut self, name: String, keys: Keys, value: Bytes) -> Result<(), StorageError> {
        self.facts
            .insert(name.clone(), keys.clone(), value.clone())?;
        self.current_updates.push((name, keys, Some(value)));
        Ok(())
    }

    fn delete(&mut self, name: String, keys: Keys) -> Result<(), StorageError> {
        self.facts.delete(name.clone(), keys.clone())?;
        self.current_updates.push((name, keys, None));
        Ok(())
    }
}

impl<R: Read> Revertable for LinearPerspective<R> {
    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            index: self.commands.len(),
        }
    }

    fn revert(&mut self, checkpoint: Checkpoint) -> Result<(), StorageError> {
        if checkpoint.index == self.commands.len() {
            return Ok(());
        }

        if checkpoint.index > self.commands.len() {
            bug!(
                "A checkpoint's index should always be less than or equal to the length of a perspective's command history!"
            );
        }

        self.commands.truncate(checkpoint.index);
        self.facts.clear();
        self.current_updates.clear();
        for data in &self.commands {
            self.facts.apply_updates(&data.updates)?;
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
            policy: command.policy().map(Bytes::from),
            data: command.bytes().into(),
            updates: core::mem::take(&mut self.current_updates),
        });
        Ok(self.commands.len())
    }

    fn includes(&self, id: CmdId) -> bool {
        self.commands.iter().any(|cmd| cmd.id == id)
    }

    fn head_address(&self) -> Result<Prior<Address>, Bug> {
        Ok(if let Some(last) = self.commands.last() {
            Prior::Single(Address {
                id: last.id,
                max_cut: self
                    .max_cut
                    .checked_add(
                        self.commands
                            .len()
                            .checked_sub(1)
                            .assume("must not overflow")? as u64,
                    )
                    .assume("must not overflow")?,
            })
        } else {
            self.parents
        })
    }
}

impl From<Prior<Address>> for Prior<CmdId> {
    fn from(p: Prior<Address>) -> Self {
        match p {
            Prior::None => Self::None,
            Prior::Single(l) => Self::Single(l.id),
            Prior::Merge(l, r) => Self::Merge(l.id, r.id),
        }
    }
}

impl Command for LinearCommand<'_> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> CmdId {
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

    fn max_cut(&self) -> Result<MaxCut, Bug> {
        Ok(self.max_cut)
    }
}

fn find_prefixes<'m, 'p: 'm>(
    map: &'m FactMap,
    prefix: &'p [Bytes],
) -> impl Iterator<Item = (&'m Keys, Option<&'m [u8]>)> + 'm {
    map.range::<[Bytes], _>((Bound::Included(prefix), Bound::Unbounded))
        .take_while(|(k, _)| k.starts_with(prefix))
        .map(|(k, v)| (k, v.as_deref()))
}

#[cfg(test)]
mod test {
    use testing::Manager;

    use super::*;
    use crate::testing::dsl::{StorageBackend, test_suite};

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
            .map(|ks| ks.iter().map(|k| Bytes::from(k.as_bytes())).collect())
            .collect();

        for ks in &keys {
            fp.insert(
                name.into(),
                ks.clone(),
                format!("{ks:?}").into_bytes().into(),
            )
            .unwrap();
        }

        let prefixes: &[&[&str]] = &[
            &["aa", "xy", "12"],
            &["aa", "xy"],
            &["aa", "xz"],
            &["aa", "x"],
            &["bb", ""],
            &["bb", "ccc"],
            &["bc", ""],
        ];

        for prefix in prefixes {
            let prefix: Keys = prefix.iter().map(|k| Bytes::from(k.as_bytes())).collect();
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
