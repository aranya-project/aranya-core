use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::ops::Deref;

use vec1::Vec1;

use super::*;

#[derive(Debug)]
pub struct MemCommand {
    priority: Priority,
    id: Id,
    parent: Prior<Id>,
    policy: Option<Box<[u8]>>,
    data: Box<[u8]>,
}

impl<'a, C: Command<'a>> From<&C> for MemCommand {
    fn from(command: &C) -> Self {
        let policy = command.policy().map(Box::from);

        MemCommand {
            priority: command.priority(),
            id: command.id(),
            parent: command.parent(),
            policy,
            data: command.bytes().into(),
        }
    }
}
impl<'a> Command<'a> for MemCommand {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Prior<Id> {
        self.parent
    }

    fn policy(&self) -> Option<&[u8]> {
        self.policy.as_deref()
    }

    fn bytes(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Default)]
pub struct MemStorageProvider {
    storage: BTreeMap<Id, MemStorage>,
}

impl MemStorageProvider {
    pub const fn new() -> MemStorageProvider {
        MemStorageProvider {
            storage: BTreeMap::new(),
        }
    }
}

impl StorageProvider for MemStorageProvider {
    type Perspective = MemPerspective;
    type Storage = MemStorage;
    type Segment = MemSegment;

    fn new_perspective(&mut self, policy_id: &PolicyId) -> Self::Perspective {
        MemPerspective::new_unrooted(policy_id)
    }

    fn new_storage<'a>(
        &'a mut self,
        group: &Id,
        update: Self::Perspective,
    ) -> Result<&'a mut Self::Storage, StorageError> {
        use alloc::collections::btree_map::Entry;
        let entry = match self.storage.entry(*group) {
            Entry::Vacant(v) => v,
            Entry::Occupied(_) => return Err(StorageError::StorageExists),
        };

        let mut storage = MemStorage::new();
        let segment = storage.write(update)?;
        storage.commit(segment)?;
        Ok(entry.insert(storage))
    }

    fn get_storage<'a>(&'a mut self, group: &Id) -> Result<&'a mut Self::Storage, StorageError> {
        self.storage
            .get_mut(group)
            .ok_or(StorageError::NoSuchStorage)
    }
}

type FactMap = BTreeMap<Box<[u8]>, Option<Box<[u8]>>>;

pub struct MemStorage {
    segments: Vec<MemSegment>,
    commands: BTreeMap<Id, Location>,
    head: Option<Location>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct Head {
    id: Id,
    policy_id: PolicyId,
    segment_index: usize,
}

impl MemStorage {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
            commands: BTreeMap::new(),
            head: None,
        }
    }

    fn new_segment(
        &mut self,
        prior: Prior<Location>,
        policy: PolicyId,
        commands: Vec1<CommandData>,
        facts: MemFactIndex,
    ) -> Result<MemSegment, StorageError> {
        let index = self.segments.len();

        let segment = MemSegmentInner {
            prior,
            index,
            policy,
            commands,
            facts,
        };

        let cell = MemSegment::from(segment);
        self.segments.push(cell.clone());

        Ok(cell)
    }
}

impl Storage for MemStorage {
    type Perspective = MemPerspective;
    type Segment = MemSegment;
    type FactIndex = MemFactIndex;
    type FactPerspective = MemFactPerspective;

    fn get_location(&self, id: &Id) -> Result<Option<Location>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None);
        };

        Ok(Some(location.clone()))
    }

    fn get_command_id(&self, location: &Location) -> Result<Id, StorageError> {
        let segment = self.get_segment(location)?;
        let command = segment
            .get_command(location)
            .ok_or_else(|| StorageError::CommandOutOfBounds(location.clone()))?;
        Ok(command.id())
    }

    fn get_linear_perspective(&self, id: &Id) -> Result<Option<Self::Perspective>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None);
        };

        let segment = self.get_segment(location)?;

        let policy = segment.policy;
        let prior_facts: FactPerspectivePrior = if location == &segment.head_location() {
            segment.facts.clone().into()
        } else {
            let mut facts = MemFactPerspective::new(segment.facts.prior.clone().into());
            for data in &segment.commands[..=location.command] {
                facts.apply_updates(&data.updates);
            }
            if facts.map.is_empty() {
                facts.prior
            } else {
                facts.into()
            }
        };
        let prior = Prior::Single(location.clone());

        let perspective = MemPerspective::new(prior, policy, prior_facts);

        Ok(Some(perspective))
    }

    fn get_fact_perspective(
        &self,
        location: &Location,
    ) -> Result<Self::FactPerspective, StorageError> {
        let segment = self.get_segment(location)?;

        if location == &segment.head_location() {
            return Ok(MemFactPerspective::new(segment.facts.clone().into()));
        }

        let mut facts = MemFactPerspective::new(segment.facts.prior.clone().into());
        for data in &segment.commands[..=location.command] {
            facts.apply_updates(&data.updates);
        }

        Ok(facts)
    }

    fn new_merge_perspective<'a>(
        &self,
        command: &impl Command<'a>,
        policy_id: PolicyId,
        braid: MemFactIndex,
    ) -> Result<Option<Self::Perspective>, StorageError> {
        // TODO(jdygert): ensure braid belongs to this storage.
        // TODO(jdygert): ensure braid ends at given command?

        let parent = command.parent();

        let Prior::Merge(left, right) = parent else {
            return Err(StorageError::NotMerge);
        };

        let Some(left_location) = self.commands.get(&left) else {
            return Err(StorageError::NoSuchId(left));
        };

        let Some(right_location) = self.commands.get(&right) else {
            return Err(StorageError::NoSuchId(right));
        };

        let left_policy_id = self.get_segment(left_location)?.policy;
        let right_policy_id = self.get_segment(right_location)?.policy;

        if (policy_id != left_policy_id) && (policy_id != right_policy_id) {
            return Err(StorageError::PolicyMismatch);
        }

        let prior = Prior::Merge(left_location.clone(), right_location.clone());

        let mut perspective = MemPerspective::new(prior, policy_id, braid.into());
        perspective.add_command(command)?;

        Ok(Some(perspective))
    }

    fn get_segment(&self, location: &Location) -> Result<MemSegment, StorageError> {
        self.segments
            .get(location.segment)
            .ok_or_else(|| StorageError::SegmentOutOfBounds(location.clone()))
            .cloned()
    }

    fn get_head(&self) -> Result<Location, StorageError> {
        self.head
            .as_ref()
            .cloned()
            .ok_or(StorageError::InternalError)
    }

    fn write(&mut self, update: Self::Perspective) -> Result<Self::Segment, StorageError> {
        let facts = self.write_facts(update.facts)?;

        let commands: Vec1<CommandData> = update
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;

        let segment_index = self.segments.len();

        // Add the commands to the segment
        for (command_index, data) in commands.iter().enumerate() {
            let new_location = Location::new(segment_index, command_index);
            self.commands.insert(data.command.id(), new_location);
        }

        let segment = self.new_segment(update.prior, update.policy, commands, facts)?;

        Ok(segment)
    }

    fn write_facts(
        &mut self,
        facts: Self::FactPerspective,
    ) -> Result<Self::FactIndex, StorageError> {
        let prior = match facts.prior {
            FactPerspectivePrior::None => None,
            FactPerspectivePrior::FactPerspective(prior) => Some(self.write_facts(*prior)?),
            FactPerspectivePrior::FactIndex(prior) => Some(prior),
        };
        if facts.map.is_empty() {
            if let Some(prior) = prior {
                return Ok(prior);
            }
        }
        Ok(MemFactIndex(Arc::new(MemFactsInner {
            map: facts.map,
            prior,
        })))
    }

    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError> {
        // TODO(jdygert): ensure segment belongs to self?

        if let Some(head) = &self.head {
            if !self.is_ancestor(head, &segment)? {
                return Err(StorageError::HeadNotAncestor);
            }
        }

        self.head = Some(Location {
            segment: segment.index,
            command: segment.commands.len() - 1,
        });

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MemFactIndex(Arc<MemFactsInner>);

impl Deref for MemFactIndex {
    type Target = MemFactsInner;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl MemFactIndex {
    #[cfg(test)]
    fn name(&self) -> String {
        format!("\"{:p}\"", Arc::as_ptr(&self.0))
    }
}

#[derive(Debug)]
pub struct MemFactsInner {
    map: FactMap,
    prior: Option<MemFactIndex>,
}

impl FactIndex for MemFactIndex {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        let mut prior = Some(self.deref());
        while let Some(facts) = prior {
            if let Some(slot) = facts.map.get(key) {
                return Ok(slot.as_ref().cloned());
            }
            prior = facts.prior.as_deref();
        }
        Ok(None)
    }
}

#[derive(Debug)]
struct CommandData {
    command: MemCommand,
    updates: Vec<Update>,
}

#[derive(Debug)]
pub struct MemSegmentInner {
    index: usize,
    prior: Prior<Location>,
    policy: PolicyId,
    commands: Vec1<CommandData>,
    facts: MemFactIndex,
}

#[derive(Clone, Debug)]
pub struct MemSegment(Arc<MemSegmentInner>);

impl Deref for MemSegment {
    type Target = MemSegmentInner;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl From<MemSegmentInner> for MemSegment {
    fn from(segment: MemSegmentInner) -> Self {
        MemSegment(Arc::new(segment))
    }
}

impl Segment for MemSegment {
    type FactIndex = MemFactIndex;
    type Command<'a> = &'a MemCommand;

    fn head(&self) -> &MemCommand {
        &self.commands.last().command
    }

    fn first(&self) -> &MemCommand {
        &self.commands.first().command
    }

    fn head_location(&self) -> Location {
        Location {
            segment: self.index,
            command: self.commands.len() - 1,
        }
    }

    fn first_location(&self) -> Location {
        Location {
            segment: self.index,
            command: 0,
        }
    }

    fn contains(&self, location: &Location) -> bool {
        location.segment == self.index
    }

    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn prior(&self) -> Prior<Location> {
        self.prior.clone()
    }

    fn get_command<'a>(&'a self, location: &Location) -> Option<&'a MemCommand> {
        if location.segment != self.index {
            return None;
        }

        self.commands.get(location.command).map(|d| &d.command)
    }

    fn get_from<'a>(&'a self, location: &Location) -> Vec<&'a MemCommand> {
        if location.segment != self.index {
            return Vec::new();
        }

        self.commands[location.command..]
            .iter()
            .map(|d| &d.command)
            .collect()
    }

    fn facts(&self) -> Result<Self::FactIndex, StorageError> {
        Ok(self.facts.clone())
    }
}

#[derive(Debug)]
pub enum Update {
    Delete(Box<[u8]>),
    Insert(Box<[u8]>, Box<[u8]>),
}

#[derive(Debug)]
pub struct MemPerspective {
    prior: Prior<Location>,
    policy: PolicyId,
    facts: MemFactPerspective,
    commands: Vec<CommandData>,
    current_updates: Vec<Update>,
}

#[derive(Debug)]
enum FactPerspectivePrior {
    None,
    FactPerspective(Box<MemFactPerspective>),
    FactIndex(MemFactIndex),
}

impl From<MemFactIndex> for FactPerspectivePrior {
    fn from(value: MemFactIndex) -> Self {
        Self::FactIndex(value)
    }
}

impl From<Option<MemFactIndex>> for FactPerspectivePrior {
    fn from(value: Option<MemFactIndex>) -> Self {
        value.map_or(Self::None, Self::FactIndex)
    }
}

impl From<MemFactPerspective> for FactPerspectivePrior {
    fn from(value: MemFactPerspective) -> Self {
        Self::FactPerspective(Box::new(value))
    }
}

#[derive(Debug)]
pub struct MemFactPerspective {
    map: FactMap,
    prior: FactPerspectivePrior,
}

impl MemFactPerspective {
    fn new(prior_facts: FactPerspectivePrior) -> MemFactPerspective {
        Self {
            map: FactMap::new(),
            prior: prior_facts,
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn apply_updates(&mut self, updates: &[Update]) {
        for update in updates {
            match update {
                Update::Delete(key) => {
                    self.map.insert(key.clone(), None);
                }
                Update::Insert(key, value) => {
                    self.map.insert(key.clone(), Some(value.clone()));
                }
            }
        }
    }
}

impl MemPerspective {
    fn new(prior: Prior<Location>, policy: PolicyId, prior_facts: FactPerspectivePrior) -> Self {
        Self {
            prior,
            policy,
            facts: MemFactPerspective::new(prior_facts),
            commands: Vec::new(),
            current_updates: Vec::new(),
        }
    }

    fn new_unrooted(policy: &PolicyId) -> Self {
        Self {
            prior: Prior::None,
            policy: *policy,
            facts: MemFactPerspective::new(FactPerspectivePrior::None),
            commands: Vec::new(),
            current_updates: Vec::new(),
        }
    }
}

impl Perspective for MemPerspective {
    fn add_command<'b>(&mut self, command: &impl Command<'b>) -> Result<usize, StorageError> {
        // TODO(jdygert): Ensure command points to previous?
        let entry = CommandData {
            command: command.into(),
            updates: core::mem::take(&mut self.current_updates),
        };
        self.commands.push(entry);
        Ok(self.commands.len()) // FIXME(jdygert): Off by one?
    }

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

    fn policy(&self) -> PolicyId {
        self.policy
    }
}

impl FactPerspective for MemPerspective {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        self.facts.query(key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.facts.insert(key, value);
        self.current_updates
            .push(Update::Insert(key.into(), value.into()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.facts.delete(key);
        self.current_updates.push(Update::Delete(key.into()));
    }
}

impl FactPerspective for MemFactPerspective {
    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        if let Some(wrapped) = self.map.get(key) {
            return Ok(wrapped.as_deref().map(Box::from));
        }
        match &self.prior {
            FactPerspectivePrior::None => Ok(None),
            FactPerspectivePrior::FactPerspective(prior) => prior.query(key),
            FactPerspectivePrior::FactIndex(prior) => prior.query(key),
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.map.insert(key.into(), Some(value.into()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.map.insert(key.into(), None);
    }
}

#[cfg(test)]
mod test {
    use std::{fs::File, io::BufWriter};

    use dot_writer::{Attributes, DotWriter, Style};

    use super::*;

    struct TestCommand {
        id: Id,
        parent: Prior<Id>,
        priority: Priority,
    }

    impl<'a> Command<'a> for TestCommand {
        fn priority(&self) -> Priority {
            self.priority.clone()
        }

        fn id(&self) -> Id {
            self.id
        }

        fn parent(&self) -> Prior<Id> {
            self.parent
        }

        fn policy(&self) -> Option<&[u8]> {
            None
        }

        fn bytes(&self) -> &[u8] {
            &[]
        }
    }

    fn mkcmd(id: impl Into<Id>, parent: Prior<Id>, priority: u32) -> TestCommand {
        let priority = match parent {
            Prior::None => Priority::Init,
            Prior::Single(..) => Priority::Basic(priority),
            Prior::Merge(..) => Priority::Merge,
        };
        TestCommand {
            id: id.into(),
            parent,
            priority,
        }
    }

    struct GraphBuilder<'a, S: Storage> {
        storage: &'a mut S,
        pending: Option<S::Segment>,
    }

    fn eval(p: &mut impl FactPerspective, id: impl Into<Id>) {
        let id = id.into().shorthex();
        let seq = match p.query(b"seq").unwrap() {
            Some(seq) => format!("{}:{}", std::str::from_utf8(&seq).unwrap(), id),
            None => id,
        };
        p.insert(b"seq", seq.as_bytes());
    }

    impl<'a, S: Storage> GraphBuilder<'a, S> {
        pub fn init<SP>(sp: &'a mut SP, ids: &[u32]) -> Self
        where
            SP: StorageProvider<Storage = S>,
        {
            let mut persp = sp.new_perspective(&PolicyId::new(0));
            let mut prev = Prior::None;
            for &id in ids {
                eval(&mut persp, id);
                persp.add_command(&mkcmd(id, prev, id)).unwrap();
                prev = Prior::Single(id.into());
            }
            Self {
                storage: sp.new_storage(&Id::from(0u32), persp).unwrap(),
                pending: None,
            }
        }

        pub fn line(&mut self, prev: u32, ids: &[u32]) {
            let mut prev = Id::from(prev);
            let mut p = self.storage.get_linear_perspective(&prev).unwrap().unwrap();
            for &id in ids {
                eval(&mut p, id);
                p.add_command(&mkcmd(id, Prior::Single(prev), id)).unwrap();
                prev = Id::from(id);
            }
            self.pending = Some(self.storage.write(p).unwrap());
        }

        pub fn merge(&mut self, (left, right): (u32, u32), ids: &[u32]) {
            let command = mkcmd(ids[0], Prior::Merge(left.into(), right.into()), 0);
            let braid = self.braid(left, right);
            let mut p = self
                .storage
                .new_merge_perspective(&command, PolicyId::new(0), braid)
                .unwrap()
                .unwrap();
            for (&prev, &id) in core::iter::zip(ids, &ids[1..]) {
                eval(&mut p, id);
                p.add_command(&mkcmd(id, Prior::Single(Id::from(prev)), id))
                    .unwrap();
            }
            self.pending = Some(self.storage.write(p).unwrap());
        }

        fn braid(&mut self, left: u32, right: u32) -> S::FactIndex {
            let left = self.storage.get_location(&left.into()).unwrap().unwrap();
            let right = self.storage.get_location(&right.into()).unwrap().unwrap();
            let order = braid(self.storage, &left, &right).unwrap();
            let mut p = self.storage.get_fact_perspective(&order[0]).unwrap();
            for location in &order[1..] {
                let id = self.storage.get_command_id(location).unwrap();
                eval(&mut p, id);
            }
            self.storage.write_facts(p).unwrap()
        }

        pub fn commit(&mut self) {
            self.storage.commit(self.pending.take().unwrap()).unwrap()
        }
    }

    macro_rules! graph {
        ( $sp:ident ; $($init:literal )+ ; $($rest:tt)*) => {{
            let mut gb = GraphBuilder::init(&mut $sp, &[$($init)+]);
            graph!(@ gb, $($rest)*);
            gb.storage
        }};
        (@ $gb:ident, $prev:literal < $($id:literal)+; $($rest:tt)*) => {
            $gb.line($prev, &[$($id),+]);
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, $l:literal $r:literal < $($id:literal)+; $($rest:tt)*) => {
            $gb.merge(($l, $r), &[$($id),+]);
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, commit; $($rest:tt)*) => {
            $gb.commit();
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, ) => {};
    }

    fn loc(location: impl Into<Location>) -> String {
        let location = location.into();
        format!("\"{}:{}\"", location.segment, location.command)
    }

    fn get_seq(p: &MemFactIndex) -> &str {
        let seq = p.map.get(b"seq".as_slice()).unwrap().as_ref().unwrap();
        std::str::from_utf8(seq).unwrap()
    }

    fn dotwrite(storage: &MemStorage, out: &mut DotWriter<'_>) {
        let mut graph = out.digraph();
        graph
            .graph_attributes()
            .set("compound", "true", false)
            .set("rankdir", "RL", false)
            .set_style(Style::Filled)
            .set("color", "grey", false);
        graph
            .node_attributes()
            .set("shape", "square", false)
            .set_style(Style::Filled)
            .set("color", "lightgrey", false);

        let mut seen_facts = std::collections::HashMap::new();
        let mut external_facts = Vec::new();

        for segment in &storage.segments {
            let mut cluster = graph.cluster();
            match segment.prior {
                Prior::None => {
                    cluster.graph_attributes().set("color", "green", false);
                }
                Prior::Single(..) => {}
                Prior::Merge(..) => {
                    cluster.graph_attributes().set("color", "crimson", false);
                }
            }

            // Draw commands and edges between commands within the segment.
            for (i, cmd) in segment.commands.iter().enumerate() {
                {
                    let mut node = cluster.node_named(loc((segment.index, i)));
                    node.set_label(&cmd.command.id().shorthex());
                    match cmd.command.parent {
                        Prior::None => {
                            node.set("shape", "house", false);
                        }
                        Prior::Single(..) => {}
                        Prior::Merge(..) => {
                            node.set("shape", "hexagon", false);
                        }
                    };
                }
                if i > 0 {
                    cluster.edge(loc((segment.index, i)), loc((segment.index, i - 1)));
                }
            }

            // Draw edges to previous segments.
            let first = loc(segment.first_location());
            for p in segment.prior() {
                cluster.edge(&first, loc(p));
            }

            // Draw fact index for this segment.
            let curr = segment.facts.name();
            cluster
                .node_named(curr.clone())
                .set_label(get_seq(&segment.facts))
                .set("shape", "cylinder", false)
                .set("color", "black", false)
                .set("style", "solid", false);
            cluster
                .edge(loc(segment.head_location()), &curr)
                .attributes()
                .set("color", "red", false);

            seen_facts.insert(curr, segment.facts.clone());
            // Make sure prior facts of fact index will get processed later.
            let mut node = &segment.facts;
            while let Some(prior) = &node.prior {
                node = prior;
                let name = node.name();
                if seen_facts.insert(name, node.clone()).is_some() {
                    break;
                }
                external_facts.push(node.clone());
            }
        }

        graph
            .node_attributes()
            .set("shape", "cylinder", false)
            .set("color", "black", false)
            .set("style", "solid", false);

        for fact in external_facts {
            // Draw nodes for fact indices not directly associated with a segment.
            graph.node_named(fact.name()).set_label(get_seq(&fact));
            // Draw edge to prior facts.
            if let Some(prior) = &fact.prior {
                graph
                    .edge(fact.name(), prior.name())
                    .attributes()
                    .set("color", "blue", false);
            }
        }

        // Draw edges to prior facts for fact indices in segments.
        for segment in &storage.segments {
            if let Some(prior) = &segment.facts.prior {
                graph
                    .edge(segment.facts.name(), prior.name())
                    .attributes()
                    .set("color", "blue", false);
            }
        }

        // Draw HEAD indicator.
        graph.node_named("HEAD").set("shape", "none", false);
        graph.edge("HEAD", loc(storage.get_head().unwrap()));
    }

    fn dot(storage: &MemStorage, name: &str) {
        std::fs::create_dir_all(".ignore").unwrap();
        dotwrite(
            storage,
            &mut DotWriter::from(&mut BufWriter::new(
                File::create(format!(".ignore/{name}.dot")).unwrap(),
            )),
        );
    }

    #[test]
    fn test_simple() -> Result<(), StorageError> {
        let mut sp = MemStorageProvider::new();
        let g = graph! { sp; 0;
            0 < 1;
            0 < 3;
            1 3 < 0xB0;
            1 < 5;
            0xB0 5 < 0xB1;
        };
        dot(g, "simple");
        Ok(())
    }

    #[test]
    fn test_complex() -> Result<(), StorageError> {
        let mut sp = MemStorageProvider::new();
        let g = graph! { sp; 0;
            0 < 1 2 3; commit;
            3 < 4 6 7; commit;
            3 < 5 8;
            6 8 < 9 10; commit;
            7 < 11 12;
            10 12 < 13;
            13 < 16 14;
            13 < 17 15;
            14 15 < 18; commit;
            9 < 42 43;
            42 < 45 46;
            45 < 47 48;
        };
        dot(g, "complex");
        Ok(())
    }
}
