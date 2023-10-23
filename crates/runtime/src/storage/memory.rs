use alloc::{boxed::Box, collections::BTreeMap, rc::Rc, vec, vec::Vec};
use core::ops::Deref;

use vec1::Vec1;

use super::*;

#[derive(Debug)]
pub struct MemCommand {
    priority: Priority,
    id: Id,
    parent: Parent,
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

    fn parent(&self) -> Parent {
        self.parent.clone()
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
        kind: MemSegmentKind,
        policy: PolicyId,
        commands: Vec1<CommandData>,
        facts: FactMap,
    ) -> Result<MemSegment, StorageError> {
        let index = self.segments.len();

        let segment = MemSegmentInner {
            kind,
            index,
            policy,
            commands,
            facts,
        };

        let cell = MemSegment::from(segment);
        self.segments.push(cell.clone());

        Ok(cell)
    }

    fn get_policy_id(&self, command_id: &Id) -> Result<PolicyId, StorageError> {
        let Some(location) = self.commands.get(command_id) else {
            return Err(StorageError::NoSuchId(*command_id));
        };

        match self.segments.get(location.segment) {
            None => Err(StorageError::InternalError),
            Some(segment) => Ok(segment.policy()),
        }
    }

    fn get_basic_perspective_inner(
        &self,
        id: &Id,
        is_braid: bool,
    ) -> Result<Option<MemPerspective>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None);
        };

        let Some(segment) = self.segments.get(location.segment) else {
            return Err(StorageError::InternalError);
        };

        let policy = segment.policy;
        let prior_facts = if location == &segment.head_location() {
            Some(segment.clone())
        } else {
            segment.prior_facts()?
        };
        let kind = if is_braid {
            MemPerspectiveKind::Braid {
                previous: (location.clone(), segment.clone()),
                prior_facts,
            }
        } else {
            MemPerspectiveKind::Linear {
                previous: (location.clone(), segment.clone()),
                prior_facts,
            }
        };

        let perspective = MemPerspective::new(kind, policy);

        Ok(Some(perspective))
    }
}

impl Storage for MemStorage {
    type Perspective = MemPerspective;
    type Segment = MemSegment;

    fn get_location(&self, id: &Id) -> Result<Option<Location>, StorageError> {
        let Some(location) = self.commands.get(id) else {
            return Ok(None);
        };

        Ok(Some(location.clone()))
    }

    fn get_command_id(&self, location: &Location) -> Result<Id, StorageError> {
        let segment = self
            .segments
            .get(location.segment)
            .ok_or(StorageError::InternalError)?;

        let command = segment
            .get_command(location)
            .ok_or(StorageError::InternalError)?;

        Ok(command.id())
    }

    fn get_linear_perspective(&self, id: &Id) -> Result<Option<Self::Perspective>, StorageError> {
        self.get_basic_perspective_inner(id, false)
    }

    fn get_braid_perspective(&self, id: &Id) -> Result<Option<Self::Perspective>, StorageError> {
        self.get_basic_perspective_inner(id, true)
    }

    fn new_merge_perspective<'a>(
        &self,
        command: &impl Command<'a>,
        policy_id: PolicyId,
        braid: MemSegment,
    ) -> Result<Option<Self::Perspective>, StorageError> {
        // TODO: ensure braid belongs to this storage.
        // TODO: ensure braid ends at given command?

        if !matches!(&braid.kind, MemSegmentKind::Braid { .. }) {
            return Err(StorageError::NotBraid);
        }

        let parent = command.parent();

        let Parent::Merge(left, right) = parent else {
            return Err(StorageError::NotMerge);
        };

        let Some(left_location) = self.commands.get(&left) else {
            return Err(StorageError::NoSuchId(left));
        };

        let Some(right_location) = self.commands.get(&right) else {
            return Err(StorageError::NoSuchId(right));
        };

        let left_policy_id = self.get_policy_id(&left)?;
        let right_policy_id = self.get_policy_id(&right)?;

        if (policy_id != left_policy_id) && (policy_id != right_policy_id) {
            return Err(StorageError::PolicyMismatch);
        }

        let kind = MemPerspectiveKind::Merge {
            left: left_location.clone(),
            right: right_location.clone(),
            braid,
        };

        let mut perspective = MemPerspective::new(kind, policy_id);
        perspective.add_command(command)?;

        Ok(Some(perspective))
    }

    fn get_segment(&self, location: &Location) -> Result<Option<MemSegment>, StorageError> {
        let Some(cell) = self.segments.get(location.segment) else {
            return Err(StorageError::InternalError);
        };

        Ok(Some(cell.clone()))
    }

    fn get_head(&self) -> Result<Location, StorageError> {
        self.head
            .as_ref()
            .cloned()
            .ok_or(StorageError::InternalError)
    }

    fn write(&mut self, update: Self::Perspective) -> Result<Self::Segment, StorageError> {
        let commands: Vec1<CommandData> = update
            .commands
            .try_into()
            .map_err(|_| StorageError::EmptyPerspective)?;

        let segment_index = self.segments.len();

        let kind = (&update.kind).into();
        let is_braid = matches!(kind, MemSegmentKind::Braid { .. });

        // Add the commands to the segment
        if !is_braid {
            for (command_index, data) in commands.iter().enumerate() {
                let new_location = Location::new(segment_index, command_index);
                self.commands.insert(data.command.id(), new_location);
            }
        }

        let segment = self.new_segment(kind, update.policy, commands, update.temp)?;

        Ok(segment)
    }

    fn commit(&mut self, segment: Self::Segment) -> Result<(), StorageError> {
        // TODO: ensure segment belongs to self?
        // TODO: Ensure not braid?

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

#[derive(Debug)]
struct CommandData {
    command: MemCommand,
    updates: Vec<Update>,
}

#[derive(Debug)]
enum MemSegmentKind {
    Init,
    Linear {
        previous: Location,              // Graph
        prior_facts: Option<MemSegment>, // Graph
    },
    Merge {
        left: Location,    // Graph
        right: Location,   // Graph
        braid: MemSegment, // Braid
    },
    Braid {
        previous: Location,              // Graph or Braid
        prior_facts: Option<MemSegment>, // Graph or Braid
    },
}

impl From<&MemPerspectiveKind> for MemSegmentKind {
    fn from(value: &MemPerspectiveKind) -> Self {
        match value {
            MemPerspectiveKind::Init => MemSegmentKind::Init,
            MemPerspectiveKind::Linear {
                previous,
                prior_facts,
            } => MemSegmentKind::Linear {
                previous: previous.0.clone(),
                prior_facts: prior_facts.clone(),
            },
            MemPerspectiveKind::Merge { left, right, braid } => MemSegmentKind::Merge {
                left: left.clone(),
                right: right.clone(),
                braid: braid.clone(),
            },
            MemPerspectiveKind::Braid {
                previous,
                prior_facts,
            } => MemSegmentKind::Braid {
                previous: previous.0.clone(),
                prior_facts: prior_facts.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub struct MemSegmentInner {
    index: usize,
    kind: MemSegmentKind,
    policy: PolicyId,
    commands: Vec1<CommandData>,
    /// Fact delta from `kind.prior_facts.facts`
    facts: FactMap,
}

#[derive(Clone, Debug)]
pub struct MemSegment(Rc<MemSegmentInner>);

impl Deref for MemSegment {
    type Target = MemSegmentInner;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl From<MemSegmentInner> for MemSegment {
    fn from(segment: MemSegmentInner) -> Self {
        MemSegment(Rc::new(segment))
    }
}

impl Segment for MemSegment {
    type Command<'a> = MemCommand;

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

    fn prior(&self) -> HVec2<Location> {
        match &self.kind {
            MemSegmentKind::Init => hvec2![],
            MemSegmentKind::Linear { previous, .. } => hvec2![previous.clone()],
            MemSegmentKind::Merge { left, right, .. } => hvec2![left.clone(), right.clone()],
            MemSegmentKind::Braid { previous, .. } => hvec2![previous.clone()],
        }
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

    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        if let Some(wrapped) = self.facts.get(key) {
            return Ok(wrapped.clone());
        }

        let mut prior_option = self.prior_facts()?;

        while let Some(prior_segment) = prior_option {
            match prior_segment.query(key)? {
                // BUG: How do I detect cycels in a croupped graph?
                // Could I use max_cut and reqire that it goes down?
                None => prior_option = prior_segment.prior_facts()?,
                Some(wrapped) => {
                    return Ok(Some(wrapped));
                }
            };
        }
        Ok(None)
    }

    fn prior_facts(&self) -> Result<Option<Self>, StorageError> {
        Ok(match &self.kind {
            MemSegmentKind::Init => None,
            MemSegmentKind::Linear { prior_facts, .. } => prior_facts.clone(),
            MemSegmentKind::Merge { braid, .. } => Some(braid.clone()),
            MemSegmentKind::Braid { prior_facts, .. } => prior_facts.clone(),
        })
    }
}

#[derive(Debug)]
pub enum Update {
    Delete(Box<[u8]>),
    Insert(Box<[u8]>, Box<[u8]>),
}

enum MemPerspectiveKind {
    Init,
    Linear {
        previous: (Location, MemSegment),
        prior_facts: Option<MemSegment>,
    },
    Merge {
        left: Location,
        right: Location,
        braid: MemSegment,
    },
    Braid {
        previous: (Location, MemSegment),
        prior_facts: Option<MemSegment>,
    },
}

pub struct MemPerspective {
    kind: MemPerspectiveKind,
    policy: PolicyId,
    temp: FactMap,
    commands: Vec<CommandData>,
    current_updates: Vec<Update>,
    target: Box<[u8]>,
}

impl MemPerspective {
    fn new(kind: MemPerspectiveKind, policy: PolicyId) -> Self {
        let mut result = MemPerspective {
            kind,
            policy,
            temp: BTreeMap::new(),
            commands: Vec::new(),
            current_updates: Vec::new(),
            target: vec![0u8; 1048576].into_boxed_slice(),
        };

        result.apply_from();

        result
    }

    fn new_unrooted(policy: &PolicyId) -> Self {
        MemPerspective {
            kind: MemPerspectiveKind::Init,
            policy: *policy,
            temp: BTreeMap::new(),
            commands: Vec::new(),
            current_updates: Vec::new(),
            target: vec![0u8; 1048576].into_boxed_slice(),
        }
    }

    fn apply_from(&mut self) {
        let (location, segment) = match &self.kind {
            MemPerspectiveKind::Init => return,
            MemPerspectiveKind::Linear { previous, .. } => previous,
            MemPerspectiveKind::Braid { previous, .. } => previous,
            // Merges always point to the end of a braid, so no partial updates to apply
            MemPerspectiveKind::Merge { .. } => return,
        };

        for data in &segment.commands[0..(location.command + 1)] {
            apply_updates(&data.updates, &mut self.temp);
        }
    }
}

fn apply_updates(updates: &[Update], map: &mut FactMap) {
    for update in updates {
        match update {
            Update::Delete(key) => {
                map.insert(key.clone(), None);
            }
            Update::Insert(key, value) => {
                map.insert(key.clone(), Some(value.clone()));
            }
        }
    }
}

impl MemPerspectiveKind {
    fn prior_facts(&self) -> Option<&MemSegment> {
        match self {
            MemPerspectiveKind::Init => None,
            MemPerspectiveKind::Linear { prior_facts, .. } => prior_facts.as_ref(),
            MemPerspectiveKind::Merge { braid, .. } => Some(braid),
            MemPerspectiveKind::Braid { prior_facts, .. } => prior_facts.as_ref(),
        }
    }
}

impl Perspective for MemPerspective {
    fn prior(&self) -> HVec2<Location> {
        match &self.kind {
            MemPerspectiveKind::Init => hvec2![],
            MemPerspectiveKind::Linear { previous, .. } => hvec2![previous.0.clone()],
            MemPerspectiveKind::Merge { left, right, .. } => hvec2![left.clone(), right.clone()],
            MemPerspectiveKind::Braid { previous, .. } => hvec2![previous.0.clone()],
        }
    }

    fn query(&self, key: &[u8]) -> Result<Option<Box<[u8]>>, StorageError> {
        if let Some(wrapped) = self.temp.get(key) {
            return Ok(wrapped.as_deref().map(Box::from));
        }
        if let Some(prior) = self.kind.prior_facts() {
            return prior.query(key);
        }
        Ok(None)
    }

    fn add_command<'b>(&mut self, command: &impl Command<'b>) -> Result<usize, StorageError> {
        // TODO: Ensure command points to previous?
        let entry = CommandData {
            command: command.into(),
            updates: core::mem::take(&mut self.current_updates),
        };
        self.commands.push(entry);
        Ok(self.commands.len()) // FIXME: Off by one?
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) {
        self.temp.insert(key.into(), Some(value.into()));
        self.current_updates
            .push(Update::Insert(key.into(), value.into()));
    }

    fn delete(&mut self, key: &[u8]) {
        self.temp.insert(key.into(), None);
        self.current_updates.push(Update::Delete(key.into()));
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

    fn policy(&self) -> PolicyId {
        self.policy
    }

    fn get_target(&mut self) -> Result<&mut [u8], StorageError> {
        Ok(&mut self.target)
    }
}

#[cfg(test)]
mod test {
    use std::{fs::File, io::BufWriter};

    use dot_writer::{Attributes, DotWriter, Style};

    use super::*;

    struct TestCommand {
        id: Id,
        parent: Parent,
        priority: Priority,
    }

    impl<'a> Command<'a> for TestCommand {
        fn priority(&self) -> Priority {
            self.priority.clone()
        }

        fn id(&self) -> Id {
            self.id
        }

        fn parent(&self) -> Parent {
            self.parent.clone()
        }

        fn policy(&self) -> Option<&[u8]> {
            None
        }

        fn bytes(&self) -> &[u8] {
            &[]
        }
    }

    fn mkcmd(id: impl Into<Id>, parent: Parent, priority: u32) -> TestCommand {
        let priority = match parent {
            Parent::None => Priority::Init,
            Parent::Id(_) => Priority::Basic(priority),
            Parent::Merge(_, _) => Priority::Merge,
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

    impl<'a, S: Storage> GraphBuilder<'a, S> {
        pub fn init<SP>(sp: &'a mut SP, ids: &[u32]) -> Self
        where
            SP: StorageProvider<Storage = S>,
        {
            let mut persp = sp.new_perspective(&PolicyId::new(0));
            let mut prev = Parent::None;
            for &id in ids {
                persp.add_command(&mkcmd(id, prev, id)).unwrap();
                prev = Parent::Id(id.into());
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
                p.add_command(&mkcmd(id, Parent::Id(prev), id)).unwrap();
                prev = Id::from(id);
            }
            self.pending = Some(self.storage.write(p).unwrap());
        }

        pub fn merge(&mut self, (left, right): (u32, u32), ids: &[u32]) {
            let command = mkcmd(ids[0], Parent::Merge(left.into(), right.into()), 0);
            let braid = self.braid(left, right);
            let mut p = self
                .storage
                .new_merge_perspective(&command, PolicyId::new(0), braid)
                .unwrap()
                .unwrap();
            for (&prev, &id) in core::iter::zip(ids, &ids[1..]) {
                p.add_command(&mkcmd(id, Parent::Id(Id::from(prev)), id))
                    .unwrap();
            }
            self.pending = Some(self.storage.write(p).unwrap());
        }

        fn braid(&mut self, left: u32, right: u32) -> S::Segment {
            let order = braid(self.storage, &left.into(), &right.into()).unwrap();
            let first = self.storage.get_command_id(&order[0]).unwrap();
            let mut p = self.storage.get_braid_perspective(&first).unwrap().unwrap();
            let mut parent = Parent::Id(first);
            for location in &order[1..] {
                let id = self.storage.get_command_id(location).unwrap();
                p.add_command(&mkcmd(id, parent, 0)).unwrap();
                parent = Parent::Id(id);
            }
            self.storage.write(p).unwrap()
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

    fn dotwrite(storage: &MemStorage, out: &mut DotWriter<'_>) {
        let mut graph = out.digraph();
        graph
            .graph_attributes()
            .set("rankdir", "RL", false)
            .set_style(Style::Filled)
            .set("color", "grey", false);
        graph
            .node_attributes()
            .set("shape", "square", false)
            .set_style(Style::Filled)
            .set("color", "lightgrey", false);
        for segment in &storage.segments {
            let mut cluster = graph.cluster();
            // cluster
            //     .graph_attributes()
            //     .set_label(&format!("Segment {}", segment.index));
            match segment.kind {
                MemSegmentKind::Init => {
                    cluster.graph_attributes().set("color", "green", false);
                }
                MemSegmentKind::Linear { .. } => {
                    //
                }
                MemSegmentKind::Merge { .. } => {
                    cluster.graph_attributes().set("color", "crimson", false);
                }
                MemSegmentKind::Braid { .. } => {
                    cluster.graph_attributes().set("color", "royalblue", false);
                }
            }
            for (i, cmd) in segment.commands.iter().enumerate() {
                {
                    let mut node = cluster.node_named(loc((segment.index, i)));
                    node.set_label(&cmd.command.id().shorthex());
                    match cmd.command.parent {
                        Parent::None => {
                            node.set("shape", "house", false);
                        }
                        Parent::Id(_) => {}
                        Parent::Merge(_, _) => {
                            node.set("shape", "hexagon", false);
                        }
                    };
                }
                if i > 0 {
                    cluster.edge(loc((segment.index, i)), loc((segment.index, i - 1)));
                }
            }
            let first = loc(segment.first_location());
            for p in segment.prior() {
                cluster.edge(&first, loc(p));
            }
            if let Some(facts) = segment.prior_facts().unwrap() {
                cluster
                    .edge(&first, loc(facts.head_location()))
                    .attributes()
                    .set("color", "orange", false);
            }
        }
        graph.node_named("HEAD").set("style", "invis", false);
        graph
            .edge("HEAD", loc(storage.get_head().unwrap()))
            .attributes()
            .set_label("HEAD");
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
        };
        dot(g, "complex");
        Ok(())
    }
}
