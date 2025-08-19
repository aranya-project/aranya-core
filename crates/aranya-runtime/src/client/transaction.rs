use alloc::collections::{BTreeMap, VecDeque};
use core::{marker::PhantomData, mem};

use buggy::{BugExt, bug};

use super::braiding;
use crate::{
    Address, ClientError, Command, CommandId, CommandRecall, Engine, EngineError, GraphId,
    Location, MAX_COMMAND_LENGTH, MergeIds, Perspective, Policy, PolicyId, Prior, Revertable,
    Segment, Sink, Storage, StorageError, StorageProvider,
};

/// Transaction used to receive many commands at once.
///
/// The transaction allows us to have many temporary heads at once, so we don't
/// need as many merges when adding commands. When the transaction is committed,
/// we will merge all temporary heads and the storage head, and then commit the
/// result as the new storage head.
pub struct Transaction<SP: StorageProvider, E> {
    /// The ID of the associated storage
    storage_id: GraphId,
    /// Current working perspective
    perspective: Option<SP::Perspective>,
    /// Head of the current perspective
    phead: Option<CommandId>,
    /// Written but not committed heads
    heads: BTreeMap<Address, Location>,
    /// Tag for associated engine
    _engine: PhantomData<E>,
}

impl<SP: StorageProvider, E> Transaction<SP, E> {
    pub(super) const fn new(storage_id: GraphId) -> Self {
        Self {
            storage_id,
            perspective: None,
            phead: None,
            heads: BTreeMap::new(),
            _engine: PhantomData,
        }
    }
}

impl<SP: StorageProvider, E: Engine> Transaction<SP, E> {
    /// Returns the transaction's storage id.
    pub fn storage_id(&self) -> GraphId {
        self.storage_id
    }

    /// Find a given id if reachable within this transaction.
    ///
    /// Does not search `self.perspective`, which should be written out beforehand.
    fn locate(
        &self,
        storage: &SP::Storage,
        address: Address,
    ) -> Result<Option<Location>, ClientError> {
        // Search from committed head.
        if let Some(found) = storage.get_location(address)? {
            return Ok(Some(found));
        }
        // Search from our temporary heads.
        for &head in self.heads.values() {
            if let Some(found) = storage.get_location_from(head, address)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Write current perspective, merge transaction heads, and commit to graph.
    pub(super) fn commit(
        &mut self,
        provider: &mut SP,
        engine: &E,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<(), ClientError> {
        let storage = provider.get_storage(self.storage_id)?;

        // Write out current perspective.
        if let Some(p) = Option::take(&mut self.perspective) {
            self.phead = None;
            let segment = storage.write(p)?;
            let head = segment.head()?;
            self.heads.insert(head.address()?, segment.head_location());
        }

        // Merge heads pairwise until single head left, then commit.
        // TODO(#370): Merge deterministically
        let mut heads: VecDeque<_> = mem::take(&mut self.heads).into_iter().collect();
        let mut merging_head = false;
        while let Some((left_id, mut left_loc)) = heads.pop_front() {
            if let Some((right_id, mut right_loc)) = heads.pop_front() {
                let (policy, policy_id) = choose_policy(storage, engine, left_loc, right_loc)?;

                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let merge_ids = MergeIds::new(left_id, right_id).assume("merging different ids")?;
                if left_id > right_id {
                    mem::swap(&mut left_loc, &mut right_loc);
                }
                let command = policy.merge(&mut buffer, merge_ids)?;

                let (braid, last_common_ancestor) =
                    make_braid_segment::<_, E>(storage, left_loc, right_loc, sink, policy)?;

                let mut perspective = storage
                    .new_merge_perspective(
                        left_loc,
                        right_loc,
                        last_common_ancestor,
                        policy_id,
                        braid,
                    )?
                    .assume("trx heads should exist in storage")?;
                perspective.add_command(&command)?;

                let segment = storage.write(perspective)?;
                let head = segment.head()?;

                heads.push_back((head.address()?, segment.head_location()));
            } else {
                let segment = storage.get_segment(left_loc)?;
                // Try to commit. If it fails with `HeadNotAncestor`, we know we
                // need to merge with the graph head.
                match storage.commit(segment) {
                    Ok(()) => break,
                    Err(StorageError::HeadNotAncestor) => {
                        if merging_head {
                            bug!("merging with graph head again, would loop");
                        }

                        merging_head = true;

                        heads.push_back((left_id, left_loc));

                        let head_loc = storage.get_head()?;
                        let segment = storage.get_segment(head_loc)?;
                        let head = segment.head()?;
                        heads.push_back((head.address()?, segment.head_location()));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }

        Ok(())
    }

    /// Attempt to store the `command` in the graph with `storage_id`. Effects will be
    /// emitted to the `sink`. This interface is used when syncing with another device
    /// and integrating the new commands.
    pub(super) fn add_commands(
        &mut self,
        commands: &[impl Command],
        provider: &mut SP,
        engine: &mut E,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<usize, ClientError> {
        let mut commands = commands.iter();
        let mut count: usize = 0;

        // Get storage or try to initialize with first command.
        let storage = match provider.get_storage(self.storage_id) {
            Ok(s) => s,
            Err(StorageError::NoSuchStorage) => {
                let command = commands.next().ok_or(ClientError::InitError)?;
                count = count.checked_add(1).assume("must not overflow")?;
                self.init(command, engine, provider, sink)?
            }
            Err(e) => return Err(e.into()),
        };

        // Handle remaining commands.
        for command in commands {
            if self
                .perspective
                .as_ref()
                .is_some_and(|p| p.includes(command.id()))
            {
                // Command in current perspective.
                continue;
            }
            if (self.locate(storage, command.address()?)?).is_some() {
                // Command already added.
                continue;
            }
            match command.parent() {
                Prior::None => {
                    if command.id().into_id() == self.storage_id.into_id() {
                        // Graph already initialized, extra init just spurious
                    } else {
                        bug!("init command does not belong in graph");
                    }
                }
                Prior::Single(parent) => {
                    self.add_single(storage, engine, sink, command, parent)?;
                    count = count.checked_add(1).assume("must not overflow")?;
                }
                Prior::Merge(left, right) => {
                    self.add_merge(storage, engine, sink, command, left, right)?;
                    count = count.checked_add(1).assume("must not overflow")?;
                }
            }
        }

        Ok(count)
    }

    fn add_single(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        engine: &E,
        sink: &mut impl Sink<E::Effect>,
        command: &impl Command,
        parent: Address,
    ) -> Result<(), ClientError> {
        let perspective = self.get_perspective(parent, storage)?;

        let policy_id = perspective.policy();
        let policy = engine.get_policy(policy_id)?;

        // Try to run command, or revert if failed.
        sink.begin();
        let checkpoint = perspective.checkpoint();
        if let Err(e) = policy.call_rule(command, perspective, sink, CommandRecall::None) {
            perspective.revert(checkpoint)?;
            sink.rollback();
            return Err(e.into());
        }
        perspective.add_command(command)?;
        sink.commit();

        self.phead = Some(command.id());

        Ok(())
    }

    fn add_merge(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        engine: &E,
        sink: &mut impl Sink<E::Effect>,
        command: &impl Command,
        left: Address,
        right: Address,
    ) -> Result<bool, ClientError> {
        // Must always start a new perspective for merges.
        if let Some(p) = Option::take(&mut self.perspective) {
            let seg = storage.write(p)?;
            let head = seg.head()?;
            self.heads.insert(head.address()?, seg.head_location());
        }

        let left_loc = self
            .locate(storage, left)?
            .ok_or(ClientError::NoSuchParent(left.id))?;
        let right_loc = self
            .locate(storage, right)?
            .ok_or(ClientError::NoSuchParent(right.id))?;

        let (policy, policy_id) = choose_policy(storage, engine, left_loc, right_loc)?;

        // Braid commands from left and right into an ordered sequence.
        let (braid, last_common_ancestor) =
            make_braid_segment::<_, E>(storage, left_loc, right_loc, sink, policy)?;

        let mut perspective = storage
            .new_merge_perspective(left_loc, right_loc, last_common_ancestor, policy_id, braid)?
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
        parent: Address,
        storage: &mut <SP as StorageProvider>::Storage,
    ) -> Result<&mut <SP as StorageProvider>::Perspective, ClientError> {
        if self.phead == Some(parent.id) {
            // Command will append to current perspective.
            return Ok(self
                .perspective
                .as_mut()
                .assume("trx has perspective when has phead")?);
        }

        // Write out the current perspective.
        if let Some(p) = Option::take(&mut self.perspective) {
            self.phead = None;
            let seg = storage.write(p)?;
            let head = seg.head()?;
            self.heads.insert(head.address()?, seg.head_location());
        }

        let loc = self
            .locate(storage, parent)?
            .ok_or(ClientError::NoSuchParent(parent.id))?;

        // Get a new perspective and store it in the transaction.
        let p = self.perspective.insert(
            storage
                .get_linear_perspective(loc)?
                .assume("location should already be in storage")?,
        );

        self.phead = Some(parent.id);
        self.heads.remove(&parent);

        Ok(p)
    }

    fn init<'sp>(
        &self,
        command: &impl Command,
        engine: &mut E,
        provider: &'sp mut SP,
        sink: &mut impl Sink<E::Effect>,
    ) -> Result<&'sp mut <SP as StorageProvider>::Storage, ClientError> {
        // Storage ID is the id of the init command by definition.
        if self.storage_id.into_id() != command.id().into_id() {
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
        let policy = engine.get_policy(policy_id)?;

        // Get an empty perspective and run the init command.
        let mut perspective = provider.new_perspective(policy_id);
        sink.begin();
        if let Err(e) = policy.call_rule(command, &mut perspective, sink, CommandRecall::None) {
            sink.rollback();
            // We don't need to revert perspective since we just drop it.
            return Err(e.into());
        }
        perspective.add_command(command)?;

        let (_, storage) = provider.new_storage(perspective)?;

        // Wait to commit until we are absolutely sure we've initialized.
        sink.commit();

        Ok(storage)
    }
}

/// Run the braid algorithm and evaluate the sequence to create a braided fact index.
fn make_braid_segment<S: Storage, E: Engine>(
    storage: &mut S,
    left: Location,
    right: Location,
    sink: &mut impl Sink<E::Effect>,
    policy: &E::Policy,
) -> Result<(S::FactIndex, (Location, usize)), ClientError> {
    let order = braiding::braid(storage, left, right)?;
    let last_common_ancestor = braiding::last_common_ancestor(storage, left, right)?;

    let (&first, rest) = order.split_first().assume("braid is non-empty")?;

    let mut braid_perspective = storage.get_fact_perspective(first)?;

    sink.begin();

    for &location in rest {
        let segment = storage.get_segment(location)?;
        let command = segment
            .get_command(location)
            .assume("braid only contains existing commands")?;

        let result = policy.call_rule(
            &command,
            &mut braid_perspective,
            sink,
            CommandRecall::OnCheck,
        );

        // If the command failed in an uncontrolled way, rollback
        if let Err(e) = result {
            if e != EngineError::Check {
                sink.rollback();
                return Err(e.into());
            }
        }
    }

    let braid = storage.write_facts(braid_perspective)?;

    sink.commit();

    Ok((braid, last_common_ancestor))
}

/// Select the policy from two locations with the greatest serial value.
fn choose_policy<'a, E: Engine>(
    storage: &impl Storage,
    engine: &'a E,
    left: Location,
    right: Location,
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
    location: Location,
) -> Result<(&'a E::Policy, PolicyId), ClientError> {
    let segment = storage.get_segment(location)?;
    let policy_id = segment.policy();
    let policy = engine.get_policy(policy_id)?;
    Ok((policy, policy_id))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use buggy::Bug;
    use test_log::test;

    use super::*;
    use crate::{ClientState, Keys, MergeIds, Priority, memory::MemStorageProvider};

    struct SeqEngine;

    /// [`SeqPolicy`] is a very simple policy which appends the id of each
    /// command to a fact named `b"seq"`. At each point in the graph, the value
    /// of this fact should be equal to the ids in braid order of all facts up
    /// to that point.
    struct SeqPolicy;

    struct SeqCommand {
        id: CommandId,
        prior: Prior<Address>,
        finalize: bool,
        data: Box<str>,
        max_cut: usize,
    }

    impl Engine for SeqEngine {
        type Policy = SeqPolicy;
        type Effect = ();

        fn add_policy(&mut self, _policy: &[u8]) -> Result<PolicyId, EngineError> {
            Ok(PolicyId::new(0))
        }

        fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, EngineError> {
            Ok(&SeqPolicy)
        }
    }

    impl Policy for SeqPolicy {
        type Action<'a> = &'a str;
        type Effect = ();
        type Command<'a> = SeqCommand;

        fn serial(&self) -> u32 {
            0
        }

        fn call_rule(
            &self,
            command: &impl Command,
            facts: &mut impl crate::FactPerspective,
            _sink: &mut impl Sink<Self::Effect>,
            _recall: CommandRecall,
        ) -> Result<(), EngineError> {
            assert!(
                !matches!(command.parent(), Prior::Merge { .. }),
                "merges shouldn't be evaluated"
            );

            // For init and basic commands, append the id to the seq fact.
            let data = command.bytes();
            if let Some(seq) = facts
                .query("seq", &Keys::default())
                .assume("can query")?
                .as_deref()
            {
                facts.insert(
                    "seq".into(),
                    Keys::default(),
                    [seq, b":", data].concat().into(),
                );
            } else {
                facts.insert("seq".into(), Keys::default(), data.into());
            };
            Ok(())
        }

        fn call_action(
            &self,
            _action: Self::Action<'_>,
            _facts: &mut impl Perspective,
            _sink: &mut impl Sink<Self::Effect>,
        ) -> Result<(), EngineError> {
            unimplemented!()
        }

        fn merge<'a>(
            &self,
            _target: &'a mut [u8],
            ids: MergeIds,
        ) -> Result<Self::Command<'a>, EngineError> {
            let (left, right): (Address, Address) = ids.into();
            let parents = [*left.id.as_array(), *right.id.as_array()];
            let id = CommandId::hash_for_testing_only(parents.as_flattened());

            Ok(SeqCommand::new(
                id,
                Prior::Merge(left, right),
                left.max_cut
                    .max(right.max_cut)
                    .checked_add(1)
                    .assume("must not overflow")?,
            ))
        }
    }

    impl SeqCommand {
        fn new(id: CommandId, prior: Prior<Address>, max_cut: usize) -> Self {
            let data = id.short_b58().into_boxed_str();
            Self {
                id,
                prior,
                finalize: false,
                data,
                max_cut,
            }
        }

        fn finalize(id: CommandId, prev: Address, max_cut: usize) -> Self {
            let data = id.short_b58().into_boxed_str();
            Self {
                id,
                prior: Prior::Single(prev),
                finalize: true,
                data,
                max_cut,
            }
        }
    }

    impl Command for SeqCommand {
        fn priority(&self) -> Priority {
            if self.finalize {
                return Priority::Finalize;
            }
            match self.prior {
                Prior::None => Priority::Init,
                Prior::Single(_) => {
                    // Use the last byte of the ID as priority, just so we can
                    // properly see the effects of braiding
                    let id = self.id.as_bytes();
                    let priority = u32::from(*id.last().unwrap());
                    Priority::Basic(priority)
                }
                Prior::Merge(_, _) => Priority::Merge,
            }
        }

        fn id(&self) -> CommandId {
            self.id
        }

        fn parent(&self) -> Prior<Address> {
            self.prior
        }

        fn policy(&self) -> Option<&[u8]> {
            // We don't actually need any policy bytes, but the
            // transaction/storage requires it on init commands.
            match self.prior {
                Prior::None { .. } => Some(b""),
                _ => None,
            }
        }

        fn bytes(&self) -> &[u8] {
            self.data.as_bytes()
        }

        fn max_cut(&self) -> Result<usize, Bug> {
            Ok(self.max_cut)
        }
    }

    struct NullSink;
    impl<E> Sink<E> for NullSink {
        fn begin(&mut self) {}
        fn consume(&mut self, _: E) {}
        fn rollback(&mut self) {}
        fn commit(&mut self) {}
    }

    /// [`GraphBuilder`] and the associated macro [`graph`] provide an easy way
    /// to create a graph with a specific structure.
    struct GraphBuilder<SP: StorageProvider> {
        client: ClientState<SeqEngine, SP>,
        trx: Transaction<SP, SeqEngine>,
        max_cuts: HashMap<CommandId, usize>,
    }

    impl<SP: StorageProvider> GraphBuilder<SP> {
        pub fn init(
            mut client: ClientState<SeqEngine, SP>,
            ids: &[CommandId],
        ) -> Result<Self, ClientError> {
            let mut trx = Transaction::new(GraphId::from(ids[0].into_id()));
            let mut prior: Prior<Address> = Prior::None;
            let mut max_cuts = HashMap::new();
            for (max_cut, &id) in ids.iter().enumerate() {
                let cmd = SeqCommand::new(id, prior, max_cut);
                trx.add_commands(
                    &[cmd],
                    &mut client.provider,
                    &mut client.engine,
                    &mut NullSink,
                )?;
                max_cuts.insert(id, max_cut);
                prior = Prior::Single(Address { id, max_cut });
            }
            Ok(Self {
                client,
                trx,
                max_cuts,
            })
        }

        fn get_addr(&self, id: CommandId) -> Address {
            Address {
                id,
                max_cut: self.max_cuts[&id],
            }
        }

        pub fn line(&mut self, prev: CommandId, ids: &[CommandId]) -> Result<(), ClientError> {
            let mut prev = self.get_addr(prev);
            for &id in ids {
                let max_cut = prev.max_cut.checked_add(1).unwrap();
                let cmd = SeqCommand::new(id, Prior::Single(prev), max_cut);
                self.trx.add_commands(
                    &[cmd],
                    &mut self.client.provider,
                    &mut self.client.engine,
                    &mut NullSink,
                )?;
                self.max_cuts.insert(id, max_cut);
                prev = Address { id, max_cut };
            }
            Ok(())
        }

        pub fn finalize(&mut self, prev: CommandId, id: CommandId) -> Result<(), ClientError> {
            let prev = self.get_addr(prev);
            let max_cut = prev.max_cut.checked_add(1).unwrap();
            let cmd = SeqCommand::finalize(id, prev, max_cut);
            self.trx.add_commands(
                &[cmd],
                &mut self.client.provider,
                &mut self.client.engine,
                &mut NullSink,
            )?;
            self.max_cuts.insert(id, max_cut);
            Ok(())
        }

        pub fn merge(
            &mut self,
            (left, right): (CommandId, CommandId),
            ids: &[CommandId],
        ) -> Result<(), ClientError> {
            let prior = Prior::Merge(self.get_addr(left), self.get_addr(right));
            let mergecmd = SeqCommand::new(ids[0], prior, prior.next_max_cut().unwrap());
            let mut prev = Address {
                id: mergecmd.id,
                max_cut: mergecmd.max_cut,
            };
            self.max_cuts.insert(mergecmd.id, mergecmd.max_cut);
            self.trx.add_commands(
                &[mergecmd],
                &mut self.client.provider,
                &mut self.client.engine,
                &mut NullSink,
            )?;
            for &id in &ids[1..] {
                let cmd = SeqCommand::new(
                    id,
                    Prior::Single(prev),
                    prev.max_cut.checked_add(1).expect("must not overflow"),
                );
                prev = Address {
                    id: cmd.id,
                    max_cut: cmd.max_cut,
                };
                self.max_cuts.insert(cmd.id, cmd.max_cut);
                self.trx.add_commands(
                    &[cmd],
                    &mut self.client.provider,
                    &mut self.client.engine,
                    &mut NullSink,
                )?;
            }
            Ok(())
        }

        pub fn flush(&mut self) {
            if let Some(p) = Option::take(&mut self.trx.perspective) {
                self.trx.phead = None;
                let seg = self
                    .client
                    .provider
                    .get_storage(self.trx.storage_id)
                    .unwrap()
                    .write(p)
                    .unwrap();
                let head = seg.head().unwrap();
                self.trx.heads.insert(
                    head.address().expect("address must exist"),
                    seg.head_location(),
                );
            }
        }

        pub fn commit(&mut self) -> Result<(), ClientError> {
            self.trx.commit(
                &mut self.client.provider,
                &mut self.client.engine,
                &mut NullSink,
            )
        }
    }

    fn mkid<T>(x: &str) -> T
    where
        aranya_crypto::Id: Into<T>,
    {
        x.parse::<aranya_crypto::Id>().unwrap().into()
    }

    /// See tests for usage.
    macro_rules! graph {
        ( $client:expr ; $init:literal $($inits:literal )* ; $($rest:tt)*) => {{
            let mut gb = GraphBuilder::init($client, &[mkid($init), $(mkid($inits)),*]).unwrap();
            graph!(@ gb, $($rest)*);
            gb
        }};
        (@ $gb:ident, $prev:literal < $($id:literal)+; $($rest:tt)*) => {
            $gb.line(mkid($prev), &[$(mkid($id)),+]).unwrap();
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, $l:literal $r:literal < $($id:literal)+; $($rest:tt)*) => {
            $gb.merge((mkid($l), mkid($r)), &[$(mkid($id)),+]).unwrap();
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, $prev:literal < finalize $id:literal; $($rest:tt)*) => {
            $gb.finalize(mkid($prev), mkid($id)).unwrap();
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, commit; $($rest:tt)*) => {
            $gb.commit().unwrap();
            graph!(@ $gb, $($rest)*);
        };
        (@ $gb:ident, ) => {
            $gb.flush();
        };
    }

    fn lookup(storage: &impl Storage, name: &str) -> Option<Box<[u8]>> {
        use crate::Query;
        let head = storage.get_head().unwrap();
        let p = storage.get_fact_perspective(head).unwrap();
        p.query(name, &Keys::default()).unwrap()
    }

    #[test]
    fn test_simple() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            "a" < "b";
            "a" < "c";
            "b" "c" < "ma";
            "b" < "d";
            "ma" "d" < "mb";
            commit;
        };
        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "simple");

        assert_eq!(g.get_head().unwrap(), Location::new(5, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:d:c");

        Ok(())
    }

    #[test]
    fn test_complex() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            "a" < "1" "2" "3";
            "3" < "4" "6" "7";
            "3" < "5" "8";
            "6" "8" < "9" "aa"; commit;
            "7" < "a1" "a2";
            "aa" "a2" < "a3";
            "a3" < "a6" "a4";
            "a3" < "a7" "a5";
            "a4" "a5" < "a8";
            "9" < "42" "43";
            "42" < "45" "46";
            "45" < "47" "48";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "complex");

        assert_eq!(g.get_head().unwrap(), Location::new(15, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(
            seq,
            "a:1:2:3:5:8:4:6:42:45:47:48:46:43:aa:7:a1:a2:a7:a6:a5:a4"
        );

        Ok(())
    }

    #[test]
    fn test_duplicates() {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            "a" < "b" "c";
            "a" < "b";
            "b" < "c";
            "c" < "d";
            commit;
            "a" < "b";
            "b" < "c";
            "d" < "e";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "duplicates");

        assert_eq!(g.get_head().unwrap(), Location::new(2, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:e");
    }

    #[test]
    fn test_mid_braid_1() {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            commit;
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "mid_braid_1");

        assert_eq!(g.get_head().unwrap(), Location::new(3, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:h:i:j:e:f:g");
    }

    #[test]
    fn test_mid_braid_2() {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            commit;
            "a" < "b" "c" "d" "h" "i" "j";
            "d" < "e" "f" "g";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "mid_braid_2");

        assert_eq!(g.get_head().unwrap(), Location::new(3, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:h:i:j:e:f:g");
    }

    #[test]
    fn test_sequential_finalize() {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            commit;
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            "e" < finalize "fff1";
            "fff1" < "x" "y";
            "y" < finalize "fff2";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        crate::storage::memory::graphviz::dot(g, "finalize_success");

        assert_eq!(g.get_head().unwrap(), Location::new(5, 0));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:e:fff1:x:y:fff2:h:i:j:f:g");
    }

    #[test]
    fn test_parallel_finalize() {
        let mut gb = graph! {
            ClientState::new(SeqEngine, MemStorageProvider::new());
            "a";
            commit;
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            "e" < finalize "fff1";
            "i" < finalize "fff2";
        };
        let err = gb.commit().expect_err("merge should fail");
        assert!(matches!(err, ClientError::ParallelFinalize), "{err:?}")
    }
}
