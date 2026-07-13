use alloc::collections::{BTreeMap, VecDeque};
use core::{marker::PhantomData, mem};

use buggy::{BugExt as _, bug};

use super::braiding;
use crate::{
    Address, BraidBuffer, ClientError, CmdId, Command, GraphId, Location, MAX_COMMAND_LENGTH,
    MergeIds, Perspective as _, Policy as _, PolicyError, PolicyId, PolicyStore, Prior,
    Revertable as _, RuntimeBuffers, Segment as _, Sink, Storage, StorageError, StorageProvider,
    TraversalBuffer,
    policy::{CommandPlacement, NullSink},
    storage::{HeadSet, LocatedAddress, MAX_HEADS, Spill},
};

/// Transaction used to receive many commands at once.
///
/// The transaction allows us to have many temporary heads at once, so we don't
/// need as many merges when adding commands. When the transaction is committed,
/// we will merge all temporary heads and the graph head, and then commit the
/// result as the new graph head.
pub struct Transaction<SP: StorageProvider, PS> {
    /// The ID of the associated graph
    graph_id: GraphId,
    /// The head set of the graph when this transaction is first used.
    original_heads: Option<HeadSet>,
    /// Current working perspective
    perspective: Option<SP::Perspective>,
    /// Head of the current perspective
    phead: Option<CmdId>,
    /// Written but not committed heads
    heads: BTreeMap<CmdId, Location>,
    /// Tag for associated policy store
    policy_store: PhantomData<PS>,
}

impl<SP: StorageProvider, PS> Transaction<SP, PS> {
    pub(super) const fn new(graph_id: GraphId) -> Self {
        Self {
            graph_id,
            original_heads: None,
            perspective: None,
            phead: None,
            heads: BTreeMap::new(),
            policy_store: PhantomData,
        }
    }
}

impl<SP: StorageProvider, PS: PolicyStore> Transaction<SP, PS> {
    /// Returns the transaction's graph id.
    pub fn graph_id(&self) -> GraphId {
        self.graph_id
    }

    /// Find a given id if reachable within this transaction.
    ///
    /// Does not search `self.perspective`, which should be written out beforehand.
    fn locate(
        &self,
        storage: &mut SP::Storage,
        address: Address,
        buffer: &mut TraversalBuffer,
    ) -> Result<Option<Location>, ClientError> {
        // Search from committed head.
        if let Some(found) = storage.get_location(address, buffer)? {
            return Ok(Some(found));
        }
        // Search from our temporary heads.
        for &head in self.heads.values() {
            if let Some(found) = storage.get_location_from(head, address, buffer)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Write any in-flight perspective into a segment so all accumulated commands
    /// are persisted and reflected in `self.heads`. Does NOT commit or braid.
    ///
    /// `commit` flushes automatically; callers only need this to make
    /// [`Self::in_flight_heads`] reflect every accumulated command before
    /// committing (e.g. to advertise the frontier while syncing).
    pub fn flush(&mut self, provider: &mut SP) -> Result<(), ClientError> {
        let storage = provider.get_storage(self.graph_id)?;
        if let Some(p) = Option::take(&mut self.perspective) {
            self.phead = None;
            let segment = storage.write(p)?;
            self.heads
                .insert(segment.head_id(), segment.head_location()?);
        }
        Ok(())
    }

    /// The transaction's accumulated frontier (committed + received-but-uncommitted
    /// tips), as `LocatedAddress`. Call `flush` first so every accumulated command
    /// is in a written segment with a real location.
    pub fn in_flight_heads(&self) -> impl Iterator<Item = LocatedAddress> + '_ {
        self.heads.iter().map(|(id, loc)| LocatedAddress {
            id: *id,
            segment: loc.segment,
            max_cut: loc.max_cut,
        })
    }

    /// Write current perspective, merge transaction heads, and commit to graph.
    pub(super) fn commit<F, MS>(
        mut self,
        provider: &mut SP,
        policy_store: &mut PS,
        sink: &mut impl Sink<PS::Effect>,
        buffers: &mut RuntimeBuffers<SP::Segment>,
        make_spill: &MS,
    ) -> Result<bool, ClientError>
    where
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        {
            let storage = provider.get_storage(self.graph_id)?;

            let Some(original_heads) = self.original_heads.take() else {
                return Ok(false);
            };
            if &original_heads != storage.get_heads()? {
                return Err(ClientError::ConcurrentTransaction);
            }
        }

        // Persist any in-flight perspective into self.heads.
        self.flush(provider)?;

        let storage = provider.get_storage(self.graph_id)?;

        if self.heads.is_empty() {
            return Ok(false);
        }

        // Build the committed head set from the live tips.
        let mut head_set = HeadSet::default();
        for (id, loc) in &self.heads {
            head_set.push(LocatedAddress {
                id: *id,
                segment: loc.segment,
                max_cut: loc.max_cut,
            })?;
        }

        // Rebuild the fact cache for this head set.
        let head_locs: heapless::Vec<Location, MAX_HEADS> =
            head_set.iter().map(LocatedAddress::location).collect();
        let fact_cache = if head_locs.len() == 1 {
            // Single head: reuse that head's fact index.
            storage.get_segment(head_locs[0])?.facts()?
        } else {
            // Multi-head: braid the heads into a merged fact index.
            // TODO(multi-policy): if heads can have differing policies, fold choose_policy
            // over the head set instead of taking head 0's policy.
            let policy_id = storage.get_segment(head_locs[0])?.policy();
            let policy = policy_store.get_policy(policy_id)?;
            let (facts, _lca) = evaluate_braid::<_, PS, F, MS>(
                storage,
                &head_locs,
                sink,
                policy,
                &mut buffers.traversal.primary,
                &mut buffers.braid,
                make_spill,
            )?;
            facts
        };

        storage.commit_heads(head_set, fact_cache)?;
        Ok(true)
    }

    /// Attempt to store the `command` in the graph with `graph_id`. Effects will be
    /// emitted to the `sink`. This interface is used when syncing with another device
    /// and integrating the new commands.
    pub(super) fn add_commands<F, MS>(
        &mut self,
        commands: &[impl Command],
        provider: &mut SP,
        policy_store: &mut PS,
        sink: &mut impl Sink<PS::Effect>,
        buffers: &mut RuntimeBuffers<SP::Segment>,
        make_spill: &MS,
    ) -> Result<usize, ClientError>
    where
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        let mut commands = commands.iter();
        let mut count: usize = 0;

        // Get storage or try to initialize with first command.
        let storage = match provider.get_storage(self.graph_id) {
            Ok(s) => s,
            Err(StorageError::NoSuchStorage) => {
                let command = commands.next().ok_or(ClientError::InitError)?;
                count = count.checked_add(1).assume("must not overflow")?;
                self.init(command, policy_store, provider, sink)?
            }
            Err(e) => return Err(e.into()),
        };

        if self.original_heads.is_none() {
            let heads = storage.get_heads()?.clone();
            for la in heads.iter() {
                self.heads.insert(la.id, la.location());
            }
            self.original_heads = Some(heads);
        }

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

            if self
                .locate(storage, command.address()?, &mut buffers.traversal.primary)?
                .is_some()
            {
                // Command already added.
                continue;
            }
            match command.parent() {
                Prior::None => {
                    if command.id().as_base() == self.graph_id.as_base() {
                        // Graph already initialized, extra init just spurious
                    } else {
                        bug!("init command does not belong in graph");
                    }
                }
                Prior::Single(parent) => {
                    self.add_single(
                        storage,
                        policy_store,
                        sink,
                        command,
                        parent,
                        &mut buffers.traversal.primary,
                    )?;
                    count = count.checked_add(1).assume("must not overflow")?;
                }
                Prior::Merge(left, right) => {
                    self.add_merge::<F, MS>(
                        storage,
                        policy_store,
                        sink,
                        command,
                        (left, right),
                        buffers,
                        make_spill,
                    )?;
                    count = count.checked_add(1).assume("must not overflow")?;
                }
            }
        }

        Ok(count)
    }

    fn add_single(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        policy_store: &mut PS,
        sink: &mut impl Sink<PS::Effect>,
        command: &impl Command,
        parent: Address,
        buffer: &mut TraversalBuffer,
    ) -> Result<(), ClientError> {
        let perspective = self.get_perspective(parent, storage, buffer)?;

        let policy_id = perspective.policy();
        let policy = policy_store.get_policy(policy_id)?;

        // Try to run command, or revert if failed.
        sink.begin();
        let checkpoint = perspective.checkpoint();
        if let Err(e) = policy.call_rule(
            command,
            perspective,
            sink,
            CommandPlacement::OnGraphAtOrigin,
        ) {
            perspective.revert(checkpoint)?;
            sink.rollback();
            return Err(e.into());
        }
        perspective.add_command(command)?;
        sink.commit();

        self.phead = Some(command.id());

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_merge<F, MS>(
        &mut self,
        storage: &mut <SP as StorageProvider>::Storage,
        policy_store: &mut PS,
        sink: &mut impl Sink<PS::Effect>,
        command: &impl Command,
        (left, right): (Address, Address),
        buffers: &mut RuntimeBuffers<SP::Segment>,
        make_spill: &MS,
    ) -> Result<bool, ClientError>
    where
        F: Spill,
        MS: Fn() -> Result<F, StorageError>,
    {
        // Must always start a new perspective for merges.
        if let Some(p) = Option::take(&mut self.perspective) {
            let seg = storage.write(p)?;
            self.heads.insert(seg.head_id(), seg.head_location()?);
        }

        let left_loc = self
            .locate(storage, left, &mut buffers.traversal.primary)?
            .ok_or(ClientError::NoSuchParent(left.id))?;
        let right_loc = self
            .locate(storage, right, &mut buffers.traversal.primary)?
            .ok_or(ClientError::NoSuchParent(right.id))?;

        let (policy, policy_id) = choose_policy(storage, policy_store, left_loc, right_loc)?;

        // Braid commands from left and right into an ordered sequence.
        let (braid, last_common_ancestor) = evaluate_braid::<_, PS, F, MS>(
            storage,
            &[left_loc, right_loc],
            sink,
            policy,
            &mut buffers.traversal.primary,
            &mut buffers.braid,
            make_spill,
        )?;

        let mut perspective = storage.new_merge_perspective(
            left_loc,
            right_loc,
            last_common_ancestor,
            policy_id,
            braid,
        )?;
        perspective.add_command(command)?;

        // These are no longer heads of the transaction, since they are both covered by the merge
        self.heads.remove(&left.id);
        self.heads.remove(&right.id);

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
        buffer: &mut TraversalBuffer,
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
            self.heads.insert(seg.head_id(), seg.head_location()?);
            // Fail fast if the accumulated tips have reached head-set capacity,
            // since the next in-flight perspective would push past MAX_HEADS.
            if self.heads.len() >= MAX_HEADS {
                return Err(StorageError::HeadSetFull(MAX_HEADS).into());
            }
        }

        let loc = self
            .locate(storage, parent, buffer)?
            .ok_or(ClientError::NoSuchParent(parent.id))?;

        // Get a new perspective and store it in the transaction.
        let p = self
            .perspective
            .insert(storage.get_linear_perspective(loc)?);

        self.phead = Some(parent.id);
        self.heads.remove(&parent.id);

        Ok(p)
    }

    fn init<'sp>(
        &mut self,
        command: &impl Command,
        policy_store: &mut PS,
        provider: &'sp mut SP,
        sink: &mut impl Sink<PS::Effect>,
    ) -> Result<&'sp mut <SP as StorageProvider>::Storage, ClientError> {
        // Graph ID is the id of the init command by definition.
        if self.graph_id.as_base() != command.id().as_base() {
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

        let policy_id = policy_store.add_policy(policy_data)?;
        let policy = policy_store.get_policy(policy_id)?;

        // Get an empty perspective and run the init command.
        let mut perspective = provider.new_perspective(policy_id);
        sink.begin();
        if let Err(e) = policy.call_rule(
            command,
            &mut perspective,
            sink,
            CommandPlacement::OnGraphAtOrigin,
        ) {
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

/// Braid `heads` together and fold every braided command into a fact index
/// (the merged perspective). Emits effects to `sink`. Returns the fact index
/// and the N-way LCA.
#[allow(clippy::too_many_arguments)]
fn evaluate_braid<S, PS, F, MS>(
    storage: &mut S,
    heads: &[Location],
    sink: &mut impl Sink<PS::Effect>,
    policy: &PS::Policy,
    traversal: &mut TraversalBuffer,
    braid_buf: &mut BraidBuffer<S::Segment>,
    make_spill: &MS,
) -> Result<(S::FactIndex, Location), ClientError>
where
    S: Storage,
    PS: PolicyStore,
    F: Spill,
    MS: Fn() -> Result<F, StorageError>,
{
    let last_common_ancestor = braiding::last_common_ancestor(storage, heads)?;
    let mut order = braiding::braid::<_, F, MS>(
        storage,
        heads,
        last_common_ancestor,
        traversal,
        braid_buf,
        make_spill,
    )?;

    let mut iter = order.iter()?;
    let first = iter.next().assume("braid is non-empty")??;

    let mut braid_perspective = storage.get_fact_perspective(first)?;

    sink.begin();

    while let Some(location) = iter.next().transpose()? {
        let segment = storage.get_segment(location)?;
        let command = segment
            .get_command(location)
            .assume("braid only contains existing commands")?;

        let result = policy.call_rule(
            &command,
            &mut braid_perspective,
            sink,
            CommandPlacement::OnGraphInBraid,
        );

        // If the command failed in an uncontrolled way, rollback
        if let Err(e) = result
            && !matches!(e, PolicyError::Check)
        {
            sink.rollback();
            return Err(e.into());
        }
    }

    let braid = storage.write_facts(braid_perspective)?;

    sink.commit();

    Ok((braid, last_common_ancestor))
}

/// Pairwise-merge a head set down to a single head, writing merge segments.
/// Returns the resulting single head location. A one-element set is returned
/// as-is (no merge).
pub(crate) fn collapse_heads<S, PS, F, MS>(
    storage: &mut S,
    policy_store: &mut PS,
    heads: HeadSet,
    buffers: &mut RuntimeBuffers<S::Segment>,
    make_spill: &MS,
) -> Result<Location, ClientError>
where
    S: Storage,
    PS: PolicyStore,
    F: Spill,
    MS: Fn() -> Result<F, StorageError>,
{
    let mut q: VecDeque<(CmdId, Location)> =
        heads.iter().map(|la| (la.id, la.location())).collect();

    // The multi-head state being collapsed was produced by a `commit` that
    // already braided these same heads and emitted their effects in converged
    // order. Re-braiding the identical head set yields no new effects (braid
    // order is a stable global sort by `(priority, id)`), so emitting again
    // would only duplicate what `commit` delivered.
    let mut null = NullSink;
    while q.len() > 1 {
        let (left_id, mut left_loc) = q.pop_front().assume("len > 1")?;
        let (right_id, mut right_loc) = q.pop_front().assume("len > 1")?;

        let (policy, policy_id) = choose_policy(storage, policy_store, left_loc, right_loc)?;

        let mut buf = [0u8; MAX_COMMAND_LENGTH];
        let merge_ids = MergeIds::new(
            Address {
                id: left_id,
                max_cut: left_loc.max_cut,
            },
            Address {
                id: right_id,
                max_cut: right_loc.max_cut,
            },
        )
        .assume("merging different ids")?;
        if left_id > right_id {
            mem::swap(&mut left_loc, &mut right_loc);
        }
        let command = policy.merge(&mut buf, merge_ids)?;

        let (braid, last_common_ancestor) = evaluate_braid::<_, PS, F, MS>(
            storage,
            &[left_loc, right_loc],
            &mut null,
            policy,
            &mut buffers.traversal.primary,
            &mut buffers.braid,
            make_spill,
        )?;

        let mut perspective = storage.new_merge_perspective(
            left_loc,
            right_loc,
            last_common_ancestor,
            policy_id,
            braid,
        )?;
        perspective.add_command(&command)?;
        let segment = storage.write(perspective)?;
        q.push_back((segment.head_id(), segment.head_location()?));
    }

    let (_, loc) = q.pop_front().assume("head set non-empty")?;
    Ok(loc)
}

/// Select the policy from two locations with the greatest serial value.
fn choose_policy<'a, PS: PolicyStore>(
    storage: &impl Storage,
    policy_store: &'a PS,
    left: Location,
    right: Location,
) -> Result<(&'a PS::Policy, PolicyId), ClientError> {
    Ok(core::cmp::max_by_key(
        get_policy(storage, policy_store, left)?,
        get_policy(storage, policy_store, right)?,
        |(p, _)| p.serial(),
    ))
}

fn get_policy<'a, PS: PolicyStore>(
    storage: &impl Storage,
    policy_store: &'a PS,
    location: Location,
) -> Result<(&'a PS::Policy, PolicyId), ClientError> {
    let segment = storage.get_segment(location)?;
    let policy_id = segment.policy();
    let policy = policy_store.get_policy(policy_id)?;
    Ok((policy, policy_id))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use aranya_crypto::id::{Id, IdTag};
    use buggy::Bug;
    use test_log::test;

    use super::*;
    use crate::{
        Bytes, ClientState, Keys, MaxCut, MemSpill, MergeIds, Perspective, Policy, Priority,
        policy::{ActionPlacement, CommandPlacement},
        storage::linear::testing::MemStorageProvider,
        testing::{hash_for_testing_only, short_b58},
    };

    struct SeqPolicyStore;

    /// [`SeqPolicy`] is a very simple policy which appends the id of each
    /// command to a fact named `b"seq"`. At each point in the graph, the value
    /// of this fact should be equal to the ids in braid order of all facts up
    /// to that point.
    struct SeqPolicy;

    struct SeqCommand {
        id: CmdId,
        prior: Prior<Address>,
        finalize: bool,
        data: Box<str>,
        max_cut: MaxCut,
    }

    impl PolicyStore for SeqPolicyStore {
        type Policy = SeqPolicy;
        type Effect = ();

        fn add_policy(&mut self, _policy: &[u8]) -> Result<PolicyId, PolicyError> {
            Ok(PolicyId::new(0))
        }

        fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
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
            _placement: CommandPlacement,
        ) -> Result<(), PolicyError> {
            assert!(
                !matches!(command.parent(), Prior::Merge { .. }),
                "merges shouldn't be evaluated"
            );

            let data = command.bytes();
            // (q)uiet commmands add no facts so we can test that.
            if !data.starts_with(b"q") {
                // For init and basic commands, append the id to the seq fact.
                if let Some(seq) = facts
                    .query("seq", &Keys::default())
                    .assume("can query")?
                    .as_deref()
                {
                    facts
                        .insert(
                            "seq".into(),
                            Keys::default(),
                            [seq, b":", data].concat().into(),
                        )
                        .unwrap();
                } else {
                    facts
                        .insert("seq".into(), Keys::default(), data.into())
                        .unwrap();
                }
            }
            Ok(())
        }

        fn call_action(
            &self,
            _action: Self::Action<'_>,
            _facts: &mut impl Perspective,
            _sink: &mut impl Sink<Self::Effect>,
            _placement: ActionPlacement,
        ) -> Result<(), PolicyError> {
            unimplemented!()
        }

        fn merge<'a>(
            &self,
            _target: &'a mut [u8],
            ids: MergeIds,
        ) -> Result<Self::Command<'a>, PolicyError> {
            let (left, right): (Address, Address) = ids.into();
            let parents = [*left.id.as_array(), *right.id.as_array()];
            let id = hash_for_testing_only(parents.as_flattened());

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
        fn new(id: CmdId, prior: Prior<Address>, max_cut: MaxCut) -> Self {
            let data = short_b58(id).into_boxed_str();
            Self {
                id,
                prior,
                finalize: false,
                data,
                max_cut,
            }
        }

        fn finalize(id: CmdId, prev: Address, max_cut: MaxCut) -> Self {
            let data = short_b58(id).into_boxed_str();
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

        fn id(&self) -> CmdId {
            self.id
        }

        fn parent(&self) -> Prior<Address> {
            self.prior
        }

        fn policy(&self) -> Option<&[u8]> {
            // We don't actually need any policy bytes, but the
            // transaction/storage requires it on init commands.
            match self.prior {
                Prior::None => Some(b""),
                _ => None,
            }
        }

        fn bytes(&self) -> &[u8] {
            self.data.as_bytes()
        }

        fn max_cut(&self) -> Result<MaxCut, Bug> {
            Ok(self.max_cut)
        }
    }

    struct NullSink;
    impl<Eff> Sink<Eff> for NullSink {
        fn begin(&mut self) {}
        fn consume(&mut self, _: Eff) {}
        fn rollback(&mut self) {}
        fn commit(&mut self) {}
    }

    /// [`GraphBuilder`] and the associated macro [`graph`] provide an easy way
    /// to create a graph with a specific structure.
    struct GraphBuilder<SP: StorageProvider> {
        client: ClientState<SeqPolicyStore, SP>,
        trx: Transaction<SP, SeqPolicyStore>,
        max_cuts: HashMap<CmdId, MaxCut>,
        buffers: RuntimeBuffers<SP::Segment>,
    }

    impl<SP: StorageProvider> GraphBuilder<SP> {
        pub fn init(
            mut client: ClientState<SeqPolicyStore, SP>,
            ids: &[CmdId],
        ) -> Result<Self, ClientError> {
            let mut trx = Transaction::new(GraphId::transmute(ids[0]));
            let mut prior: Prior<Address> = Prior::None;
            let mut max_cuts = HashMap::new();
            let mut buffers = RuntimeBuffers::new();
            for (max_cut, &id) in ids.iter().enumerate() {
                let max_cut = MaxCut::new(max_cut as u64);
                let cmd = SeqCommand::new(id, prior, max_cut);
                trx.add_commands(
                    &[cmd],
                    &mut client.provider,
                    &mut client.policy_store,
                    &mut NullSink,
                    &mut buffers,
                    &MemSpill::new,
                )?;
                max_cuts.insert(id, max_cut);
                prior = Prior::Single(Address { id, max_cut });
            }
            Ok(Self {
                client,
                trx,
                max_cuts,
                buffers,
            })
        }

        fn get_addr(&self, id: CmdId) -> Address {
            let max_cut = *self
                .max_cuts
                .get(&id)
                .unwrap_or_else(|| panic!("bad ID {id}"));
            Address { id, max_cut }
        }

        pub fn line(&mut self, prev: CmdId, ids: &[CmdId]) -> Result<(), ClientError> {
            let mut prev = self.get_addr(prev);
            for &id in ids {
                let max_cut = prev.max_cut.checked_add(1).unwrap();
                let cmd = SeqCommand::new(id, Prior::Single(prev), max_cut);
                self.trx.add_commands(
                    &[cmd],
                    &mut self.client.provider,
                    &mut self.client.policy_store,
                    &mut NullSink,
                    &mut self.buffers,
                    &MemSpill::new,
                )?;
                self.max_cuts.insert(id, max_cut);
                prev = Address { id, max_cut };
            }
            Ok(())
        }

        pub fn finalize(&mut self, prev: CmdId, id: CmdId) -> Result<(), ClientError> {
            let prev = self.get_addr(prev);
            let max_cut = prev.max_cut.checked_add(1).unwrap();
            let cmd = SeqCommand::finalize(id, prev, max_cut);
            self.trx.add_commands(
                &[cmd],
                &mut self.client.provider,
                &mut self.client.policy_store,
                &mut NullSink,
                &mut self.buffers,
                &MemSpill::new,
            )?;
            self.max_cuts.insert(id, max_cut);
            Ok(())
        }

        pub fn merge(
            &mut self,
            (left, right): (CmdId, CmdId),
            ids: &[CmdId],
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
                &mut self.client.policy_store,
                &mut NullSink,
                &mut self.buffers,
                &MemSpill::new,
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
                    &mut self.client.policy_store,
                    &mut NullSink,
                    &mut self.buffers,
                    &MemSpill::new,
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
                    .get_storage(self.trx.graph_id)
                    .unwrap()
                    .write(p)
                    .unwrap();
                self.trx
                    .heads
                    .insert(seg.head_id(), seg.head_location().unwrap());
            }
        }

        pub fn commit(&mut self) -> Result<(), ClientError> {
            let graph_id = self.trx.graph_id;
            let trx = mem::replace(&mut self.trx, Transaction::new(graph_id));
            assert!(trx.commit(
                &mut self.client.provider,
                &mut self.client.policy_store,
                &mut NullSink,
                &mut self.buffers,
                &MemSpill::new,
            )?);
            Ok(())
        }
    }

    fn mkid<Tag: IdTag>(x: &str) -> Id<Tag> {
        x.parse().unwrap()
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

    fn lookup(storage: &impl Storage, name: &str) -> Option<Bytes> {
        use crate::Query as _;
        // Read the committed fact cache, which is the braided state across all
        // graph heads (lazy merges keep the graph multi-head after commit, so
        // there is no single head segment whose facts represent the whole graph).
        let p = storage.fact_cache().unwrap();
        p.query(name, &[]).unwrap()
    }

    /// Number of committed graph heads.
    fn head_count(storage: &impl Storage) -> usize {
        storage.get_heads().unwrap().len()
    }

    /// The greatest `max_cut` across all committed graph heads.
    fn max_head_cut(storage: &impl Storage) -> MaxCut {
        storage
            .get_heads()
            .unwrap()
            .iter()
            .map(|la| la.max_cut)
            .max()
            .unwrap()
    }

    /// The sole committed graph head; panics if the graph is multi-head.
    fn sole_head(storage: &impl Storage) -> LocatedAddress {
        let heads = storage.get_heads().unwrap();
        assert_eq!(heads.len(), 1, "expected a single-head graph");
        heads.iter().next().unwrap()
    }

    #[test]
    fn test_simple() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
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
        graphviz::dot(g, "simple");

        assert_eq!(sole_head(g).max_cut, MaxCut::new(3));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:d:c");

        Ok(())
    }

    #[test]
    fn test_complex() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
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
        graphviz::dot(g, "complex");

        // Lazy merges: the graph ends multi-head (a8 merge plus the 42/45/46/47/48
        // descendants of 9). The braided fact cache below reflects the full state.
        assert_eq!(head_count(g), 4);
        assert_eq!(max_head_cut(g), MaxCut::new(12));

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
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
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
        graphviz::dot(g, "duplicates");

        assert_eq!(sole_head(g).max_cut, MaxCut::new(4));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:e");
    }

    #[test]
    fn test_mid_braid_1() {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "a";
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "mid_braid_1");

        // Lazy merges: the two branches from `d` (e/f/g and h/i/j) stay as two
        // separate heads (no synthetic merge command). The braided fact cache
        // below still reflects the full merged state.
        assert_eq!(head_count(g), 2);
        assert_eq!(max_head_cut(g), MaxCut::new(6));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:h:i:j:e:f:g");
    }

    #[test]
    fn test_mid_braid_2() {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "a";
            "a" < "b" "c" "d" "h" "i" "j";
            "d" < "e" "f" "g";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "mid_braid_2");

        // Lazy merges: two separate heads (h/i/j and e/f/g branches from `d`).
        assert_eq!(head_count(g), 2);
        assert_eq!(max_head_cut(g), MaxCut::new(6));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:h:i:j:e:f:g");
    }

    #[test]
    fn test_sequential_finalize() {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "a";
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            "e" < finalize "fff1";
            "fff1" < "x" "y";
            "y" < finalize "fff2";
            commit;
        };

        let g = gb.client.provider.get_storage(mkid("a")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "finalize_success");

        // Lazy merges: branches from `e` (the fff1->x->y->fff2 finalize chain
        // and f/g) and from `d` (h/i/j) remain as separate heads.
        assert_eq!(head_count(g), 3);
        assert_eq!(max_head_cut(g), MaxCut::new(8));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "a:b:c:d:e:fff1:x:y:fff2:h:i:j:f:g");
    }

    #[test]
    fn test_parallel_finalize() {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "a";
            "a" < "b" "c" "d" "e" "f" "g";
            "d" < "h" "i" "j";
            "e" < finalize "fff1";
            "i" < finalize "fff2";
        };
        let err = gb.commit().expect_err("merge should fail");
        assert!(matches!(err, ClientError::ParallelFinalize), "{err:?}");
    }

    /// Build a [`CmdId`] deterministically from a counter value.
    fn id_from_u64(n: u64) -> CmdId {
        hash_for_testing_only(&n.to_le_bytes())
    }

    /// Ingest more than MAX_HEADS divergent commands (all children of init)
    /// and assert that add_commands returns HeadSetFull before commit.
    ///
    /// With the early check, the error surfaces at ingest time.  Without it,
    /// add_commands would succeed and the error would surface at commit.
    #[test]
    fn test_head_set_overflow_errors_at_ingest() {
        let init_id: CmdId = id_from_u64(0);
        let graph_id = GraphId::transmute(init_id);
        let init_addr = Address {
            id: init_id,
            max_cut: MaxCut::new(0),
        };

        let init_cmd = SeqCommand::new(init_id, Prior::None, MaxCut::new(0));

        let mut client = ClientState::new(SeqPolicyStore, MemStorageProvider::default());
        let mut trx = Transaction::new(graph_id);
        let mut buffers = RuntimeBuffers::new();

        // Ingest the init command to create the graph.
        trx.add_commands(
            &[init_cmd],
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        )
        .expect("init must succeed");

        // Ingest MAX_HEADS siblings of init.  Each has Prior::Single(init_addr)
        // with a distinct id.  The result is MAX_HEADS divergent tips, which is
        // the maximum the HeadSet can hold -- still within bounds.
        for i in 1u64..=(MAX_HEADS as u64) {
            let id = id_from_u64(i);
            let cmd = SeqCommand::new(id, Prior::Single(init_addr), MaxCut::new(1));
            trx.add_commands(
                &[cmd],
                &mut client.provider,
                &mut client.policy_store,
                &mut NullSink,
                &mut buffers,
                &MemSpill::new,
            )
            .expect("sibling within capacity must succeed");
        }

        // One more sibling pushes the in-transaction head count above MAX_HEADS.
        // The early check must surface the error here, not at commit.
        // Use a counter value well outside the 1..=MAX_HEADS range to ensure a unique id.
        let overflow_id = id_from_u64(0xffff_ffff_ffff_ffff);
        let overflow_cmd = SeqCommand::new(overflow_id, Prior::Single(init_addr), MaxCut::new(1));
        let result = trx.add_commands(
            &[overflow_cmd],
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        );

        assert!(
            matches!(
                result,
                Err(ClientError::StorageError(StorageError::HeadSetFull(_)))
            ),
            "expected HeadSetFull at ingest, got: {result:?}"
        );
    }

    /// Ingest a couple commands, call `flush`, and assert `in_flight_heads`
    /// yields the expected tip and that the tip is resolvable in storage.
    #[test]
    fn test_flush_in_flight_heads() {
        let a: CmdId = id_from_u64(0);
        let b: CmdId = id_from_u64(1);
        let c: CmdId = id_from_u64(2);
        let graph_id = GraphId::transmute(a);

        let mut client = ClientState::new(SeqPolicyStore, MemStorageProvider::default());
        let mut trx = Transaction::new(graph_id);
        let mut buffers = RuntimeBuffers::new();

        // a (init) -> b -> c, a single linear chain. The sole tip is `c`.
        let init = SeqCommand::new(a, Prior::None, MaxCut::new(0));
        let cmd_b = SeqCommand::new(
            b,
            Prior::Single(Address {
                id: a,
                max_cut: MaxCut::new(0),
            }),
            MaxCut::new(1),
        );
        let cmd_c = SeqCommand::new(
            c,
            Prior::Single(Address {
                id: b,
                max_cut: MaxCut::new(1),
            }),
            MaxCut::new(2),
        );
        trx.add_commands(
            &[init, cmd_b, cmd_c],
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        )
        .expect("add_commands must succeed");

        // Before flush, the in-flight perspective holds the tip (it is not yet
        // written to a segment).
        trx.flush(&mut client.provider).expect("flush must succeed");

        // The frontier is the single tip `c`.
        let heads: Vec<LocatedAddress> = trx.in_flight_heads().collect();
        assert_eq!(heads.len(), 1, "expected a single tip, got {heads:?}");
        assert_eq!(heads[0].id, c, "tip should be the last command");

        // The tip is now resolvable in storage (written by flush).
        let storage = client.provider.get_storage(graph_id).unwrap();
        let loc = storage
            .get_location_from(
                heads[0].location(),
                Address {
                    id: c,
                    max_cut: MaxCut::new(2),
                },
                &mut buffers.traversal.primary,
            )
            .unwrap();
        assert!(loc.is_some(), "flushed tip must be resolvable in storage");
    }

    #[test]
    fn test_merge_bug() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "i";
            "i" < "j";
            "j" < "qo1";
            "j" < "qa1";
            "qo1" "qa1" < "m1";
            "m1" < "qo2";
            "m1" < "qa2";
            "qo2" "qa2" < "m2";
            "m2" < "h";
            commit;
        };
        let g = gb.client.provider.get_storage(mkid("i")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "merge-bug");

        assert_eq!(sole_head(g).max_cut, MaxCut::new(6));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "i:j:h");

        Ok(())
    }

    #[test]
    fn test_linear_bug() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "i";
            "i" < "j";
            commit;
            "j" < "qa" "qb";
            commit;
            "qa" < "c";
            "qb" "c" < "m";
            commit;
        };
        let g = gb.client.provider.get_storage(mkid("i")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "linear-bug");

        assert_eq!(sole_head(g).max_cut, MaxCut::new(4));

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert_eq!(seq, "i:j:c");

        Ok(())
    }

    #[test]
    fn test_fact_convergence_bug() -> Result<(), StorageError> {
        let mut gb = graph! {
            ClientState::new(SeqPolicyStore, MemStorageProvider::default());
            "i";
            "i" < "a" "b";
            "i" < "c";
            "a" "c" < "m1";
            "m1" "b" < "m2";
            commit;
        };
        let g = gb.client.provider.get_storage(mkid("i")).unwrap();

        #[cfg(feature = "graphviz")]
        graphviz::dot(g, "fact-convergence-bug");

        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap();
        assert!(
            "iabc".chars().all(|c| seq.contains(c)),
            "fact missing from {seq:?}"
        );

        Ok(())
    }

    #[cfg(feature = "graphviz")]
    mod graphviz {
        #![allow(clippy::unwrap_used)]

        use std::{
            collections::{HashSet, VecDeque},
            fs::File,
            io::BufWriter,
        };

        use dot_writer::{Attributes as _, DotWriter, Style};

        use crate::{
            Command as _, FactIndexExtra, Location, Prior, Query, Segment as _, Storage,
            testing::short_b58,
        };

        fn loc(location: impl Into<Location>) -> String {
            let location = location.into();
            format!("\"{}:{}\"", location.segment, location.max_cut)
        }

        fn get_seq(p: &impl Query) -> String {
            p.query("seq", &[]).unwrap().map_or(String::new(), |seq| {
                String::from_utf8(seq.into_vec()).unwrap()
            })
        }

        fn get_segments(storage: &impl Storage) -> Vec<Location> {
            let mut locations = Vec::new();
            let mut seen_segments = HashSet::new();
            let mut segment_queue = VecDeque::new();
            // Lazy merges keep the graph multi-head; walk back from every head.
            for head in storage.get_heads().unwrap().iter() {
                segment_queue.push_back(head.location());
            }
            while let Some(location) = segment_queue.pop_front() {
                if !seen_segments.insert(location.segment) {
                    continue;
                }
                let segment = storage.get_segment(location).unwrap();
                segment_queue.extend(segment.prior());
                locations.push(location);
            }
            locations.sort_by_key(|loc| loc.segment);
            locations
        }

        fn dotwrite(storage: &impl Storage<FactIndex: FactIndexExtra>, out: &mut DotWriter<'_>) {
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

            let mut seen_facts = HashSet::new();
            let mut external_facts = Vec::new();

            let segments = get_segments(storage);

            for &location in &segments {
                let segment = storage.get_segment(location).unwrap();

                let mut cluster = graph.cluster();
                match segment.prior() {
                    Prior::None => {
                        cluster.graph_attributes().set("color", "green", false);
                    }
                    Prior::Single(..) => {}
                    Prior::Merge(..) => {
                        cluster.graph_attributes().set("color", "crimson", false);
                    }
                }

                // Draw commands and edges between commands within the segment.
                for (i, cmd) in segment
                    .get_from(segment.first_location())
                    .into_iter()
                    .enumerate()
                {
                    {
                        let mut node =
                            cluster.node_named(loc((segment.index(), cmd.max_cut().unwrap())));
                        node.set_label(&short_b58(cmd.id()));
                        match cmd.parent() {
                            Prior::None => {
                                node.set("shape", "house", false);
                            }
                            Prior::Single(..) => {}
                            Prior::Merge(..) => {
                                node.set("shape", "hexagon", false);
                            }
                        }
                    }
                    if i > 0 {
                        let previous = cmd.max_cut().unwrap().decremented().expect("i must be > 0");
                        cluster.edge(
                            loc((segment.index(), cmd.max_cut().unwrap())),
                            loc((segment.index(), previous)),
                        );
                    }
                }

                // Draw edges to previous segments.
                let first = loc(segment.first_location());
                for p in segment.prior() {
                    cluster.edge(&first, loc(p));
                }

                // Draw fact index for this segment.
                let facts = segment.facts().unwrap();
                let curr = facts.name();
                cluster
                    .node_named(curr.clone())
                    .set_label(&get_seq(&facts))
                    .set("shape", "cylinder", false)
                    .set("color", "black", false)
                    .set("style", "solid", false);
                cluster
                    .edge(loc(segment.head_location().unwrap()), &curr)
                    .attributes()
                    .set("color", "red", false);

                seen_facts.insert(curr);

                // Make sure prior facts of fact index will get processed later.
                let mut prior = facts.prior().unwrap();
                while let Some(node) = prior {
                    let name = node.name();
                    if !seen_facts.insert(name) {
                        break;
                    }
                    prior = node.prior().unwrap();
                    external_facts.push(node);
                }
            }

            graph
                .node_attributes()
                .set("shape", "cylinder", false)
                .set("color", "black", false)
                .set("style", "solid", false);

            for fact in external_facts {
                // Draw nodes for fact indices not directly associated with a segment.
                graph.node_named(fact.name()).set_label(&get_seq(&fact));

                // Draw edge to prior facts.
                if let Some(prior) = fact.prior().unwrap() {
                    graph
                        .edge(fact.name(), prior.name())
                        .attributes()
                        .set("color", "blue", false);
                }
            }

            // Draw edges to prior facts for fact indices in segments.
            for &location in &segments {
                let segment = storage.get_segment(location).unwrap();
                let facts = segment.facts().unwrap();
                if let Some(prior) = facts.prior().unwrap() {
                    graph
                        .edge(facts.name(), prior.name())
                        .attributes()
                        .set("color", "blue", false);
                }
            }

            // Draw HEAD indicator with an edge to each graph head.
            graph.node_named("HEAD").set("shape", "none", false);
            for head in storage.get_heads().unwrap().iter() {
                graph.edge("HEAD", loc(head.location()));
            }
        }

        pub fn dot(storage: &impl Storage<FactIndex: FactIndexExtra>, name: &str) {
            std::fs::create_dir_all(".ignore").unwrap();
            dotwrite(
                storage,
                &mut DotWriter::from(&mut BufWriter::new(
                    File::create(format!(".ignore/{name}.dot")).unwrap(),
                )),
            );
        }
    }
}
