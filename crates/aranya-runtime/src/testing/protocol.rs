//! [`PolicyStore`]/[`Policy`] test implementation.
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::mem;

use buggy::bug;
use postcard::ser_flavors::Slice;
use serde::{Deserialize, Serialize};
use spin::mutex::Mutex;
use tracing::{error, trace};

use crate::{
    Address, CmdId, Command, FactPerspective, Keys, MAX_COMMAND_LENGTH, MaxCut, MergeIds,
    Perspective, Policy, PolicyError, PolicyId, PolicyStore, Prior, Priority, Sink, alloc,
    testing::hash_for_testing_only,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireInit {
    pub nonce: u128,
    pub policy_num: [u8; 8],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireMerge {
    pub left: Address,
    pub right: Address,
}

#[derive(Serialize, Deserialize, Debug, Clone, Ord, Eq, PartialOrd, PartialEq)]
pub struct WireBasic {
    pub parent: Address,
    pub prority: u32,
    pub payload: (u64, u64),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WireProtocol {
    Init(WireInit),
    Merge(WireMerge),
    Basic(WireBasic),
}

#[derive(Debug, Clone)]
pub struct TestProtocol<'a> {
    id: CmdId,
    command: WireProtocol,
    data: &'a [u8],
}

impl Command for TestProtocol<'_> {
    fn priority(&self) -> Priority {
        match &self.command {
            WireProtocol::Init(_) => Priority::Init,
            WireProtocol::Merge(_) => Priority::Merge,
            WireProtocol::Basic(m) => Priority::Basic(m.prority),
        }
    }

    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        match &self.command {
            WireProtocol::Init(_) => Prior::None,
            WireProtocol::Basic(m) => Prior::Single(m.parent),
            WireProtocol::Merge(m) => Prior::Merge(m.left, m.right),
        }
    }

    fn policy(&self) -> Option<&[u8]> {
        match &self.command {
            WireProtocol::Init(m) => Some(&m.policy_num),
            WireProtocol::Merge(_) => None,
            WireProtocol::Basic(_) => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.data
    }
}

pub struct TestPolicyStore {
    policy: TestPolicy,
}

impl TestPolicyStore {
    pub fn new() -> Self {
        Self {
            policy: TestPolicy::new(0),
        }
    }
}

impl Default for TestPolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStore for TestPolicyStore {
    type Policy = TestPolicy;
    type Effect = EmittedTestEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, PolicyError> {
        Ok(PolicyId::new(policy[0].into()))
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&self.policy)
    }
}

pub struct TestPolicy {
    serial: u32,
}

impl TestPolicy {
    pub fn new(serial: u32) -> Self {
        Self { serial }
    }

    fn origin_check_message(
        &self,
        command: &WireBasic,
        facts: &mut impl FactPerspective,
    ) -> Result<(), PolicyError> {
        let (group, count) = command.payload;

        let key = group.to_be_bytes();
        let value = count.to_be_bytes();

        facts
            .insert("payload".into(), Keys::from_iter([key]), value.into())
            .map_err(|_| PolicyError::Write)?;

        Ok(())
    }

    fn call_rule_internal(
        &self,
        id: CmdId,
        policy_command: &WireProtocol,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<<Self as Policy>::Effect>,
    ) -> Result<(), PolicyError> {
        if let WireProtocol::Basic(m) = &policy_command {
            self.origin_check_message(m, facts)?;

            sink.consume((id, TestEffect::Got(m.payload.1)));
        }

        Ok(())
    }

    fn init<'a>(&self, target: &'a mut [u8], nonce: u64) -> Result<TestProtocol<'a>, PolicyError> {
        let message = WireInit {
            nonce: u128::from(nonce),
            policy_num: nonce.to_le_bytes(),
        };

        let command = WireProtocol::Init(message);
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        payload: (u64, u64),
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let prority = 0; //BUG

        let message = WireBasic {
            parent,
            prority,
            payload,
        };

        let command = WireProtocol::Basic(message);
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }
}

fn write<'a>(target: &'a mut [u8], message: &WireProtocol) -> Result<&'a mut [u8], PolicyError> {
    postcard::serialize_with_flavor(message, Slice::new(target))
        .inspect_err(|err| error!(?err))
        .map_err(|_| PolicyError::Write)
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum TestEffect {
    Got(u64),
}

/// A [`TestEffect`] as emitted: tagged with the command that produced it, so
/// sinks can tell a re-evaluation of a command (e.g. in a braid) from a new
/// emission. Expectations stay plain [`TestEffect`]s.
pub type EmittedTestEffect = (CmdId, TestEffect);

#[derive(Debug, Default)]
struct PoolInner {
    expect: Vec<TestEffect>,
    ignore_expect: bool,
    /// Effects from committed batches, keyed by the receiving client and
    /// the emitting command.
    seen: BTreeSet<(u64, EmittedTestEffect)>,
}

/// The expectation multiset and per-client delivery history shared by a set
/// of [`TestSink`]s. Mint one sink per client with [`Self::sink`].
#[derive(Debug, Clone, Default)]
pub struct SinkPool(Arc<Mutex<PoolInner>>);

impl SinkPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink delivering to `client` against this pool.
    #[must_use]
    pub fn sink(&self, client: u64) -> TestSink {
        TestSink {
            pool: self.clone(),
            client,
            pending: Vec::new(),
        }
    }

    pub fn add_expectation(&self, expect: TestEffect) {
        self.0.lock().expect.push(expect);
    }

    pub fn count(&self) -> usize {
        self.0.lock().expect.len()
    }

    /// The expectations not yet satisfied, for test failure messages.
    pub fn remaining(&self) -> Vec<TestEffect> {
        self.0.lock().expect.clone()
    }

    pub fn ignore_expectations(&self, ignore: bool) {
        self.0.lock().ignore_expect = ignore;
    }

    /// Forgets everything delivered to `client`, e.g. because it removed
    /// its graph: commands it re-ingests legitimately re-deliver.
    pub fn forget_client(&self, client: u64) {
        self.0.lock().seen.retain(|(c, _)| *c != client);
    }
}

/// An expectation-checking sink that drops duplicate deliveries.
///
/// The runtime may re-evaluate a command (braids re-run commands whenever
/// heads are merged); a re-evaluation that reproduces an identical effect
/// is dropped instead of matched against expectations, while an effect the
/// re-evaluation changed is delivered as new.
///
/// The duplicate drop is per client, since each client's runtime delivers a
/// command's effect once. A `TestSink` delivers to a single client, baked in
/// at construction by [`SinkPool::sink`]; sinks minted from one pool share
/// its expectation multiset.
#[derive(Debug, Clone)]
pub struct TestSink {
    pool: SinkPool,
    /// The client this sink delivers to.
    client: u64,
    /// Effects consumed since `begin`, held until `commit` so a rolled
    /// back evaluation leaves no trace in the pool.
    pending: Vec<EmittedTestEffect>,
}

impl TestSink {
    /// A standalone single-client sink over its own private pool.
    pub fn new() -> Self {
        SinkPool::new().sink(0)
    }
}

impl Default for TestSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink<EmittedTestEffect> for TestSink {
    fn begin(&mut self) {
        self.pending.clear();
    }

    fn consume(&mut self, effect: EmittedTestEffect) {
        trace!(?effect, client = self.client, "consume");
        self.pending.push(effect);
    }

    fn rollback(&mut self) {
        self.pending.clear();
    }

    fn commit(&mut self) {
        let pool = &mut *self.pool.0.lock();
        for emitted in mem::take(&mut self.pending) {
            if !pool.seen.insert((self.client, emitted.clone())) {
                // A re-evaluation reproduced an effect this client already
                // received; drop the duplicate.
                continue;
            }
            let (_, effect) = emitted;
            if !pool.ignore_expect {
                assert!(!pool.expect.is_empty(), "consumed {effect:?} while empty");
                // Match expectations as a multiset (content + count) rather than
                // strict FIFO order: every expected effect must be produced exactly
                // once, but the emit order is not asserted.
                let pos = pool.expect.iter().position(|e| *e == effect);
                trace!(consuming = ?effect, expected = ?pool.expect);
                assert!(
                    pos.is_some(),
                    "consumed {effect:?} which is not among remaining expectations {:?}",
                    pool.expect
                );
                if let Some(i) = pos {
                    pool.expect.remove(i);
                }
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TestActions {
    Init(u64),
    SetValue(u64, u64),
}

impl Policy for TestPolicy {
    type Effect = EmittedTestEffect;
    type Action<'a> = TestActions;
    type Command<'a> = TestProtocol<'a>;

    fn serial(&self) -> u32 {
        self.serial
    }

    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<Self::Effect>,
        _placement: crate::policy::CommandPlacement,
    ) -> Result<(), PolicyError> {
        let policy_command: WireProtocol = postcard::from_bytes(command.bytes())
            .inspect_err(|err| error!(?err))
            .map_err(|_| PolicyError::Read)?;
        self.call_rule_internal(command.id(), &policy_command, facts, sink)
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let (left, right) = ids.into();
        let command = WireProtocol::Merge(WireMerge { left, right });
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
        _placement: crate::policy::ActionPlacement,
    ) -> Result<(), PolicyError> {
        let parent = match facts.head_address()? {
            Prior::None => Address {
                id: CmdId::default(),
                max_cut: MaxCut::new(0),
            },
            Prior::Single(id) => id,
            Prior::Merge(_, _) => bug!("cannot get merge command in call_action"),
        };
        match action {
            TestActions::Init(nonce) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let command = self.init(target, nonce)?;

                self.call_rule_internal(command.id, &command.command, facts, sink)?;

                facts
                    .add_command(&command)
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
            TestActions::SetValue(key, value) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let payload = (key, value);
                let command = self.basic(target, parent, payload)?;

                self.call_rule_internal(command.id, &command.command, facts, sink)?;

                facts
                    .add_command(&command)
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
        }

        Ok(())
    }
}
