//! [`PolicyStore`]/[`Policy`] test implementation.
use alloc::vec::Vec;

use buggy::bug;
use postcard::ser_flavors::Slice;
use serde::{Deserialize, Serialize};
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
pub struct WireDelete {
    pub parent: Address,
    pub prority: u32,
    pub key: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireNoOp {
    pub parent: Address,
    pub prority: u32,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WireProtocol {
    Init(WireInit),
    Merge(WireMerge),
    Basic(WireBasic),
    Delete(WireDelete),
    NoOp(WireNoOp),
    /// A command whose rule writes its payload fact and then fails.
    ///
    /// Models a write-then-fail rule (e.g. a VM policy `finish` block that
    /// inserts a fact and then errors partway through): the runtime must
    /// revert the write when it rejects the command.
    Poison(WireBasic),
}

#[derive(Debug, Clone)]
pub struct TestProtocol<'a> {
    id: CmdId,
    command: WireProtocol,
    data: &'a [u8],
}

/// Derives a command's priority from its (id-covered) serialized body,
/// mirroring how a real policy derives priority from the command kind.
fn wire_priority(command: &WireProtocol) -> Priority {
    match command {
        WireProtocol::Init(_) => Priority::Init,
        WireProtocol::Merge(_) => Priority::Merge,
        WireProtocol::Basic(m) => Priority::Basic(m.prority),
        WireProtocol::Delete(m) => Priority::Basic(m.prority),
        WireProtocol::NoOp(m) => Priority::Basic(m.prority),
        WireProtocol::Poison(m) => Priority::Basic(m.prority),
    }
}

impl Command for TestProtocol<'_> {
    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        match &self.command {
            WireProtocol::Init(_) => Prior::None,
            WireProtocol::Basic(m) => Prior::Single(m.parent),
            WireProtocol::Merge(m) => Prior::Merge(m.left, m.right),
            WireProtocol::Delete(m) => Prior::Single(m.parent),
            WireProtocol::NoOp(m) => Prior::Single(m.parent),
            WireProtocol::Poison(m) => Prior::Single(m.parent),
        }
    }

    fn policy(&self) -> Option<&[u8]> {
        match &self.command {
            WireProtocol::Init(m) => Some(&m.policy_num),
            WireProtocol::Merge(_) => None,
            WireProtocol::Basic(_) => None,
            WireProtocol::Delete(_) => None,
            WireProtocol::NoOp(_) => None,
            WireProtocol::Poison(_) => None,
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
    type Effect = TestEffect;

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

        // All facts must live under "payload": the DSL's fact-equality
        // oracle (`collect_facts` in testing/dsl.rs) enumerates only this
        // name, so a fact written under another name escapes comparison.
        facts
            .insert("payload".into(), Keys::from_iter([key]), value.into())
            .map_err(|_| PolicyError::Write)?;

        Ok(())
    }

    fn call_rule_internal(
        &self,
        policy_command: &WireProtocol,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<<Self as Policy>::Effect>,
    ) -> Result<(), PolicyError> {
        match policy_command {
            WireProtocol::Basic(m) => {
                self.origin_check_message(m, facts)?;
                sink.consume(TestEffect::Got(m.payload.1));
            }
            WireProtocol::Delete(m) => {
                let key = m.key.to_be_bytes();
                // Must stay under "payload"; see `origin_check_message`.
                facts
                    .delete("payload".into(), Keys::from_iter([key]))
                    .map_err(|_| PolicyError::Write)?;
            }
            WireProtocol::Poison(m) => {
                // Write-then-fail: the fact write lands before the rule
                // rejects, so the caller's revert must clear it.
                self.origin_check_message(m, facts)?;
                return Err(PolicyError::Rejected);
            }
            WireProtocol::Init(_) | WireProtocol::Merge(_) | WireProtocol::NoOp(_) => {}
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

    pub(crate) fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        payload: (u64, u64),
        priority: u32,
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let message = WireBasic {
            parent,
            prority: priority,
            payload,
        };

        let command = WireProtocol::Basic(message);
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    /// Builds a [`WireProtocol::Poison`] command: its rule writes
    /// `payload` under the `"payload"` fact name and then rejects.
    ///
    /// There is deliberately no [`TestActions`] variant for this: an action
    /// whose rule fails never produces a command, so a poison command can
    /// only arrive on the ingest path (as if from a peer).
    pub(crate) fn poison<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        payload: (u64, u64),
        priority: u32,
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let message = WireBasic {
            parent,
            prority: priority,
            payload,
        };

        let command = WireProtocol::Poison(message);
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn delete<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        key: u64,
        priority: u32,
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let message = WireDelete {
            parent,
            prority: priority,
            key,
        };

        let command = WireProtocol::Delete(message);
        let data = write(target, &command)?;
        let id = hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn noop<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        nonce: u64,
        priority: u32,
    ) -> Result<TestProtocol<'a>, PolicyError> {
        let message = WireNoOp {
            parent,
            prority: priority,
            nonce,
        };

        let command = WireProtocol::NoOp(message);
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

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum TestEffect {
    Got(u64),
}

#[derive(Debug, Clone)]
pub struct TestSink {
    expect: Vec<TestEffect>,
    ignore_expect: bool,
}

impl TestSink {
    pub fn new() -> Self {
        Self {
            expect: Vec::new(),
            ignore_expect: false,
        }
    }

    pub fn ignore_expectations(&mut self, ignore: bool) {
        self.ignore_expect = ignore;
    }
}

impl Default for TestSink {
    fn default() -> Self {
        Self::new()
    }
}

impl TestSink {
    pub fn add_expectation(&mut self, expect: TestEffect) {
        self.expect.push(expect);
    }

    pub fn count(&self) -> usize {
        self.expect.len()
    }
}

impl Sink<TestEffect> for TestSink {
    fn begin(&mut self) {
        //NOOP
    }

    fn consume(&mut self, effect: TestEffect) {
        trace!(?effect, "consume");
        if !self.ignore_expect {
            assert!(!self.expect.is_empty(), "consumed {effect:?} while empty");
            // Match expectations as a multiset (content + count) rather than
            // strict FIFO order: every expected effect must be produced exactly
            // once, but the emit order is not asserted.
            let pos = self.expect.iter().position(|e| *e == effect);
            trace!(consuming = ?effect, expected = ?self.expect);
            assert!(
                pos.is_some(),
                "consumed {effect:?} which is not among remaining expectations {:?}",
                self.expect
            );
            if let Some(i) = pos {
                self.expect.remove(i);
            }
        }
    }

    fn rollback(&mut self) {
        //NOOP
    }

    fn commit(&mut self) {
        //NOOP
    }
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TestActions {
    Init(u64),
    SetValue(u64, u64),
    SetValuePriority(u64, u64, u32),
    DeleteValue(u64, u32),
    NoOp(u64, u32),
}

impl Policy for TestPolicy {
    type Effect = TestEffect;
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
    ) -> Result<Priority, PolicyError> {
        let policy_command: WireProtocol = postcard::from_bytes(command.bytes())
            .inspect_err(|err| error!(?err))
            .map_err(|_| PolicyError::Read)?;
        self.call_rule_internal(&policy_command, facts, sink)?;
        Ok(wire_priority(&policy_command))
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

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command, wire_priority(&command.command))
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
            TestActions::SetValue(key, value) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let payload = (key, value);
                let command = self.basic(target, parent, payload, 0)?;

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command, wire_priority(&command.command))
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
            TestActions::SetValuePriority(key, value, priority) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let payload = (key, value);
                let command = self.basic(target, parent, payload, priority)?;

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command, wire_priority(&command.command))
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
            TestActions::DeleteValue(key, priority) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let command = self.delete(target, parent, key, priority)?;

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command, wire_priority(&command.command))
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
            TestActions::NoOp(nonce, priority) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let command = self.noop(target, parent, nonce, priority)?;

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command, wire_priority(&command.command))
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| PolicyError::Write)?;
            }
        }

        Ok(())
    }
}
