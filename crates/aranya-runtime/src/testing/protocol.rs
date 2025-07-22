//! [`Engine`]/[`Policy`] test implementation.
use alloc::vec::Vec;

use buggy::bug;
use postcard::ser_flavors::Slice;
use serde::{Deserialize, Serialize};
use tracing::{error, trace};

use crate::{
    Address, Command, CommandId, CommandRecall, Engine, EngineError, FactPerspective, Keys,
    MAX_COMMAND_LENGTH, MergeIds, Perspective, Policy, PolicyId, Prior, Priority, Sink, alloc,
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
    id: CommandId,
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

    fn id(&self) -> CommandId {
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

pub struct TestEngine {
    policy: TestPolicy,
}

impl TestEngine {
    pub fn new() -> TestEngine {
        TestEngine {
            policy: TestPolicy::new(0),
        }
    }
}

impl Default for TestEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for TestEngine {
    type Policy = TestPolicy;
    type Effect = TestEffect;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, EngineError> {
        Ok(&self.policy)
    }
}

pub struct TestPolicy {
    serial: u32,
}

impl TestPolicy {
    pub fn new(serial: u32) -> Self {
        TestPolicy { serial }
    }

    fn origin_check_message(
        &self,
        command: &WireBasic,
        facts: &mut impl FactPerspective,
    ) -> Result<(), EngineError> {
        let (group, count) = command.payload;

        let key = group.to_be_bytes();
        let value = count.to_be_bytes();

        facts.insert("payload".into(), Keys::from_iter([key]), value.into());
        Ok(())
    }

    fn call_rule_internal(
        &self,
        policy_command: &WireProtocol,
        facts: &mut impl FactPerspective,
        sink: &mut impl Sink<<TestPolicy as Policy>::Effect>,
    ) -> Result<(), EngineError> {
        if let WireProtocol::Basic(m) = &policy_command {
            self.origin_check_message(m, facts)?;

            sink.consume(TestEffect::Got(m.payload.1));
        }

        Ok(())
    }

    fn init<'a>(&self, target: &'a mut [u8], nonce: u64) -> Result<TestProtocol<'a>, EngineError> {
        let message = WireInit {
            nonce: u128::from(nonce),
            policy_num: nonce.to_le_bytes(),
        };

        let command = WireProtocol::Init(message);
        let data = write(target, &command)?;
        let id = CommandId::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn basic<'a>(
        &self,
        target: &'a mut [u8],
        parent: Address,
        payload: (u64, u64),
    ) -> Result<TestProtocol<'a>, EngineError> {
        let prority = 0; //BUG

        let message = WireBasic {
            parent,
            prority,
            payload,
        };

        let command = WireProtocol::Basic(message);
        let data = write(target, &command)?;
        let id = CommandId::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }
}

fn write<'a>(target: &'a mut [u8], message: &WireProtocol) -> Result<&'a mut [u8], EngineError> {
    postcard::serialize_with_flavor(message, Slice::new(target))
        .inspect_err(|err| error!(?err))
        .map_err(|_| EngineError::Write)
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
        TestSink {
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
            let expect = self.expect.remove(0);
            trace!(consuming = ?effect, expected = ?expect, remainder = ?self.expect);
            assert_eq!(
                effect, expect,
                "consumed {effect:?} while expecting {expect:?}"
            );
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
        _recall: CommandRecall,
    ) -> Result<(), EngineError> {
        let policy_command: WireProtocol = postcard::from_bytes(command.bytes())
            .inspect_err(|err| error!(?err))
            .map_err(|_| EngineError::Read)?;
        self.call_rule_internal(&policy_command, facts, sink)
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<TestProtocol<'a>, EngineError> {
        let (left, right) = ids.into();
        let command = WireProtocol::Merge(WireMerge { left, right });
        let data = write(target, &command)?;
        let id = CommandId::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn call_action(
        &self,
        action: Self::Action<'_>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effect>,
    ) -> Result<(), EngineError> {
        let parent = match facts.head_address()? {
            Prior::None => Address {
                id: CommandId::default(),
                max_cut: 0,
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
                    .add_command(&command)
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| EngineError::Write)?;
            }
            TestActions::SetValue(key, value) => {
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let payload = (key, value);
                let command = self.basic(target, parent, payload)?;

                self.call_rule_internal(&command.command, facts, sink)?;

                facts
                    .add_command(&command)
                    .inspect_err(|err| error!(?err))
                    .map_err(|_| EngineError::Write)?;
            }
        }

        Ok(())
    }
}
