use core::convert::Infallible;

use postcard::{from_bytes, ser_flavors::Slice, serialize_with_flavor};
use serde::{Deserialize, Serialize};

use super::*;

impl From<StorageError> for EngineError {
    fn from(_: StorageError) -> Self {
        EngineError::InternalError
    }
}

impl From<postcard::Error> for EngineError {
    fn from(_error: postcard::Error) -> Self {
        EngineError::Read
    }
}

impl From<Infallible> for EngineError {
    fn from(_error: Infallible) -> Self {
        EngineError::Write
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireInit {
    pub nonce: u128,
    pub policy_num: [u8; 8],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WireMerge {
    pub left: Id,
    pub right: Id,
}

#[derive(Serialize, Deserialize, Debug, Clone, Ord, Eq, PartialOrd, PartialEq)]
pub struct WireBasic {
    pub parent: Id,
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
    id: Id,
    command: WireProtocol,
    data: &'a [u8],
}

impl<'a> Command<'a> for TestProtocol<'a> {
    fn priority(&self) -> Priority {
        match &self.command {
            WireProtocol::Init(_) => Priority::Init,
            WireProtocol::Merge(_) => Priority::Merge,
            WireProtocol::Basic(m) => Priority::Basic(m.prority),
        }
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Parent {
        match &self.command {
            WireProtocol::Init(_) => Parent::None,
            WireProtocol::Merge(m) => Parent::Merge(m.left, m.right),
            WireProtocol::Basic(m) => Parent::Id(m.parent),
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

impl Engine for TestEngine {
    type Policy = TestPolicy;
    type Payload = (u64, u64);
    type Effects = TestEffect;
    type Actions = TestActions;

    fn add_policy(&mut self, policy: &[u8]) -> Result<PolicyId, EngineError> {
        Ok(PolicyId::new(policy[0] as usize))
    }

    fn get_policy<'a>(&'a self, _id: &PolicyId) -> Result<&'a Self::Policy, EngineError> {
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
        facts: &mut impl Perspective,
    ) -> Result<bool, EngineError> {
        let (group, count) = command.payload;

        let mut key = Vec::<u8>::new();
        key.extend_from_slice(&group.to_be_bytes());

        let mut value = Vec::<u8>::new();
        value.extend_from_slice(&count.to_be_bytes());

        if let Some(current) = facts.query(&key)? {
            let current_val = u64::from_be_bytes(current[0..8].try_into().unwrap());
            match current_val <= count {
                true => {
                    facts.insert(key.as_slice(), value.as_slice());
                    Ok(true)
                }
                false => Ok(false),
            }
        } else {
            facts.insert(key.as_slice(), value.as_slice());
            Ok(true)
        }
    }

    fn call_rule_internal(
        &self,
        policy_command: &WireProtocol,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<<TestPolicy as Policy>::Effects>,
    ) -> Result<bool, EngineError> {
        let passed = match &policy_command {
            WireProtocol::Init(_) => true,
            WireProtocol::Merge(_) => true,
            WireProtocol::Basic(m) => {
                let passed = self.origin_check_message(m, facts)?;

                if passed {
                    sink.consume(TestEffect::Got(m.payload.1));
                }

                passed
            }
        };

        Ok(passed)
    }
}

fn write<'a>(target: &'a mut [u8], message: &WireProtocol) -> Result<&'a mut [u8], EngineError> {
    Ok(serialize_with_flavor::<WireProtocol, Slice<'a>, &mut [u8]>(
        message,
        Slice::new(target),
    )?)
}

#[derive(PartialEq, Eq, Debug)]
pub enum TestEffect {
    Got(u64),
}

pub struct TestSink {
    expect: Vec<TestEffect>,
}

impl TestSink {
    pub fn new() -> Self {
        TestSink { expect: Vec::new() }
    }

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
        let expect = self.expect.remove(0);
        assert_eq!(effect, expect);
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
    SetValue(u64, u64),
}

impl Policy for TestPolicy {
    type Payload = (u64, u64);
    type Effects = TestEffect;
    type Actions = TestActions;
    type Command<'a> = TestProtocol<'a>;

    fn serial(&self) -> u32 {
        self.serial
    }

    fn read_command<'a>(&self, data: &'a [u8]) -> Result<TestProtocol<'a>, EngineError> {
        let id = Id::hash_for_testing_only(data);
        let command = from_bytes(data)?;

        Ok(TestProtocol::<'a> { id, command, data })
    }

    fn call_rule<'a>(
        &self,
        command: &impl Command<'a>,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        let policy_command: WireProtocol = from_bytes(command.bytes())?;
        let passed = self.call_rule_internal(&policy_command, facts, sink)?;

        if passed {
            let _ = facts.add_command(command);
        }

        Ok(passed)
    }

    fn init<'a>(
        &self,
        target: &'a mut [u8],
        policy_data: &[u8],
        _payload: &Self::Payload,
    ) -> Result<TestProtocol<'a>, EngineError> {
        let policy: [u8; 8] = policy_data[0..8].try_into().unwrap();
        let command = WireProtocol::Init(WireInit {
            nonce: 0,
            policy_num: policy,
        });
        let data = write(target, &command)?;
        let id = Id::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn merge<'a>(
        &self,
        target: &'a mut [u8],
        left: Id,
        right: Id,
    ) -> Result<TestProtocol<'a>, EngineError> {
        let command = WireProtocol::Merge(WireMerge { left, right });
        let data = write(target, &command)?;
        let id = Id::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }

    fn call_action(
        &self,
        parent: &Id,
        action: &Self::Actions,
        facts: &mut impl Perspective,
        sink: &mut impl Sink<Self::Effects>,
    ) -> Result<bool, EngineError> {
        match action {
            TestActions::SetValue(key, value) => {
                //let target = facts.get_target()?;
                let mut buffer = [0u8; MAX_COMMAND_LENGTH];
                let target = buffer.as_mut_slice();
                let payload = (*key, *value);
                let command = self.message(target, *parent, &payload)?;
                facts.add_command(&command).or(Err(EngineError::Write))?;

                let passed = self.call_rule_internal(&command.command, facts, sink)?;

                Ok(passed)
            }
        }
    }

    fn message<'a>(
        &self,
        target: &'a mut [u8],
        parent: Id,
        payload: &Self::Payload,
    ) -> Result<TestProtocol<'a>, EngineError> {
        let prority = 0; //BUG

        let message = WireBasic {
            parent,
            prority,
            payload: *payload,
        };

        let command = WireProtocol::Basic(message);
        let data = write(target, &command)?;
        let id = Id::hash_for_testing_only(data);

        Ok(TestProtocol { id, command, data })
    }
}