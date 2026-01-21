pub mod testing_ffi;

use std::sync::Mutex;

use aranya_crypto::KeyStore;
use aranya_policy_vm::{FactKey, FactValue, MachineError, MachineErrorType, MachineIO, MachineIOError, MachineStack};
use aranya_runtime::FfiCallable as _;
use tracing::error;

use crate::io::testing_ffi::TestingFfi;

pub struct NullFactIterator;

impl Iterator for NullFactIterator {
    type Item = Result<(Vec<FactKey>, Vec<FactValue>), MachineIOError>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

pub struct PreambleIO<'o, CE, KS> {
    engine: &'o Mutex<CE>,
    testing_ffi: TestingFfi<KS>
}

impl<'o, CE, KS> PreambleIO<'o, CE, KS> {
    pub fn new(engine: &'o Mutex<CE>, keystore: KS) -> Self {
        let testing_ffi = TestingFfi::new(keystore);
        Self { engine, testing_ffi }
    }
}

impl<CE, KS> MachineIO<MachineStack> for PreambleIO<'_, CE, KS>
where
    CE: aranya_crypto::Engine,
    KS: KeyStore,
{
    type QueryIterator = NullFactIterator;

    fn fact_insert(
        &mut self,
        _name: aranya_policy_vm::Identifier,
        _key: impl IntoIterator<Item = FactKey>,
        _value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        error!("Cannot use facts in preamble");
        Err(MachineIOError::Internal)
    }

    fn fact_delete(
        &mut self,
        _name: aranya_policy_vm::Identifier,
        _key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        error!("Cannot use facts in preamble");
        Err(MachineIOError::Internal)
    }

    fn fact_query(
        &self,
        _name: aranya_policy_vm::Identifier,
        _key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        error!("Cannot use facts in preamble");
        Err(MachineIOError::Internal)
    }

    fn effect(
        &mut self,
        _name: aranya_policy_vm::Identifier,
        _fields: impl IntoIterator<Item = aranya_policy_vm::KVPair>,
        _command: aranya_crypto::CmdId,
        _recalled: bool,
    ) {
        error!("Cannot use effects in preamble");
    }

    fn call(
        &self,
        module: usize,
        procedure: usize,
        stack: &mut MachineStack,
        ctx: &aranya_policy_vm::CommandContext,
    ) -> Result<(), MachineError> {
        let mut guard = self.engine.lock();
        let eng = guard.as_deref_mut().expect("engine should be unlocked");
        match module {
            0 => self.testing_ffi.call(procedure, stack, ctx, eng),
            i => Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(i))),
        }
    }
}
