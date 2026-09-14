#![cfg(feature = "testing")]

use alloc::borrow::Cow;

use aranya_crypto::{CipherSuite, DeviceId, Engine};
use aranya_policy_vm::Struct;

use crate::{
    command::CmdId,
    vm_policy::{Envelope, Open, OpenError, QueryValue, Seal, SealError},
};

pub struct TestSeal(pub DeviceId);

impl<CE: Engine> Seal<CE> for TestSeal {
    fn seal_command(
        &self,
        _engine: &CE,
        _command_struct: &Struct,
        payload: &[u8],
        parent_id: CmdId,
    ) -> Result<Envelope<'_>, SealError> {
        let author_id = self.0;

        let command_id = cmd_id::<CE::CS>(parent_id, author_id, payload);

        Ok(Envelope {
            parent_id,
            author_id,
            command_id,
            signature: Cow::Borrowed(b"LOL"),
        })
    }
}

pub struct TestOpen;

impl<CE: Engine> Open<CE> for TestOpen {
    fn open_command(
        &self,
        _command_struct: &Struct,
        payload: &[u8],
        envelope: &Envelope<'_>,
        _facts: &dyn QueryValue,
    ) -> Result<(), OpenError> {
        let command_id = cmd_id::<CE::CS>(envelope.parent_id, envelope.author_id, payload);

        if envelope.command_id != command_id {
            return Err(OpenError::IdMismatch);
        }

        Ok(())
    }
}

fn cmd_id<CS: CipherSuite>(parent_id: CmdId, author_id: DeviceId, payload: &[u8]) -> CmdId {
    use aranya_crypto::id::IdExt as _;
    CmdId::new::<CS>(
        b"TestSealCommandId",
        [parent_id.as_bytes(), author_id.as_bytes(), payload],
    )
}
