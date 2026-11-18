use alloc::vec::Vec;

use aranya_crypto::{
    BaseId, CipherSuite, CmdId, DeviceId, Engine, Signature, SigningKey, VerifyingKey, policy::Cmd,
};
use aranya_policy_vm::Struct;
use buggy::bug;

use super::protocol::{BasicEnvelope, Envelope, EphemeralEnvelope, FinalizeEnvelope, InitEnvelope};
use crate::GraphId;

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("signature bytes were malformed")]
    BadSignature(#[source] aranya_crypto::ImportError),
    #[error("command ID did not match")]
    IdMismatch,
    #[error("command data does not match its flavor")]
    BadContext,
    #[error(transparent)]
    Crypto(#[from] aranya_crypto::Error),
}

pub struct SealCtx<CE: Engine> {
    pub author: DeviceId,
    pub key: SigningKey<CE::CS>,
}

impl<CE: Engine> Clone for SealCtx<CE>
where
    SigningKey<CE::CS>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            author: self.author,
            key: self.key.clone(),
        }
    }
}

pub(super) struct Sealed<CS: CipherSuite> {
    pub payload: Vec<u8>,
    pub envelope: Envelope,
    pub signature: Signature<CS>,
}

pub(super) fn seal_with_key<CS: CipherSuite>(
    key: &SigningKey<CS>,
    flavor: &str,
    command_struct: &Struct,
    payload: Vec<u8>,
    author_id: DeviceId,
    parent_id: CmdId,
    policy: Option<&[u8]>,
) -> Result<Sealed<CS>, aranya_crypto::Error> {
    if (flavor == "init") != (parent_id == CmdId::default()) {
        bug!("must seal without parent only at init");
    }

    let fact_root = BaseId::default(); // TODO(jdygert): real fact root
    let cmd = {
        let name = command_struct.name.as_str();
        let data = payload.as_slice();
        match (flavor, policy) {
            ("init", Some(policy)) => Cmd::Init { name, data, policy },
            ("basic", None) => Cmd::Basic {
                name,
                parent_id: &parent_id,
                data,
            },
            ("finalize", Some(policy)) => Cmd::Finalize {
                name,
                parent_id: &parent_id,
                fact_root: &fact_root,
                data,
                policy,
            },
            ("ephemeral", None) => Cmd::Ephemeral {
                name,
                graph_id: &GraphId::transmute(parent_id),
                data,
            },
            _ => bug!("seal has invalid context"),
        }
    };

    let (signature, command_id) = key.sign_cmd(cmd)?;

    let envelope = match flavor {
        "init" => Envelope::Init(InitEnvelope {
            command_id,
            author_id,
        }),
        "basic" => Envelope::Basic(BasicEnvelope {
            command_id,
            parent_id,
            author_id,
        }),
        "finalize" => Envelope::Finalize(FinalizeEnvelope {
            command_id,
            parent_id,
            fact_root,
        }),
        "ephemeral" => Envelope::Ephemeral(EphemeralEnvelope {
            command_id,
            graph_id: GraphId::transmute(parent_id),
            author_id,
        }),
        _ => bug!("unknown flavor"),
    };

    Ok(Sealed {
        payload,
        envelope,
        signature,
    })
}

pub(super) fn open_with_key<CS: CipherSuite>(
    key: VerifyingKey<CS>,
    command_struct: &Struct,
    data: &[u8],
    signature: &[u8],
    envelope: &Envelope,
    policy: Option<&[u8]>,
) -> Result<(), OpenError> {
    let signature = Signature::<CS>::from_bytes(signature).map_err(OpenError::BadSignature)?;

    let name = command_struct.name.as_str();

    let cmd = match (envelope, policy) {
        (Envelope::Init(InitEnvelope { .. }), Some(policy)) => Cmd::Init { name, data, policy },
        (Envelope::Basic(BasicEnvelope { parent_id, .. }), None) => Cmd::Basic {
            name,
            parent_id,
            data,
        },
        (
            Envelope::Finalize(FinalizeEnvelope {
                parent_id,
                fact_root,
                ..
            }),
            Some(policy),
        ) => Cmd::Finalize {
            name,
            parent_id,
            fact_root,
            data,
            policy,
        },
        (Envelope::Ephemeral(EphemeralEnvelope { graph_id, .. }), None) => Cmd::Ephemeral {
            name,
            graph_id,
            data,
        },
        _ => return Err(OpenError::BadContext),
    };

    let id = key.verify_cmd(cmd, &signature)?;
    if id != envelope.command_id() {
        return Err(OpenError::IdMismatch);
    }

    Ok(())
}
