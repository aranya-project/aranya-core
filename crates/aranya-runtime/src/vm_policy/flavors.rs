use aranya_crypto::{BaseId, DeviceId};
use aranya_policy_module::{
    ast::ident,
    flavor::{Flavor, Flavors},
};
use aranya_policy_vm::ffi::Valuable;

use crate::{GraphId, command::CmdId};

pub static FLAVORS: Flavors<'static> = {
    Flavors {
        flavors: &[
            (
                ident!("init"),
                Flavor {
                    envelope: InitEnvelope::SCHEMA,
                },
            ),
            (
                ident!("basic"),
                Flavor {
                    envelope: BasicEnvelope::SCHEMA,
                },
            ),
            (
                ident!("ephemeral"),
                Flavor {
                    envelope: EphemeralEnvelope::SCHEMA,
                },
            ),
            (
                ident!("finalize"),
                Flavor {
                    envelope: FinalizeEnvelope::SCHEMA,
                },
            ),
        ],
    }
};

pub enum Envelope {
    Init(InitEnvelope),
    Basic(BasicEnvelope),
    Finalize(FinalizeEnvelope),
    Ephemeral(EphemeralEnvelope),
}

impl Envelope {
    pub(super) fn command_id(&self) -> CmdId {
        match self {
            Self::Init(e) => e.command_id,
            Self::Basic(e) => e.command_id,
            Self::Finalize(e) => e.command_id,
            Self::Ephemeral(e) => e.command_id,
        }
    }

    // temporary helper method?
    pub(super) fn author_id(&self) -> DeviceId {
        match self {
            Self::Init(e) => e.author_id,
            Self::Basic(e) => e.author_id,
            // TODO(jdygert): Handle certified command properly
            Self::Finalize(_) => DeviceId::default(),
            Self::Ephemeral(e) => e.author_id,
        }
    }
}

#[derive(Clone, Debug, Valuable)]
pub struct InitEnvelope {
    pub command_id: CmdId,
    pub author_id: DeviceId,
}

#[derive(Clone, Debug, Valuable)]
pub struct BasicEnvelope {
    pub command_id: CmdId,
    pub parent_id: CmdId,
    pub author_id: DeviceId,
}

#[derive(Clone, Debug, Valuable)]
pub struct FinalizeEnvelope {
    pub command_id: CmdId,
    pub parent_id: CmdId,
    pub fact_root: BaseId,
}

#[derive(Clone, Debug, Valuable)]
pub struct EphemeralEnvelope {
    pub command_id: CmdId,
    pub graph_id: GraphId,
    pub author_id: DeviceId,
}

impl From<Envelope> for aranya_policy_vm::Struct {
    fn from(e: Envelope) -> Self {
        match e {
            Envelope::Init(e) => e.into(),
            Envelope::Basic(e) => e.into(),
            Envelope::Finalize(e) => e.into(),
            Envelope::Ephemeral(e) => e.into(),
        }
    }
}
