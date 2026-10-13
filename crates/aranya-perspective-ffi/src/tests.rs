#![cfg(test)]
#![allow(clippy::unwrap_used)]

use aranya_crypto::{
    BaseId, DeviceId,
    default::{DefaultEngine, Rng},
    policy::CmdId,
};
use aranya_policy_vm::{ActionContext, CommandContext, MachineErrorType, PolicyContext, ident};

use crate::FfiPerspective;

#[test]
fn test_head_id() {
    let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let perspective = FfiPerspective {};
    let head_id = CmdId::default();

    {
        let context = CommandContext::Action(ActionContext {
            name: ident!("action"),
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Policy(PolicyContext {
            name: ident!("policy"),
            id: CmdId::default(),
            author: DeviceId::default(),
            version: BaseId::default(),
        });
        assert_eq!(
            perspective.head_id(&context, &eng).expect_err("").err_type,
            MachineErrorType::Unknown("head_id is only available in Action context".to_string())
        );
    }

    {
        let context = CommandContext::Recall(PolicyContext {
            name: ident!("recall"),
            id: CmdId::default(),
            author: DeviceId::default(),
            version: BaseId::default(),
        });
        assert_eq!(
            perspective.head_id(&context, &eng).expect_err("").err_type,
            MachineErrorType::Unknown("head_id is only available in Action context".to_string())
        );
    }
}
