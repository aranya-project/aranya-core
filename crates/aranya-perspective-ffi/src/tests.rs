#![cfg(test)]
#![allow(clippy::unwrap_used)]

use aranya_crypto::{
    BaseId, DeviceId,
    default::{DefaultEngine, Rng},
    policy::CmdId,
};
use aranya_policy_vm::{
    ActionContext, CommandContext, MachineErrorType, OpenContext, PolicyContext, SealContext, ident,
};

use crate::FfiPerspective;

#[test]
fn test_head_id() {
    let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let perspective = FfiPerspective {};
    let head_id = CmdId::default();

    {
        let mut context = CommandContext::Action(ActionContext {
            name: ident!("action"),
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &eng).unwrap(), head_id);

        let new_head_id = [1; 32].into();
        context = context
            .with_new_head(new_head_id)
            .expect("should work for `Action` variants.");
        assert_eq!(
            perspective.head_id(&context, &eng).unwrap(),
            new_head_id,
            "updated head"
        );
    }

    {
        let context = CommandContext::Seal(SealContext {
            name: ident!("seal"),
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Open(OpenContext {
            name: ident!("open"),
        });
        assert_eq!(
            perspective.head_id(&context, &eng).unwrap_err().err_type,
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
        );
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
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
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
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
        );
    }
}
