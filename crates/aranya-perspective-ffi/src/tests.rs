#![cfg(test)]
#![allow(clippy::unwrap_used)]

use aranya_crypto::{
    default::{DefaultEngine, Rng},
    BaseId, DeviceId,
};
use aranya_policy_vm::{
    ident, ActionContext, CommandContext, MachineErrorType, OpenContext, PolicyContext, SealContext,
};

use crate::FfiPerspective;

#[test]
fn test_head_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let perspective = FfiPerspective {};
    let head_id = BaseId::default();

    {
        let context = CommandContext::Action(ActionContext {
            name: ident!("action"),
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &mut eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Seal(SealContext {
            name: ident!("seal"),
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &mut eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Open(OpenContext {
            name: ident!("open"),
        });
        assert_eq!(
            perspective
                .head_id(&context, &mut eng)
                .unwrap_err()
                .err_type,
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
        );
    }

    {
        let context = CommandContext::Policy(PolicyContext {
            name: ident!("policy"),
            id: BaseId::default(),
            author: DeviceId::default(),
            version: BaseId::default(),
        });
        assert_eq!(
            perspective
                .head_id(&context, &mut eng)
                .expect_err("")
                .err_type,
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
        );
    }

    {
        let context = CommandContext::Recall(PolicyContext {
            name: ident!("recall"),
            id: BaseId::default(),
            author: DeviceId::default(),
            version: BaseId::default(),
        });
        assert_eq!(
            perspective
                .head_id(&context, &mut eng)
                .expect_err("")
                .err_type,
            MachineErrorType::Unknown(
                "head_id is only available in Seal and Action contexts".to_string()
            )
        );
    }
}
