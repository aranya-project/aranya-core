#![cfg(test)]
#![allow(clippy::unwrap_used)]

use aranya_crypto::{
    default::{DefaultEngine, Rng},
    Id, UserId,
};
use aranya_policy_vm::{
    ActionContext, CommandContext, MachineErrorType, OpenContext, PolicyContext, SealContext,
};

use crate::FfiPerspective;

#[test]
fn test_head_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let perspective = FfiPerspective {};
    let head_id = Id::default();

    {
        let context = CommandContext::Action(ActionContext {
            name: "action",
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &mut eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Seal(SealContext {
            name: "seal",
            head_id,
        });
        assert_eq!(perspective.head_id(&context, &mut eng).unwrap(), head_id);
    }

    {
        let context = CommandContext::Open(OpenContext { name: "open" });
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
            name: "policy",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
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
            name: "recall",
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
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
