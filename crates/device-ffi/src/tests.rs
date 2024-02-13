#![cfg(test)]

use crypto::{
    default::{DefaultEngine, Rng},
    Id, UserId,
};
use policy_vm::{ActionContext, CommandContext, OpenContext, PolicyContext, SealContext};

use crate::FfiDevice;

#[test]
fn test_current_user_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let user_id = UserId::random(&mut Rng);
    let device = FfiDevice { id: user_id };

    let contexts = vec![
        CommandContext::Action(ActionContext {
            name: "action",
            head_id: Id::default(),
        }),
        CommandContext::Seal(SealContext {
            name: "seal",
            parent_id: Id::default(),
        }),
        CommandContext::Open(OpenContext {
            name: "open",
            parent_id: Id::default(),
        }),
        CommandContext::Policy(PolicyContext {
            name: "policy",
            parent_id: Id::default(),
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        }),
        CommandContext::Recall(PolicyContext {
            name: "recall",
            parent_id: Id::default(),
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        }),
    ];

    for context in contexts {
        let id = device
            .current_user_id(&context, &mut eng)
            .expect("Should have succeeded");
        assert_eq!(id, user_id);
    }
}
