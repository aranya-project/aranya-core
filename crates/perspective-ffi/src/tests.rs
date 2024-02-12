#![cfg(test)]

use crypto::{
    default::{DefaultEngine, Rng},
    Id, UserId,
};
use policy_vm::{ActionContext, CommandContext, OpenContext, PolicyContext, SealContext};

use crate::FfiPerspective;

#[test]
fn test_head_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let mut perspective = FfiPerspective {};
    let head_id = Id::default();

    // NOTE head_id used to return a MachineError, but now it's Infallible... Not sure there's much benefit to this test anymore.

    let contexts = vec![
        CommandContext::Action(ActionContext {
            name: "action",
            head_id,
        }),
        CommandContext::Seal(SealContext {
            name: "seal",
            parent_id: head_id,
        }),
        CommandContext::Open(OpenContext {
            name: "open",
            parent_id: head_id,
        }),
        CommandContext::Policy(PolicyContext {
            name: "policy",
            parent_id: head_id,
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        }),
        CommandContext::Recall(PolicyContext {
            name: "recall",
            parent_id: head_id,
            id: Id::default(),
            author: UserId::default(),
            version: Id::default(),
        }),
    ];

    for context in contexts {
        let id = perspective
            .head_id(&context, &mut eng)
            .expect("Should have succeeded");
        assert_eq!(id, head_id);
    }
}
