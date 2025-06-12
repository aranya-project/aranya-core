#![cfg(test)]

use aranya_crypto::{
    default::{DefaultEngine, Rng},
    DeviceId, Id,
};
use aranya_policy_vm::{ActionContext, CommandContext, OpenContext, PolicyContext, SealContext};

use crate::FfiDevice;

#[test]
fn test_current_device_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let device_id = Id::random(&mut Rng).into_id();
    let device = FfiDevice { id: device_id };

    let contexts = vec![
        CommandContext::Action(ActionContext {
            name: "action",
            head_id: Id::default(),
        }),
        CommandContext::Seal(SealContext {
            name: "seal",
            head_id: Id::default(),
        }),
        CommandContext::Open(OpenContext { name: "open" }),
        CommandContext::Policy(PolicyContext {
            name: "policy",
            id: Id::default(),
            author: DeviceId::default(),
            version: Id::default(),
        }),
        CommandContext::Recall(PolicyContext {
            name: "recall",
            id: Id::default(),
            author: DeviceId::default(),
            version: Id::default(),
        }),
    ];

    for context in contexts {
        let id = device
            .current_device_id(&context, &mut eng)
            .expect("Should have succeeded");
        assert_eq!(id, device_id);
    }
}
