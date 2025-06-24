#![cfg(test)]

use aranya_crypto::{
    default::{DefaultEngine, Rng},
    id::IdExt as _,
    DeviceId, Id,
};
use aranya_policy_vm::{
    ident, ActionContext, CommandContext, OpenContext, PolicyContext, SealContext,
};

use crate::FfiDevice;

#[test]
fn test_current_device_id() {
    let (mut eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let device_id = DeviceId::random(&mut Rng);
    let device = FfiDevice { id: device_id };

    let contexts = vec![
        CommandContext::Action(ActionContext {
            name: ident!("action"),
            head_id: Id::default(),
        }),
        CommandContext::Seal(SealContext {
            name: ident!("seal"),
            head_id: Id::default(),
        }),
        CommandContext::Open(OpenContext {
            name: ident!("open"),
        }),
        CommandContext::Policy(PolicyContext {
            name: ident!("policy"),
            id: Id::default(),
            author: DeviceId::default(),
            version: Id::default(),
        }),
        CommandContext::Recall(PolicyContext {
            name: ident!("recall"),
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
