#![cfg(test)]

use aranya_crypto::{
    BaseId, DeviceId,
    default::{DefaultEngine, Rng},
    id::IdExt as _,
    policy::CmdId,
};
use aranya_policy_vm::{
    ActionContext, CommandContext, OpenContext, PolicyContext, SealContext, ident,
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
            head_id: CmdId::default(),
        }),
        CommandContext::Seal(SealContext {
            name: ident!("seal"),
            head_id: CmdId::default(),
        }),
        CommandContext::Open(OpenContext {
            name: ident!("open"),
            parent_id: CmdId::default(),
        }),
        CommandContext::Policy(PolicyContext {
            name: ident!("policy"),
            id: CmdId::default(),
            author: DeviceId::default(),
            parent_id: CmdId::default(),
            version: BaseId::default(),
        }),
        CommandContext::Recall(PolicyContext {
            name: ident!("recall"),
            id: CmdId::default(),
            author: DeviceId::default(),
            parent_id: CmdId::default(),
            version: BaseId::default(),
        }),
    ];

    for context in contexts {
        let id = device
            .current_device_id(&context, &mut eng)
            .expect("Should have succeeded");
        assert_eq!(id, device_id);
    }
}
