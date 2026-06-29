#![cfg(test)]
#![allow(clippy::panic)]

use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::ffi::FfiModule as _;
use aranya_runtime::{
    testing::vm::{self, TestPolicyStore},
    vm_policy::testing::TestFfiEnvelope,
};
use test_log::test;

/// Creates a `TestPolicyStore` from a policy document.
fn new_policy_store() -> TestPolicyStore {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    TestPolicyStore::from_module(module)
}

#[test]
fn test_vmpolicy() {
    vm::test_vmpolicy(new_policy_store()).unwrap();
}

#[test]
fn test_query_fact_value() {
    vm::test_query_fact_value(new_policy_store()).unwrap();
}

#[test]
fn test_aranya_session() {
    vm::test_aranya_session(new_policy_store()).unwrap();
}

#[test]
fn test_effect_metadata() {
    vm::test_effect_metadata(new_policy_store(), new_policy_store()).unwrap();
}

/// Exercises `VmEffectData`'s `PartialEq<VmEffect>` impl (the `data == effect`
/// direction). The `TestSink` only ever compares in the `effect == data`
/// direction, so this direction is otherwise unexercised in this test binary.
#[test]
fn test_vm_effect_data_eq() {
    use aranya_policy_vm::{KVPair, Value, ident};
    use aranya_runtime::{CmdId, VmEffect, VmEffectData};

    let field = KVPair::new(ident!("x"), Value::Int(1));
    let effect = VmEffect {
        name: ident!("Foo"),
        fields: vec![field.clone()],
        command: CmdId::default(),
        recalled: false,
    };
    let data_eq = VmEffectData {
        name: ident!("Foo"),
        fields: vec![field.clone()],
    };
    let data_diff_fields = VmEffectData {
        name: ident!("Foo"),
        fields: vec![KVPair::new(ident!("x"), Value::Int(2))],
    };
    let data_diff_name = VmEffectData {
        name: ident!("Bar"),
        fields: vec![field.clone()],
    };

    // `VmEffectData == VmEffect`
    assert!(data_eq == effect); // name eq && fields eq
    assert!(!(data_diff_fields == effect)); // name eq && fields ne
    assert!(!(data_diff_name == effect)); // name ne (short circuit)

    // `VmEffect == VmEffectData`. The `TestSink` only ever compares equal
    // effects, so the inequality (short-circuit) arm is otherwise unexercised
    // in this test binary.
    assert!(effect == data_eq); // name eq && fields eq
    assert!(!(effect == data_diff_fields)); // name eq && fields ne
    assert!(!(effect == data_diff_name)); // name ne (short circuit)
}

/// Building a `VmPolicy` whose policy contains an ephemeral command with a
/// priority-related attribute must fail. The standard test policies only define
/// ephemeral commands without such attributes, so this error path is otherwise
/// unexercised in this test binary.
#[test]
fn test_ephemeral_command_priority_rejected() {
    use aranya_crypto::{Rng, default::DefaultEngine};
    use aranya_policy_lang::lang::parse_policy_str;
    use aranya_policy_vm::{Machine, ast::Version};
    use aranya_runtime::VmPolicy;

    let policy = r#"
        ephemeral command Test {
            attributes {
                priority: 1
            }
            fields { }
            seal { return todo() }
            open { return todo() }
            policy { }
        }
    "#;
    let ast = parse_policy_str(policy, Version::V2).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    let machine = Machine::from_module(module).expect("can create machine");
    let (eng, _) = DefaultEngine::<Rng>::from_entropy(Rng);
    VmPolicy::new(machine, eng, vec![])
        .err()
        .expect("ephemeral command with priority must be rejected");
}
