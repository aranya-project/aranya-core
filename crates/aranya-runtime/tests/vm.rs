#![cfg(test)]
#![allow(clippy::panic)]

use aranya_crypto::{
    DeviceId, Rng,
    default::{DefaultCipherSuite, DefaultEngine},
    id::IdExt as _,
};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{
    Machine,
    ffi::{FfiModule as _, ModuleSchema},
    ident,
};
use aranya_runtime::{
    VmPolicy, VmPolicyError,
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

#[test]
fn test_ffi_mismatch() {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    let machine = Machine::from_module(module).expect("module conversion failed");
    let (eng, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    let r = VmPolicy::new(machine, eng, Vec::new());
    assert!(matches!(r, Err(VmPolicyError::ContractMismatch)));

    let module = Compiler::new(&ast)
        .ffi_modules(&[
            TestFfiEnvelope::SCHEMA,
            ModuleSchema {
                name: ident!("fake"),
                functions: &[],
                structs: &[],
                enums: &[],
            },
        ])
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    let machine = Machine::from_module(module).expect("module conversion failed");
    let (eng, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    let r = VmPolicy::new(
        machine,
        eng,
        vec![
            Box::from(TestFfiEnvelope {
                device: DeviceId::random(Rng),
            }),
            Box::from(TestFfiEnvelope {
                device: DeviceId::random(Rng),
            }),
        ],
    );
    assert!(matches!(r, Err(VmPolicyError::ContractMismatch)));
}
