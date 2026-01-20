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
