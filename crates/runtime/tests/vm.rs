#![cfg(test)]
#![allow(clippy::panic)]

use policy_compiler::Compiler;
use policy_lang::lang::parse_policy_document;
use policy_vm::ffi::FfiModule;
use runtime::{
    testing::vm::{self, TestEngine},
    vm_policy::testing::TestFfiEnvelope,
};
use test_log::test;

/// Creates a `TestEngine` from a policy document.
fn new_engine() -> TestEngine {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    TestEngine::from_module(module)
}

#[test]
fn test_vmpolicy() {
    vm::test_vmpolicy(new_engine()).unwrap()
}

#[test]
fn test_query_fact_value() {
    vm::test_query_fact_value(new_engine()).unwrap()
}

#[test]
fn test_aranya_session() {
    vm::test_aranya_session(new_engine()).unwrap()
}