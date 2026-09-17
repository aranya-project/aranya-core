#![cfg(test)]
#![allow(clippy::panic)]

use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_runtime::testing::vm::{self, TestPolicyStore};
use test_log::test;

/// Creates a `TestPolicyStore` from a policy document.
fn new_policy_store() -> TestPolicyStore {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap();
    let module = Compiler::new(&ast).compile().unwrap();
    TestPolicyStore::from_module(module)
}

#[test]
fn test_vmpolicy() {
    vm::test_vmpolicy(new_policy_store()).unwrap();
}

#[test]
fn test_action_result() {
    vm::test_action_result(new_policy_store()).unwrap();
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
    let store1 = new_policy_store();
    let store2 = new_policy_store().with_seal_ctx(store1.seal_ctx());
    vm::test_effect_metadata(store1, store2).unwrap();
}
