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
    ContractValidationError, Machine, ModuleContract, TypeContract, ffi::FfiModule as _, ident,
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

fn contract_tester<F: FnOnce(&mut ModuleContract)>(contract_mutator: F, expect_error: &str) {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    let mut machine = Machine::from_module(module).expect("module conversion failed");
    contract_mutator(machine.contract.as_mut().unwrap());
    let (eng, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    let r = VmPolicy::new(
        machine,
        eng,
        vec![Box::from(TestFfiEnvelope {
            device: DeviceId::random(Rng),
        })],
    );
    let Err(VmPolicyError::ContractValidation(ContractValidationError(got_error))) = r else {
        panic!("Did not get Contract Validation error")
    };
    assert_eq!(got_error, expect_error);
}

#[test]
fn test_ffi_missing() {
    contract_tester(
        |c| c.ffis.clear(),
        "Module has 0 FFI modules but VM implementation expects 1",
    );
}

#[test]
fn test_ffi_mismatch() {
    contract_tester(
        |c| c.ffis[0].name = ident!("fake"),
        "FFI module `fake` != `envelope`",
    );
}

#[test]
fn test_ffi_function_missing() {
    contract_tester(
        |c| c.ffis[0].functions.clear(),
        "FFI module `envelope` has 0 functions but module specifies 2",
    );
}

#[test]
fn test_ffi_function_args_wrong_name() {
    contract_tester(
        |c| c.ffis[0].functions[0].args[0].name = ident!("blah"),
        "FFI module `envelope`, function `do_seal` arg `blah`, `blah` != `payload`",
    );
}

#[test]
fn test_ffi_function_args_wrong_type() {
    contract_tester(
        |c| c.ffis[0].functions[0].args[0].vtype = TypeContract::Bool,
        "FFI module `envelope`, function `do_seal` arg `payload`, type Bool != Bytes",
    );
}

#[test]
fn test_ffi_function_return_wrong_type() {
    contract_tester(
        |c| c.ffis[0].functions[0].return_type = TypeContract::Bool,
        "FFI module `envelope`, function `do_seal` return type, Bool != Struct(\"Envelope\")",
    );
}

#[test]
fn test_ffi_struct_wrong_count() {
    contract_tester(
        |c| c.ffis[0].structs.clear(),
        "FFI module `envelope` has 0 structs but module specifies 1",
    );
}

#[test]
fn test_ffi_struct_wrong_name() {
    contract_tester(
        |c| c.ffis[0].structs[0].name = ident!("Fail"),
        "FFI module `envelope`, struct `Fail` != `Envelope`",
    );
}

#[test]
fn test_ffi_struct_wrong_field_count() {
    contract_tester(
        |c| c.ffis[0].structs[0].fields.clear(),
        "FFI module `envelope`, struct `Envelope` has a 0 fields but VM expects 5",
    );
}

#[test]
fn test_ffi_struct_wrong_field_name() {
    contract_tester(
        |c| c.ffis[0].structs[0].fields[0].name = ident!("fail"),
        "FFI module `envelope`, struct `Envelope` field `fail`, `fail` != `parent_id`",
    );
}

#[test]
fn test_ffi_struct_wrong_field_type() {
    contract_tester(
        |c| c.ffis[0].structs[0].fields[0].vtype = TypeContract::Bool,
        "FFI module `envelope`, struct `Envelope` field `parent_id`, type Bool != Id",
    );
}

#[test]
fn test_ffi_enum_wrong_count() {
    contract_tester(
        |c| c.ffis[0].enums.clear(),
        "FFI module `envelope` has 0 enums but module specifies 1",
    );
}

#[test]
fn test_ffi_enum_wrong_name() {
    contract_tester(
        |c| c.ffis[0].enums[0].name = ident!("Fail"),
        "FFI module `envelope`, enum `Fail` != `TestEnum`",
    );
}

#[test]
fn test_ffi_enum_wrong_variant_count() {
    contract_tester(
        |c| c.ffis[0].enums[0].variants.clear(),
        "FFI module `envelope`, enum `TestEnum` has 0 variants but VM expects 3",
    );
}

#[test]
fn test_ffi_enum_wrong_variant_name() {
    contract_tester(
        |c| c.ffis[0].enums[0].variants[0] = ident!("Blonk"),
        "FFI module `envelope`, enum `TestEnum` variant `Blonk` is not `True`",
    );
}
