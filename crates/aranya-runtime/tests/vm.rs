#![cfg(test)]
#![allow(clippy::panic)]

use std::sync::Arc;

use aranya_crypto::{
    DeviceId, Rng, SigningKey,
    default::{DefaultCipherSuite, DefaultEngine},
};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{FfiContract, Machine, TypeContract, ffi::FfiModule as _, ident};
use aranya_runtime::{
    testing::vm::{self, TestPolicyStore},
    vm_policy::{FLAVORS, FfiSet, SealCtx, VmPolicy, VmPolicyError, VmPolicyStore},
};
use test_log::test;

/// Create a `TestPolicyStore`.
fn new_policy_store() -> TestPolicyStore {
    let [store] = new_policy_stores::<1>();
    store
}

/// Create multiple `TestPolicyStore`s with the same seal context.
fn new_policy_stores<const N: usize>() -> [TestPolicyStore; N] {
    let seal_ctx = generate_seal_context();
    core::array::from_fn(|_| {
        let (eng, _) = DefaultEngine::from_entropy(Rng);
        VmPolicyStore::new(Arc::new(eng), FfiSet::new(), seal_ctx.clone())
    })
}

/// Compile and serialize the policy.
fn compile_policy() -> Vec<u8> {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap();
    let module = Compiler::new(&ast).flavors(&FLAVORS).compile().unwrap();
    module.write_to_vec().expect("can serialize test module")
}

/// Generate a random seal context.
fn generate_seal_context() -> SealCtx<Arc<DefaultEngine>> {
    use aranya_crypto::id::IdExt as _;
    SealCtx {
        author: DeviceId::random(Rng),
        key: SigningKey::new(Rng),
    }
}

#[test]
fn test_vmpolicy() {
    vm::test_vmpolicy(new_policy_store(), &compile_policy()).unwrap();
}

#[test]
fn test_action_result() {
    vm::test_action_result(new_policy_store(), &compile_policy()).unwrap();
}

#[test]
fn test_query_fact_value() {
    vm::test_query_fact_value(new_policy_store(), &compile_policy()).unwrap();
}

#[test]
fn test_aranya_session() {
    vm::test_aranya_session(new_policy_store(), &compile_policy()).unwrap();
}

#[test]
fn test_effect_metadata() {
    let [store1, store2] = new_policy_stores();
    vm::test_effect_metadata(store1, store2, &compile_policy()).unwrap();
}

fn contract_tester<F: FnOnce(&mut Vec<FfiContract>)>(contract_mutator: F, expect_error: &str) {
    let ast = parse_policy_document(vm::TEST_POLICY_1).unwrap_or_else(|e| panic!("{e}"));
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .flavors(&FLAVORS)
        .compile()
        .unwrap_or_else(|e| panic!("{e}"));
    let mut machine = Machine::from_module(module).expect("module conversion failed");
    contract_mutator(machine.ffis.as_mut().unwrap());
    let (eng, _) = DefaultEngine::<Rng, DefaultCipherSuite>::from_entropy(Rng);
    let r = VmPolicy::new(machine, eng, vec![Arc::new(TestFfiEnvelope)]);
    let Err(VmPolicyError::ContractValidation(got_error)) = r else {
        panic!("Did not get Contract Validation error")
    };
    assert_eq!(
        got_error.to_string(),
        format!("Contract Validation Error: {expect_error}")
    );
}

#[test]
fn test_ffi_missing() {
    contract_tester(Vec::clear, "Module has 0 FFI modules but VM expects 1");
}

#[test]
fn test_ffi_mismatch() {
    contract_tester(
        |c| c[0].name = ident!("fake"),
        "FFI module `fake`, VM expected `envelope`",
    );
}

#[test]
fn test_ffi_function_missing() {
    contract_tester(
        |c| c[0].functions.clear(),
        "FFI module `envelope` has 0 functions but VM expects 2",
    );
}

#[test]
fn test_ffi_function_args_wrong_name() {
    contract_tester(
        |c| c[0].functions[0].args[0].name = ident!("blah"),
        "FFI module `envelope`, function `do_seal` arg `blah`, VM expected `payload`",
    );
}

#[test]
fn test_ffi_function_args_wrong_type() {
    contract_tester(
        |c| c[0].functions[0].args[0].vtype = TypeContract::Bool,
        "FFI module `envelope`, function `do_seal` arg `payload`, type Bool but VM expected Bytes",
    );
}

#[test]
fn test_ffi_function_return_wrong_type() {
    contract_tester(
        |c| c[0].functions[0].return_type = TypeContract::Bool,
        "FFI module `envelope`, function `do_seal` return type Bool but VM expected Struct(\"Envelope\")",
    );
}

#[test]
fn test_ffi_struct_wrong_count() {
    contract_tester(
        |c| c[0].structs.clear(),
        "FFI module `envelope` has 0 structs but VM expects 1",
    );
}

#[test]
fn test_ffi_struct_wrong_name() {
    contract_tester(
        |c| c[0].structs[0].name = ident!("Fail"),
        "FFI module `envelope`, `struct Fail`, VM expected `struct Envelope`",
    );
}

#[test]
fn test_ffi_struct_wrong_field_count() {
    contract_tester(
        |c| c[0].structs[0].fields.clear(),
        "FFI module `envelope`, `struct Envelope` has 0 fields but VM expects 4",
    );
}

#[test]
fn test_ffi_struct_wrong_field_name() {
    contract_tester(
        |c| c[0].structs[0].fields[0].name = ident!("fail"),
        "FFI module `envelope`, `struct Envelope` field `fail`, VM expected `parent_id`",
    );
}

#[test]
fn test_ffi_struct_wrong_field_type() {
    contract_tester(
        |c| c[0].structs[0].fields[0].vtype = TypeContract::Bool,
        "FFI module `envelope`, `struct Envelope` field `parent_id`, type Bool but VM expected Id",
    );
}

#[test]
fn test_ffi_enum_wrong_count() {
    contract_tester(
        |c| c[0].enums.clear(),
        "FFI module `envelope` has 0 enums but VM expects 1",
    );
}

#[test]
fn test_ffi_enum_wrong_name() {
    contract_tester(
        |c| c[0].enums[0].name = ident!("Fail"),
        "FFI module `envelope`, `enum Fail`, VM expected `enum TestEnum`",
    );
}

#[test]
fn test_ffi_enum_wrong_variant_count() {
    contract_tester(
        |c| c[0].enums[0].variants.clear(),
        "FFI module `envelope`, `enum TestEnum` has 0 variants but VM expects 3",
    );
}

#[test]
fn test_ffi_enum_wrong_variant_name() {
    contract_tester(
        |c| c[0].enums[0].variants[0] = ident!("Blonk"),
        "FFI module `envelope`, `enum TestEnum` has variant `Blonk` but VM expected `True`",
    );
}

mod ffi {
    use core::convert::Infallible;

    use aranya_policy_vm::{CommandContext, MachineError, ffi::ffi};

    pub struct TestFfiEnvelope;

    #[ffi(
        module = "envelope",
        def = r#"
struct Envelope {
    // The parent command ID.
    parent_id: id,
    // The author's device ID.
    author_id: id,
    // Uniquely identifies the command.
    command_id: id,
    // The signature over the command and its contextual
    // bindings.
    signature: bytes,
}

// This exists only for FFI contract testing purposes
enum TestEnum {
    True,
    False,
    FileNotFound,
}
"#
    )]
    impl TestFfiEnvelope {
        #[ffi_export(def = "function do_seal(payload: bytes) struct Envelope")]
        fn seal<CE>(
            &self,
            _ctx: &CommandContext,
            _eng: &CE,
            _payload: Vec<u8>,
        ) -> Result<Envelope, MachineError> {
            unimplemented!()
        }

        #[ffi_export(
            def = "function do_open(payload: bytes, envelope_input: struct Envelope) unit"
        )]
        fn open<CE>(
            &self,
            _ctx: &CommandContext,
            _eng: &CE,
            _payload: Vec<u8>,
            _envelope_input: Envelope,
        ) -> Result<(), Infallible> {
            unimplemented!()
        }
    }
}
use ffi::TestFfiEnvelope;
