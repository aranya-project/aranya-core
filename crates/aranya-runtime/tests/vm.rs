#![cfg(test)]
#![allow(clippy::panic)]

use std::fs;

use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::ffi::FfiModule;
use aranya_runtime::{
    linear::{libc::FileManager, LinearStorageProvider},
    testing::vm::{self, TestEngine},
    vm_policy::testing::TestFfiEnvelope,
    Sink, VmEffect,
};
use test_log::test;
use tracing::debug;

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

#[test]
fn test_effect_metadata() {
    vm::test_effect_metadata(new_engine(), new_engine()).unwrap()
}

#[test]
fn test_duplicate_fact_insert() {
    use aranya_policy_lang::lang::{parse_policy_str, Version};
    use aranya_runtime::{testing::vm::TestEngine, vm_action, ClientState};

    // Policy that creates the same fact twice
    let policy_str = r#"
use envelope

action init() {
    publish Init {}
}
command Init {
    fields {}
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        finish {
            emit Initialized {}
        }
    }
}
effect Initialized {}

fact Duplicate[x int]=>{}
fact NeverTrue[]=>{}

command Foo {
    fields {
        x int,
    }
    seal { return envelope::do_seal(serialize(this)) }
    open { return deserialize(envelope::do_open(envelope)) }
    policy {
        let n = count_up_to 999999 Duplicate[x: ?]
        finish {
            // Never created, so should fail.
            delete NeverTrue[]=>{}

            // Should fail the second time it's called with the
            // same `x`.
            create Duplicate[x: this.x]=>{}
            create Duplicate[x: this.x]=>{}
            create Duplicate[x: this.x]=>{}

            emit CalledFoo {
                x: this.x,
                n: n,
            }
        }
    }
}

action foo(x int) {
    publish Foo { x: x }
}

effect CalledFoo {
    x int,
    n int,
}
"#;

    let ast = parse_policy_str(policy_str, Version::V2).unwrap();
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestFfiEnvelope::SCHEMA])
        .compile()
        .unwrap();
    let engine = TestEngine::from_module(module);

    let dir = std::env::temp_dir().join("test_duplicate_fact_insert");
    println!("dir = {dir:?}");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let provider = LinearStorageProvider::new(FileManager::new(dir).unwrap());

    let mut cs = ClientState::new(engine, provider);
    let mut sink = VecSink::new();

    let graph_id = cs
        .new_graph(&[0u8], vm_action!(init()), &mut sink)
        .expect("could not create graph");

    for _ in 0..3 {
        let result = cs.action(graph_id, &mut sink, vm_action!(foo(42)));
        println!("sink = {sink:?}");
        assert!(result.is_ok(), "{result:?}");
    }

    let result = cs.action(graph_id, &mut sink, vm_action!(foo(42)));
    println!("sink = {sink:?}");
    let err = result.unwrap_err();
    let err_msg = format!("{err:?}");
    assert!(
        err_msg.contains("FactExists")
            || err_msg.contains("fact already exists")
            || err_msg.contains("IO"),
        "Expected FactExists error, got: {err_msg}",
    );
}

#[derive(Debug, Default)]
struct VecSink(Vec<VmEffect>);

impl VecSink {
    fn new() -> Self {
        Self::default()
    }
}

impl Sink<VmEffect> for VecSink {
    fn begin(&mut self) {}

    fn consume(&mut self, effect: VmEffect) {
        debug!(?effect, "sink consume");
        self.0.push(effect)
    }

    fn rollback(&mut self) {}

    fn commit(&mut self) {}
}
