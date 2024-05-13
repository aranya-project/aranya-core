#![cfg(test)]
#![allow(clippy::unwrap_used)]

mod bits;

use std::collections::BTreeMap;

use bits::{policies::*, testio::*};
use ciborium as cbor;
use crypto::Id;
use policy_ast::{self as ast, Version};
use policy_compiler::{CompileError, CompileErrorType, Compiler};
use policy_lang::lang::parse_policy_str;
use policy_vm::{
    ActionContext, CommandContext, ExitReason, FactValue, KVPair, Machine, MachineError,
    MachineErrorType, Module, OpenContext, PolicyContext, SealContext, Struct, Value,
};

fn dummy_ctx_action(name: &str) -> CommandContext<'_> {
    CommandContext::Action(ActionContext {
        name,
        head_id: Id::default(),
    })
}

fn dummy_ctx_seal(name: &str) -> CommandContext<'_> {
    CommandContext::Seal(SealContext {
        name,
        head_id: Id::default(),
    })
}

fn dummy_ctx_open(name: &str) -> CommandContext<'_> {
    CommandContext::Open(OpenContext { name })
}

fn dummy_ctx_policy(name: &str) -> CommandContext<'_> {
    CommandContext::Policy(PolicyContext {
        name,
        id: Id::default(),
        author: Id::default().into(),
        version: Id::default(),
    })
}

fn dummy_envelope() -> Struct {
    Struct {
        name: "Envelope".into(),
        fields: BTreeMap::new(),
    }
}

// Data types

#[test]
fn test_bytes() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {
                id id,
                x bytes,
            }
            seal { return None }
            open { return None }
        }

        action foo(id id, x bytes) {
            publish Foo{id: id, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);

        rs.call_action(name, [vec![0xa, 0xb, 0xc], vec![0, 255, 42]])?;
    }

    assert_eq!(
        io.publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("id", Value::Bytes(vec![0xa, 0xb, 0xc])),
                KVPair::new("x", Value::Bytes(vec![0, 255, 42]))
            ]
        )
    );
    assert_eq!(
        format!("{}", io.publish_stack[0].1[0]),
        "id: b:0A0B0C".to_string()
    );

    Ok(())
}

#[test]
fn test_structs() -> anyhow::Result<()> {
    let text = r#"
        struct Bar {
            x int
        }

        command Foo {
            fields {
                id id,
                bar struct Bar,
            }
            seal { return None }
            open { return None }
        }

        action foo(id id, x int) {
            publish Foo{
                id: id,
                bar: Bar {
                    x: x
                },
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    assert_eq!(
        machine.struct_defs.get("Bar"),
        Some(&vec![ast::FieldDefinition {
            identifier: String::from("x"),
            field_type: ast::VType::Int
        }])
    );

    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        rs.call_action(name, [Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])?;
    }

    assert_eq!(
        io.publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new(
                    "bar",
                    Value::Struct(Struct::new("Bar", [KVPair::new("x", Value::Int(3))]))
                ),
                KVPair::new("id", Value::Bytes(vec![0xa, 0xb, 0xc])),
            ]
        )
    );

    Ok(())
}

#[test]
fn test_invalid_struct_field() -> anyhow::Result<()> {
    let text = r#"
        struct Bar {
            x int
        }

        action foo(id id, x int) {
            let v = Bar {
                y: x
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let err = {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        rs.call_action("foo", [Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])
            .unwrap_err()
    };

    assert_eq!(
        err.err_type,
        MachineErrorType::InvalidStructMember(String::from("y")),
    );

    Ok(())
}

// Basic entry points - action, policy, seal, open (TODO: recall)

#[test]
fn test_action() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V1)?;

    let name = "foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    machine.call_action(name, [Value::from(3), Value::from("foo")], &mut io, &ctx)?;

    println!("publish stack: {:?}", io.publish_stack);

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V1)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_policy(name);
    let mut io = TestIO::new();

    let self_data = Struct {
        name: String::from("Bar"),
        fields: vec![
            (String::from("a"), Value::Int(3)),
            (String::from("b"), Value::Int(4)),
        ]
        .into_iter()
        .collect(),
    };
    machine
        .call_command_policy(name, &self_data, dummy_envelope(), &mut io, &ctx)
        .expect("Could not call command policy");

    println!("effects: {:?}", io.effect_stack);

    Ok(())
}

#[test]
fn test_seal() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V1)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_seal(name);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let this_data = Struct {
        name: String::from("Bar"),
        fields: vec![
            (String::from("a"), Value::Int(3)),
            (String::from("b"), Value::Int(4)),
        ]
        .into_iter()
        .collect(),
    };
    rs.call_seal(name, &this_data)
        .expect("Could not call command policy");

    let stack_vec = rs.stack.into_vec();
    assert_eq!(stack_vec[0], Value::None);

    Ok(())
}

#[test]
fn test_open() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V1)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_open(name);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io, &ctx);

    rs.call_open(name, dummy_envelope())
        .expect("Could not call command policy");

    let stack_vec = rs.stack.into_vec();
    assert_eq!(stack_vec[0], Value::None);

    Ok(())
}

// Fact manipulation

#[test]
fn test_fact_create_delete() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V1)?;

    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let mut io = TestIO::new();

    // We have to scope the RunState so that it and its mutable
    // reference to IO is dropped before we inspect the IO struct.
    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [(KVPair::new_int("a", 3))]);
        machine.call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)?;
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(3))];
    assert_eq!(io.facts[&fk], fv);

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Set", &[]);
        machine.call_command_policy("Clear", &self_struct, dummy_envelope(), &mut io, &ctx)?;
    }

    assert_eq!(io.facts.get(&fk), None);

    Ok(())
}

#[test]
fn test_fact_query() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V1)?;

    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let mut io = TestIO::new();

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [KVPair::new_int("a", 3)]);
        machine.call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)?;

        let name = "Increment";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, &[]);
        machine.call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)?;
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(4))];
    assert_eq!(io.facts[&fk], fv);

    Ok(())
}

#[test]
fn test_fact_exists() -> anyhow::Result<()> {
    let text = r#"
    fact Foo[] => {x int}
    fact Bar[i int] => {s string, b bool}

    command setup {
        fields {}
        seal { return None }
        open { return None }
        policy {
            finish {
                create Foo[] => {x: 3}
                create Bar[i: 1] => {s: "abc", b: true}
            }
        }
    }

    action testExists() {
        check exists Foo[] => {x: 3}
        check exists Foo[]
        check exists Bar[i: 1] => {s: "abc", b: true}

        check exists Foo[] => {x: ?}
        check exists Bar[i: ?] => {s: ?, b: true}

        // Not-exists

        // incomplete values
        check !exists Bar[i: 0]=>{s: ?}

        // no fact with such values
        check !exists Bar[i:0] => {s:"ab", b:true}
        check !exists Bar[i:1] => {s:"", b:true}
        check !exists Bar[i: ?]=>{s: "ab", b: ?}
    }
    "#;

    let policy = parse_policy_str(text.trim(), Version::V1)?;

    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = "setup";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let self_struct = Struct::new(name, &[]);
        let result = rs.call_command_policy(name, &self_struct, dummy_envelope())?;
        assert_eq!(result, ExitReason::Normal);
    }

    {
        let name = "testExists";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let result = rs.call_action(name, [false])?;
        assert_eq!(result, ExitReason::Normal);
    }

    Ok(())
}

#[test]
fn test_fact_function_return() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[a int]=>{b int}

        effect Result {
            x struct Foo
        }

        // This tests the implicitly defined struct as a return type
        function get_foo(a int) struct Foo {
            let foo = unwrap query Foo[a: a]=>{b: ?}

            return foo
        }

        // Foo creates and emmits the fact
        command Bar {
            fields {
                a int,
                x int,
            }

            seal { return None }
            open { return None }

            policy {
                finish {
                    create Foo[a: this.a]=>{b: this.x}
                    emit Result { x: get_foo(this.a) }
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    // Create fact through Foo
    {
        let name = "Bar";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let self_struct = Struct::new(
            "Foo",
            [
                KVPair::new("a", Value::Int(1)),
                KVPair::new("x", Value::Int(2)),
            ],
        );
        rs.call_command_policy(name, &self_struct, dummy_envelope())?;
    }

    assert_eq!(
        io.effect_stack[0],
        (
            String::from("Result"),
            vec![KVPair::new(
                "x",
                Value::Struct(Struct {
                    name: String::from("Foo"),
                    fields: {
                        let mut test_struct_map = BTreeMap::new();
                        test_struct_map.insert(String::from("a"), Value::Int(1));
                        test_struct_map.insert(String::from("b"), Value::Int(2));
                        test_struct_map
                    }
                })
            ),]
        )
    );

    Ok(())
}

#[test]
fn test_query_partial_key() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int, j int]=>{x int, s string}

        command Setup {
            fields {}
            seal { return None }
            open { return None }
            policy {
                finish {
                    create Foo[i: 1, j: 1]=>{x: 1, s: "a"}
                    create Foo[i: 2, j: 1]=>{x: 3, s: "b" }
                }
            }
        }

        action test_query() {
            let f = unwrap query Foo[i: 1, j: ?]
            check f.x == 1
            let f2 = unwrap query Foo[i: ?, j: ?]
            check f2.x == 1
            let f3 = unwrap query Foo[i:2, j:?]
            check f3.x == 3

            // bind value
            let f4 = unwrap query Foo[i: 2, j: 1]=>{x: 3, s: ?}
            check f4.x == 3
            // bind key and value
            let f5 = unwrap query Foo[i: ?, j: ?]=>{x: 3, s: ?}
            check f5.x == 3
        }

        action test_nonexistent() {
            let f = unwrap query Foo[i:?, j:?]=>{}
        }

        action test_exists() {
            check exists Foo[i:1, j:?]
            check exists Foo[i:-1, j:?] == false
            check exists Foo[i:1, j:?] => {x:?}
            check !exists Foo[i:1, j:?] => {x:-1}
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;

    {
        let cmd_name = "Setup";
        let this_data = Struct {
            name: String::from(cmd_name),
            fields: [].into(),
        };

        let ctx = dummy_ctx_open(cmd_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_command_policy(cmd_name, &this_data, dummy_envelope())?;
        assert_eq!(status, ExitReason::Normal);
    }

    {
        let action_name = "test_query";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_action(action_name, [Value::None])?;
        assert_eq!(status, ExitReason::Normal);
    }

    {
        let action_name = "test_exists";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_action(action_name, [Value::None])?;
        assert_eq!(status, ExitReason::Normal);
    }

    Ok(())
}

// Language features

#[test]
fn test_not_operator() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        action test() {
            check !false
        }
    "#,
        Version::V1,
    )?;

    let name = "test";
    let ctx = dummy_ctx_policy(name);
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.run()?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

#[test]
fn test_when_true() -> anyhow::Result<()> {
    let text = r#"
        action foo(x bool) {
            when x == true {
                check true == false
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [true])?;
    assert_eq!(result, ExitReason::Check);

    Ok(())
}

#[test]
fn test_when_false() -> anyhow::Result<()> {
    let text = r#"
        action foo(x bool) {
            when x == true {
                check true == false
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [false])?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

#[test]
fn test_match_first() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [5])?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(5)),])
    );

    Ok(())
}

#[test]
fn test_match_second() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [6])?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(6)),])
    );

    Ok(())
}

#[test]
fn test_match_none() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action("foo", [Value::Int(0)])?;
    assert_eq!(result, ExitReason::Panic);

    Ok(())
}

#[test]
fn test_match_alternation() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
        }

        action foo(x int) {
            match x {
                0 | 1 => {
                    check false
                }
                5 | 6 | 7 => {
                    publish Result { x: x }
                }
            }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let action_name = "foo";
    let ctx = dummy_ctx_action(action_name);
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let res = rs.call_action(action_name, [Value::Int(6)])?;

    assert_eq!(res, ExitReason::Normal);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(6)),])
    );
    Ok(())
}

#[test]
fn test_match_default() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
        }

        action foo(x int) {
            match x {
                5 => {
                    publish Result { x: x }
                }
                _ => {
                    publish Result { x: 0 }
                }
            }
        }
    "#;
    let name = "foo";
    let policy = parse_policy_str(policy_str, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [Value::Int(6)])?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(0)),])
    );

    Ok(())
}

#[test]
fn test_match_return() -> anyhow::Result<()> {
    // See https://git.spideroak-inc.com/spideroak-inc/flow3-rs/issues/800

    let text = r#"
        action foo(val int) {
            check val == bar()
        }

        function bar() int {
            match 0 {
                0 => { return 42 }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_action("foo");
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action("foo", [42]);

    assert_eq!(result.unwrap(), ExitReason::Normal);

    Ok(())
}

#[test]
fn test_is_some_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    // Test with a value that is not None
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [Value::Int(10)])?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(10))])
    );

    Ok(())
}

#[test]
fn test_is_none_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V1)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    // Test with a None value
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [Value::None])?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::None)])
    );

    Ok(())
}

#[test]
fn test_negative_numeric_expression() -> anyhow::Result<()> {
    let text = r#"
    action foo(x int) {
        let a = -2
        let c = if x - a == 1 then true else false
        check c
    }
    "#;
    let name = "foo";
    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [-1])?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

#[test]
fn test_negative_logical_expression() -> anyhow::Result<()> {
    let text = r#"
    action foo(x bool, y bool) {
        when x {
            check x
        }
        when !y {
            check !y
        }
    }
    "#;
    let name = "foo";
    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [true, false])?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

#[test]
fn test_negative_overflow_numeric_expression() -> anyhow::Result<()> {
    let text = r#"
    action check_overflow(x int) {
        let a = -x
    }
    "#;
    let name = "check_overflow";
    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [i64::MIN]);

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_pure_function() -> anyhow::Result<()> {
    let text = r#"
        command Result {
            fields {
                x int
            }
            seal { return None }
            open { return None }
        }

        function f(x int) int {
            return x + 1
        }

        action foo(x int) {
            publish Result { x: f(x) }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;

    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        machine.call_action(name, [3], &mut io, &ctx)?;
    }

    assert_eq!(
        io.publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(4)),])
    );

    Ok(())
}

#[test]
fn test_finish_function() -> anyhow::Result<()> {
    let text = r#"
        effect Result {
            x int
        }

        finish function f(x int) {
            emit Result { x: x + 1 }
        }

        command Foo {
            fields {
                x int,
            }

            seal { return None }
            open { return None }

            policy {
                finish {
                    f(this.x)
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Foo", [KVPair::new("x", Value::Int(3))]);
        machine.call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)?;
    }

    assert_eq!(
        io.effect_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(4)),])
    );

    Ok(())
}

#[test]
fn test_serialize_deserialize() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {
                a int,
                b string,
            }

            seal {
                return serialize(this)
            }
            open {
                // Don't access payload this way. See below.
                return deserialize(envelope.payload)
            }

            policy {
                finish {}
            }
        }
    "#;

    let this_struct = Struct::new(
        "Foo",
        [
            KVPair::new("a", Value::Int(1)),
            KVPair::new("b", Value::String(String::from("foo"))),
        ],
    );

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let name = "Foo";
    let this_bytes: Vec<u8> = {
        let ctx = dummy_ctx_seal(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        rs.call_seal(name, &this_struct)?;
        let result = rs.consume_return()?;
        result.try_into()?
    };

    {
        let ctx = dummy_ctx_open(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        // call_open expects an envelope struct, so we smuggle the bytes
        // in through a field. The payload would normally be accessed
        // through an FFI module.
        let envelope = Struct::new(
            "Envelope",
            [KVPair::new("payload", Value::Bytes(this_bytes))],
        );
        rs.call_open(name, envelope)?;
        let result = rs.consume_return()?;
        let got_this: Struct = result.try_into()?;
        assert_eq!(got_this, this_struct);
    }

    Ok(())
}

#[test]
fn test_check_unwrap() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int]=>{x int}

        command Setup {
            fields {}

            seal {
                return None
            }
            open {
                return None
            }

            policy {
                finish {
                    create Foo[i: 1]=>{x: 1}
                }
            }
        }

        action test_existing() {
            let f = check_unwrap query Foo[i: 1]
            check f.x == 1
            let f2 = check_unwrap query Foo[i: 1]=>{}
            check f2.x == 1
        }

        action test_nonexistent() {
            let f = check_unwrap query Foo[i: 0]=>{}
            check false // would exit(panic), but check_unwrap should exit(check) first
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    {
        let cmd_name = "Setup";
        let this_data = Struct {
            name: String::from(cmd_name),
            fields: [].into(),
        };

        let ctx = dummy_ctx_open(cmd_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_command_policy(cmd_name, &this_data, dummy_envelope())?;
        assert_eq!(status, ExitReason::Normal);
    }

    {
        let action_name = "test_existing";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_action(action_name, [Value::None])?;
        assert_eq!(status, ExitReason::Normal);
    }

    {
        let action_name = "test_nonexistent";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_action(action_name, [Value::None])?;
        assert_eq!(status, ExitReason::Check);
    }

    Ok(())
}

#[test]
fn test_envelope_in_policy_and_recall() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {}
            seal { return None }
            open { return None }

            policy {
                check envelope.thing == "policy"
            }

            recall {
                check envelope.thing == "recall"
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_command_policy(
            name,
            &Struct::new("Foo", &[]),
            Struct::new("Envelope", [("thing".into(), "policy".into())]),
        )?;
        assert_eq!(status, ExitReason::Normal);
    }

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        let status = rs.call_command_recall(
            name,
            &Struct::new("Foo", &[]),
            Struct::new("Envelope", [("thing".into(), "recall".into())]),
        )?;
        assert_eq!(status, ExitReason::Normal);
    }

    Ok(())
}

#[test]
fn test_debug_assert() -> anyhow::Result<()> {
    let text = r#"
    function get_false() bool {
        return false
    }

    action test_debug_assert_failure() {
        debug_assert(false)
    }

    action test_debug_assert_failure_expression() {
        debug_assert(get_false())
    }

    function get_true() bool {
        return true
    }

    action test_debug_assert_pass() {
        debug_assert(true)
        debug_assert(get_true())
    }

    action test_debug_assert_invalid_type() {
        debug_assert(1)
    }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).debug(true).compile()?;
    let machine = Machine::from_module(module)?;

    fn run_action(
        machine: &Machine,
        io: &mut TestIO,
        action_name: &str,
    ) -> Result<ExitReason, MachineError> {
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(io, &ctx);
        rs.call_action(action_name, [Value::None])
    }

    assert_eq!(
        run_action(&machine, &mut io, "test_debug_assert_failure")?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(&machine, &mut io, "test_debug_assert_failure_expression")?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(&machine, &mut io, "test_debug_assert_pass")?,
        ExitReason::Normal
    );

    assert!(matches!(
        run_action(&machine, &mut io, "test_debug_assert_invalid_type")
            .err()
            .unwrap(),
        MachineError {
            err_type: MachineErrorType::InvalidType,
            ..
        }
    ));

    let module_no_debug = Compiler::new(&policy).debug(false).compile()?;
    let machine_no_debug = Machine::from_module(module_no_debug)?;

    let test_names = vec![
        "test_debug_assert_failure",
        "test_debug_assert_failure_expression",
        "test_debug_assert_pass",
        "test_debug_assert_invalid_type",
    ];

    for test_name in test_names {
        assert_eq!(
            run_action(&machine_no_debug, &mut io, test_name)?,
            ExitReason::Normal
        );
    }

    Ok(())
}

#[test]
fn test_global_let_statements() -> anyhow::Result<()> {
    let text = r#"
        let x = 42
        let y = "hello world"
        let z = true

        struct Far {
            a int,
        }

        struct Bar {
            a struct Far,
            b string,
            c bool,
        }

        let d = Bar {
            a: Far {
                a: 3
            },
            b: "y",
            c: false,
        }

        command Result {
            fields {
                a int,
                b string,
                c bool,
                d struct Bar,
            }
            seal { return None }
            open { return None }
        }

        action foo() {
            let a = x + 1
            let b = y
            let c = !z
            publish Result {
                a: a,
                b: b,
                c: c,
                d: d,
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    // Check if the global variables are defined correctly in the machine
    assert_eq!(machine.globals, {
        BTreeMap::from([
            (
                String::from("d"),
                Value::Struct(Struct {
                    name: String::from("Bar"),
                    fields: BTreeMap::from([
                        (
                            String::from("a"),
                            Value::Struct(Struct {
                                name: String::from("Far"),
                                fields: BTreeMap::from([(String::from("a"), Value::Int(3))]),
                            }),
                        ),
                        (String::from("b"), Value::String(String::from("y"))),
                        (String::from("c"), Value::Bool(false)),
                    ]),
                }),
            ),
            (String::from("x"), Value::Int(42)),
            (
                String::from("y"),
                Value::String(String::from("hello world")),
            ),
            (String::from("z"), Value::Bool(true)),
        ])
    });

    let ctx = dummy_ctx_action("foo");
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action("foo", [Value::None])?;
    assert_eq!(result, ExitReason::Normal);

    // Check if the published struct is correct
    assert_eq!(io.publish_stack.len(), 1);
    assert_eq!(
        io.publish_stack[0],
        (
            String::from("Result"),
            vec![
                KVPair::new("a", Value::Int(43)),
                KVPair::new("b", Value::String(String::from("hello world"))),
                KVPair::new("c", Value::Bool(false)),
                KVPair::new(
                    "d",
                    Value::Struct(Struct {
                        name: String::from("Bar"),
                        fields: BTreeMap::from([
                            (
                                String::from("a"),
                                Value::Struct(Struct {
                                    name: String::from("Far"),
                                    fields: BTreeMap::from([(String::from("a"), Value::Int(3))]),
                                }),
                            ),
                            (String::from("b"), Value::String(String::from("y"))),
                            (String::from("c"), Value::Bool(false)),
                        ]),
                    }),
                ),
            ]
        )
    );

    Ok(())
}

#[test]
fn test_global_let_duplicates() -> anyhow::Result<()> {
    let text = r#"
        let x = 10

        command Result {
            fields {
                a int,
            }
            seal { return None }
            open { return None }
        }

        action foo() {
            let x = x + 15
            publish Result {
                a: x,
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_action("foo");
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action("foo", [Value::None]);

    assert!(matches!(
        result,
        Err(MachineError {
            err_type: MachineErrorType::AlreadyDefined(identifier),
            ..
        }) if identifier == "x"
    ));

    let text = r#"
        let x = 10
        let x = 5
    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let res = Compiler::new(&policy).compile();
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::AlreadyDefined(identifier),
            ..
        }) if identifier == "x"
    ));

    Ok(())
}

#[test]
fn test_enum_reference() -> anyhow::Result<()> {
    let text = r#"
        effect Effect { a string }

        enum Drink {
            Water, Coffee
        }

        command Test {
            fields {
                e string
            }
            open { return None }
            seal { return None }
            policy {
                finish {
                    emit Effect { e: this.e }
                }
            }
        }

        action test(type enum Drink) {
            match type {
                Drink::Water => {
                    publish Test { e: "bleh" }
                }
                Drink::Coffee => {
                    publish Test { e: "mmm" }
                }
            }
        }


    "#;

    let policy = parse_policy_str(text, Version::V1)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let reason = rs.call_action("test", [Value::from(1)])?;
    assert_eq!(reason, ExitReason::Normal);
    assert_eq!(
        io.publish_stack[0],
        (
            String::from("Test"),
            vec![KVPair::new("e", Value::from("mmm"))]
        )
    );

    Ok(())
}

// Module support

/// Tests serializing then deserializing a [`Module`].
#[test]
fn test_module_round_trip() {
    let policy = parse_policy_str(
        r#"
fact Foo[]=>{x int}

effect Update {
value int
}

command Set {
fields {
    a int,
}
seal { return None }
open { return None }
policy {
    let x = this.a
    finish {
        create Foo[]=>{x: x}
        emit Update{value: x}
    }
}
}

command Clear {
fields {}
seal { return None }
open { return None }
policy {
    finish {
        delete Foo[]
    }
}
}

command Increment {
fields {}
seal { return None }
open { return None }
policy {
    let r = unwrap query Foo[]=>{x: ?}
    let new_x = r.x + 1
    finish {
        update Foo[]=>{x: r.x} to {x: new_x}
        emit Update{value: new_x}
    }
}
}
"#
        .trim(),
        Version::V1,
    )
    .unwrap();

    let want = Compiler::new(&policy).compile().unwrap();
    let machine = Machine::from_module(want.clone());

    let data = {
        let mut buf = Vec::new();
        cbor::into_writer(&want, &mut buf).unwrap();
        buf
    };
    let got: Module = cbor::from_reader(&data[..]).unwrap();
    assert_eq!(got, want);
    assert_eq!(Machine::from_module(got), machine);
}
