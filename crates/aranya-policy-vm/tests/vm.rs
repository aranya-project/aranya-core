#![cfg(test)]
#![allow(clippy::unwrap_used)]

mod bits;

use std::{cell::RefCell, collections::BTreeMap, iter};

use aranya_crypto::Id;
use aranya_policy_ast::{self as ast, Version};
use aranya_policy_compiler::{CompileErrorType, Compiler};
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, FactValue, KVPair, Machine, MachineError,
    MachineErrorType, MachineIO, MachineStack, Module, OpenContext, PolicyContext, RunState,
    SealContext, Stack, Struct, Value,
};
use bits::{policies::*, testio::*};
use ciborium as cbor;

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
                id_field id,
                x bytes,
            }
            seal { return None }
            open { return None }
        }

        action foo(id_input id, x bytes) {
            publish Foo{id_field: id_input, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&io, ctx);

        call_action(
            &mut rs,
            &io,
            name,
            [Value::Id(Id::default()), Value::Bytes(vec![0, 255, 42])],
        )?
        .success();
    }

    assert_eq!(
        io.borrow().publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("id_field", Value::Id(Id::default())),
                KVPair::new("x", Value::Bytes(vec![0, 255, 42]))
            ]
        )
    );
    assert_eq!(
        format!("{}", io.borrow().publish_stack[0].1[0]),
        format!("id_field: {}", Id::default().to_string())
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
                id_field id,
                bar struct Bar,
            }
            seal { return None }
            open { return None }
        }

        action foo(id_input id, x int) {
            publish Foo{
                id_field: id_input,
                bar: Bar {
                    x: x
                },
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
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
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(
            &mut rs,
            &io,
            name,
            [Value::Id(Id::default()), Value::Int(3)],
        )?
        .success();
    }

    assert_eq!(
        io.borrow().publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new(
                    "bar",
                    Value::Struct(Struct::new("Bar", [KVPair::new("x", Value::Int(3))]))
                ),
                KVPair::new("id_field", Value::Id(Id::default())),
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

        action foo(id_input id, x int) {
            let v = Bar {
                y: x
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let err = {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action("foo", [Value::Id(Id::default()), Value::Int(3)])
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
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = "foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, name, [Value::from(3)])?.success();

    assert_eq!(
        io.borrow().publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("a", Value::Int(3)),
                KVPair::new("b", Value::Int(4))
            ]
        )
    );

    Ok(())
}

#[test]
fn test_action_wrong_args() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = "foo";
    let module = Compiler::new(&policy).compile()?;
    let mut machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_action(name);

    // wrong number of args
    {
        let io = RefCell::new(TestIO::new());

        let err = machine
            .call_action(
                name,
                [Value::from("3"), Value::from(false)],
                &io,
                ctx.to_owned(),
            )
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::Unknown(String::from(
                "action `foo` expects 1 argument(s), but was called with 2"
            ))
        );
    }

    // invalid type
    {
        let io = RefCell::new(TestIO::new());

        let err = machine
            .call_action(name, [Value::from("3")], &io, ctx)
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::invalid_type("int", "String", "invalid function argument")
        );
    }

    Ok(())
}

#[test]
fn test_action_call_action() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1, Version::V2).expect("should parse");
    let module = Compiler::new(&policy).compile().expect("should compile");
    let machine = Machine::from_module(module).expect("should create machine");
    let io = RefCell::new(TestIO::new());

    let action_name = "bar";
    let ctx = dummy_ctx_policy(action_name);
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, action_name, Vec::<i64>::new())?.success();

    assert_eq!(io.borrow().publish_stack.len(), 2);
    assert_eq!(
        io.borrow().publish_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("a", Value::Int(4)),
                KVPair::new("b", Value::Int(4))
            ]
        )
    );
    assert_eq!(
        io.borrow().publish_stack[1],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("a", Value::Int(3)),
                KVPair::new("b", Value::Int(4))
            ]
        )
    );

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_policy(name);
    let io = RefCell::new(TestIO::new());

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
        .call_command_policy(name, &self_data, dummy_envelope(), &io, ctx)
        .expect("Could not call command policy")
        .success();

    println!("effects: {:?}", io.borrow().effect_stack);

    Ok(())
}

#[test]
fn test_command_invalid_this() {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2).expect("should parse");

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()
        .expect("should compile");
    let mut machine = Machine::from_module(module).expect("should create machine");
    let ctx = dummy_ctx_policy(name);

    // invalid field count
    {
        let io = RefCell::new(TestIO::new());
        let self_data = Struct {
            name: String::from("Bar"),
            fields: vec![(String::from("b"), Value::Int(4))]
                .into_iter()
                .collect(),
        };
        let err = machine
            .call_command_policy(name, &self_data, dummy_envelope(), &io, ctx.to_owned())
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::Unknown(String::from(
                "command `Foo` expects 2 field(s), but `this` contains 1"
            ))
        );
    }

    // invalid field name
    {
        let io = RefCell::new(TestIO::new());
        let self_data = Struct {
            name: String::from("Bar"),
            fields: vec![
                (String::from("aaa"), Value::Int(3)),
                (String::from("b"), Value::Int(4)),
            ]
            .into_iter()
            .collect(),
        };
        let err = machine
            .call_command_policy(name, &self_data, dummy_envelope(), &io, ctx.to_owned())
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::InvalidStructMember(String::from("aaa"))
        );
    }

    // invalid type
    {
        let io = RefCell::new(TestIO::new());
        let self_data = Struct {
            name: String::from("Bar"),
            fields: vec![
                (String::from("a"), Value::Int(3)),
                (String::from("b"), Value::Bool(false)),
            ]
            .into_iter()
            .collect(),
        };
        let err = machine
            .call_command_policy(name, &self_data, dummy_envelope(), &io, ctx)
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::invalid_type("int", "Bool", "invalid function argument")
        );
    }
}

#[test]
fn test_seal() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_seal(name);
    let io = RefCell::new(TestIO::new());
    let mut rs = machine.create_run_state(&io, ctx);

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
        .expect("Could not call command policy")
        .success();

    let stack_vec = rs.stack.into_vec();
    assert_eq!(stack_vec[0], Value::None);

    Ok(())
}

#[test]
fn test_open() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = "Foo";
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_open(name);
    let io = RefCell::new(TestIO::new());
    let mut rs = machine.create_run_state(&io, ctx);

    rs.call_open(name, dummy_envelope())
        .expect("Could not call command policy")
        .success();

    let stack_vec = rs.stack.into_vec();
    assert_eq!(stack_vec[0], Value::None);

    Ok(())
}

// Fact manipulation

#[test]
fn test_fact_create_delete() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V2)?;

    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());

    // We have to scope the RunState so that it and its mutable
    // reference to IO is dropped before we inspect the IO struct.
    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [(KVPair::new_int("a", 3))]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(3))];
    assert_eq!(io.borrow().facts[&fk], fv);

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Set", &[]);
        machine
            .call_command_policy("Clear", &self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    assert_eq!(io.borrow().facts.get(&fk), None);

    Ok(())
}

#[test]
fn test_fact_query() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V2)?;

    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [KVPair::new_int("a", 3)]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &io, ctx)?
            .success();

        let name = "Increment";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, &[]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(4))];
    assert_eq!(io.borrow().facts[&fk], fv);

    Ok(())
}

#[test]
fn test_fact_exists() -> anyhow::Result<()> {
    let text = r#"
    enum Bool {
        True,
        False
    }

    fact Foo[] => {x int}
    fact Bar[i int] => {s string, b enum Bool}

    command setup {
        fields {}
        seal { return None }
        open { return None }
        policy {
            finish {
                create Foo[] => {x: 3}
                create Bar[i: 1] => {s: "abc", b: Bool::True}
            }
        }
    }

    action testExists() {
        check exists Foo[] => {x: 3}
        check exists Foo[]
        check exists Bar[i: 1] => {s: "abc", b: Bool::True}

        check exists Foo[] => {x: ?}
        check exists Bar[i: ?] => {s: ?, b: Bool::True}

        // Not-exists

        // no fact with such values
        check !exists Bar[i:0] => {s:"ab", b:Bool::True}
        check !exists Bar[i:1] => {s:"", b:Bool::True}
        check !exists Bar[i: ?]=>{s: "ab", b: ?}
    }
    "#;

    let policy = parse_policy_str(text.trim(), Version::V2)?;

    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = "setup";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    {
        let name = "testExists";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(&mut rs, &io, name, iter::empty::<Value>())?.success();
    }

    Ok(())
}

#[test]
fn test_counting() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int]=>{}

        command Setup {
            open { return None }
            seal { return None }
            policy {
                finish {
                    create Foo[i:1]=>{}
                    create Foo[i:2]=>{}
                    create Foo[i:3]=>{}
                }
            }
        }

        command TestUpTo {
            open { return None }
            seal { return None }
            policy {
                let count_one = count_up_to 1 Foo[i:?]
                check count_one == 1
                let count_two = count_up_to 2 Foo[i:?]
                check count_two == 2
                let count_all = count_up_to 10 Foo[i:?]
                check count_all == 3
                let count_max = count_up_to 9223372036854775807 Foo[i:?]
                check count_max == 3
            }
        }

        command TestAtLeast {
            open { return None }
            seal { return None }
            policy {
                check at_least 1 Foo[i:?]
                check at_least 3 Foo[i:?]
                check at_least 4 Foo[i:?] == false
            }
        }

        command TestAtMost {
            open { return None }
            seal { return None }
            policy {
                check at_most 1 Foo[i:?] == false
                check at_most 3 Foo[i:?]
                check at_most 4 Foo[i:?]
            }
        }

        command TestExactly {
            open { return None }
            seal { return None }
            policy {
                check exactly 1 Foo[i:?] == false
                check exactly 3 Foo[i:?]
                check exactly 4 Foo[i:?] == false
            }
        }
    "#;

    let policy = parse_policy_str(text.trim(), Version::V2)?;

    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    {
        let name = "Setup";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    println!("TestUpTo...");
    {
        let name = "TestUpTo";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    println!("TestAtLeast...");
    {
        let name = "TestAtLeast";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    println!("TestAtMost...");
    {
        let name = "TestAtMost";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    println!("TestExactly...");
    {
        let name = "TestExactly";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
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

        // Set creates the fact
        command Set {
            fields {
                a int,
                x int,
            }

            seal { return None }
            open { return None }

            policy {
                finish {
                    create Foo[a: this.a]=>{b: this.x}
                }
            }
        }

        // Emit emmits the fact query from the function
        command Emit {
            fields {
                a int
            }

            seal { return None }
            open { return None }

            policy {
                let x = get_foo(this.a)
                finish {
                    emit Result { x: x }
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let a = Value::Int(1);

    // Create fact through Set
    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(
            "Foo",
            [KVPair::new("a", a.clone()), KVPair::new("x", Value::Int(2))],
        );
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }

    // Emit fact through Bar
    {
        let cmd_name = "Emit";
        let ctx = dummy_ctx_policy(cmd_name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new("Bar", [KVPair::new("a", a)]);
        rs.call_command_policy(cmd_name, &self_struct, dummy_envelope())?
            .success();
    }

    assert_eq!(
        io.borrow().effect_stack[0],
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
            let f = unwrap query Foo[i:?, j:?]
        }

        action test_exists() {
            check exists Foo[i:1, j:?]
            check exists Foo[i:-1, j:?] == false
            check !exists Foo[i:1, j:?] => {x:-1, s:?}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;

    {
        let cmd_name = "Setup";
        let this_data = Struct {
            name: String::from(cmd_name),
            fields: [].into(),
        };

        let ctx = dummy_ctx_open(cmd_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(cmd_name, &this_data, dummy_envelope())?
            .success();
    }

    {
        let action_name = "test_query";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
    }

    {
        let action_name = "test_exists";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
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
        Version::V2,
    )?;

    let name = "test";
    let ctx = dummy_ctx_policy(name);
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action("test", iter::empty::<Value>())?.success();

    Ok(())
}

#[test]
fn test_if_true() -> anyhow::Result<()> {
    let text = r#"
        action foo(x bool) {
            if x == true {
                check true == false
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);

    let result = rs.call_action(name, [true])?;
    assert_eq!(result, ExitReason::Check);

    Ok(())
}

#[test]
fn test_if_false() -> anyhow::Result<()> {
    let text = r#"
        action foo(x bool) {
            if x == true {
                check true == false
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);

    rs.call_action(name, [false])?.success();

    Ok(())
}

#[test]
fn test_if_branches() -> anyhow::Result<()> {
    let text = r#"
        command Result {
            fields {
                s string
            }
            seal { return None }
            open { return None }
        }

        action foo(x int) {
            if x == 0 {
                check true
                publish Result { s: "0" }
                check true
            } else if x == 1 {
                publish Result { s: "1" }
            } else if x == 2 {
                check true
                publish Result { s: "2" }
            } else {
                publish Result { s: "3" }
                check true
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V2)?;
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    for i in 0i64..4 {
        let io = RefCell::new(TestIO::new());
        let mut rs = machine.create_run_state(&io, ctx.to_owned());
        call_action(&mut rs, &io, name, [i])?.success();
        drop(rs);

        assert_eq!(
            io.borrow().publish_stack,
            [(
                "Result".to_string(),
                vec![KVPair::new("s", i.to_string().into())]
            )],
        );
    }

    Ok(())
}

#[test]
fn test_match_first() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);

    call_action(&mut rs, &io, name, [5])?.success();
    drop(rs);

    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(5)),])
    );

    Ok(())
}

#[test]
fn test_match_second() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, name, [6])?.success();
    drop(rs);

    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(6)),])
    );

    Ok(())
}

#[test]
fn test_match_none() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&io, ctx);
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
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let action_name = "foo";
    let ctx = dummy_ctx_action(action_name);
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, action_name, [Value::Int(6)])?.success();
    drop(rs);

    assert_eq!(
        io.borrow().publish_stack[0],
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
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, name, [Value::Int(6)])?.success();
    drop(rs);

    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(0)),])
    );

    Ok(())
}

#[test]
fn test_match_return() -> anyhow::Result<()> {
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_action("foo");
    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action("foo", [42])?.success();

    Ok(())
}

#[test]
fn test_is_some_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);

    // Test with a value that is not None
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, name, [Value::Int(10)])?.success();
    drop(rs);

    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(10))])
    );

    Ok(())
}

#[test]
fn test_is_none_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);

    // Test with a None value
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, name, [Value::None])?.success();
    drop(rs);

    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::None)])
    );

    Ok(())
}

#[test]
fn test_negative_numeric_expression() -> anyhow::Result<()> {
    let text = r#"
        action foo(x int) {
            let a = -2
            check x - a == 1
            check -5 == -(4 + 1)
            check 42 == --42
        }

        action neg_min_1() {
            let n = -9223372036854775807
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let io = RefCell::new(TestIO::new());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(name, [-1])?.success();
    }

    {
        let name = "neg_min_1";
        let ctx = dummy_ctx_action(name);
        let io = RefCell::new(TestIO::new());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(name, iter::empty::<Value>())?.success();
    }

    Ok(())
}

#[test]
fn test_negative_logical_expression() -> anyhow::Result<()> {
    let text = r#"
    action foo(x bool, y bool) {
        if x {
            check x
        }
        if !y {
            check !y
        }
    }
    "#;
    let name = "foo";
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action(name, [true, false])?.success();

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
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name);
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&io, ctx);
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(&mut rs, &io, name, [3])?.success();
    }

    assert_eq!(
        io.borrow().publish_stack[0],
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
            emit Result { x: x }
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Foo", [KVPair::new("x", Value::Int(3))]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    assert_eq!(
        io.borrow().effect_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(3)),])
    );

    Ok(())
}

#[test]
fn test_serialize_deserialize() -> anyhow::Result<()> {
    let text = r#"
        struct Envelope {
            payload bytes
        }

        command Foo {
            fields {
                a int,
                b string,
            }

            seal {
                return Envelope {
                    payload: serialize(this)
                }
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let name = "Foo";
    let this_bytes: Vec<u8> = {
        let ctx = dummy_ctx_seal(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_seal(name, &this_struct)?.success();
        let result = rs.consume_return()?;
        let mut envelope: Struct = result.try_into()?;
        let payload = envelope
            .fields
            .remove("payload")
            .expect("envelope has no payload");
        payload.try_into()?
    };

    {
        let ctx = dummy_ctx_open(name);
        let mut rs = machine.create_run_state(&io, ctx);
        // call_open expects an envelope struct, so we smuggle the bytes
        // in through a field. The payload would normally be accessed
        // through an FFI module.
        let envelope = Struct::new("Env", [KVPair::new("payload", Value::Bytes(this_bytes))]);
        rs.call_open(name, envelope)?.success();
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
        }

        action test_nonexistent() {
            let f = check_unwrap query Foo[i: 0]
            check false // would exit(panic), but check_unwrap should exit(check) first
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
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
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(cmd_name, &this_data, dummy_envelope())?
            .success();
    }

    {
        let action_name = "test_existing";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
    }

    {
        let action_name = "test_nonexistent";
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(&io, ctx);
        let status = rs.call_action(action_name, iter::empty::<Value>())?;
        assert_eq!(status, ExitReason::Check);
    }

    Ok(())
}

#[test]
fn test_envelope_in_policy_and_recall() -> anyhow::Result<()> {
    let text = r#"
        struct Envelope {
            payload bytes
        }

        command Foo {
            fields {
                test bytes
            }
            seal { return None }
            open { return None }

            policy {
                check envelope.payload == this.test
            }

            recall {
                check envelope.payload == this.test
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let test_data = "thing".as_bytes().to_vec();

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(
            name,
            &Struct::new("Foo", [KVPair::new("test", test_data.clone().into())]),
            Struct::new(
                "Envelope",
                [KVPair::new("payload", test_data.clone().into())],
            ),
        )?
        .success();
    }

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_recall(
            name,
            &Struct::new("Foo", [KVPair::new("test", test_data.clone().into())]),
            Struct::new(
                "Envelope",
                [KVPair::new("payload", test_data.clone().into())],
            ),
        )?
        .success();
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).debug(true).compile()?;
    let machine = Machine::from_module(module)?;

    fn run_action(
        machine: &Machine,
        io: &RefCell<TestIO>,
        action_name: &str,
    ) -> Result<ExitReason, MachineError> {
        let ctx = dummy_ctx_open(action_name);
        let mut rs = machine.create_run_state(io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())
    }

    assert_eq!(
        run_action(&machine, &io, "test_debug_assert_failure")?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(&machine, &io, "test_debug_assert_failure_expression")?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(&machine, &io, "test_debug_assert_pass")?,
        ExitReason::Normal
    );

    assert!(matches!(
        run_action(&machine, &io, "test_debug_assert_invalid_type")
            .err()
            .unwrap(),
        MachineError {
            err_type: MachineErrorType::InvalidType { .. },
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
            run_action(&machine_no_debug, &io, test_name)?,
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

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
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
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &io, "foo", iter::empty::<Value>())?.success();
    drop(rs);

    // Check if the published struct is correct
    assert_eq!(io.borrow().publish_stack.len(), 1);
    assert_eq!(
        io.borrow().publish_stack[0],
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
fn test_enum_reference() -> anyhow::Result<()> {
    let text = r#"
        effect Effect { a string }

        enum Drink {
            Water, Coffee
        }

        action test(type enum Drink) {
            match type {
                Drink::Water => {
                    publish Effect { a: "bleh" }
                }
                Drink::Coffee => {
                    publish Effect { a: "mmm" }
                }
            }
        }


    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(
        &mut rs,
        &io,
        "test",
        [machine
            .parse_enum("Drink::Coffee")
            .expect("enum ref is valid")],
    )?
    .success();

    drop(rs);

    assert_eq!(
        io.borrow().publish_stack[0],
        (
            String::from("Effect"),
            vec![KVPair::new("a", Value::from("mmm"))]
        )
    );

    Ok(())
}

fn call_action<M, Args>(
    rs: &mut RunState<'_, M>,
    io: &RefCell<M>,
    name: &str,
    args: Args,
) -> Result<ExitReason, MachineError>
where
    M: MachineIO<MachineStack>,
    Args: IntoIterator,
    Args::Item: Into<Value>,
{
    let mut er = rs.call_action(name, args)?;
    while let ExitReason::Yield = er {
        // usually, we would seal the command and add it to the IO
        let command_struct: Struct = rs.stack.pop()?;
        let fields = command_struct
            .fields
            .iter()
            .map(|(k, v)| KVPair::new(k, v.clone()));
        io.borrow_mut().publish(command_struct.name, fields);
        er = rs.run()?;
    }
    Ok(er)
}

#[test]
fn test_enum_parse() -> anyhow::Result<()> {
    let policy = parse_policy_str("enum Drink { Water, Coffee }", Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;

    assert_eq!(
        machine.parse_enum("Drink").unwrap_err().err_type,
        MachineErrorType::invalid_type("<Enum>::<Variant>", "Drink", "invalid enum reference")
    );
    assert_eq!(
        machine.parse_enum("Drink::").unwrap_err().err_type,
        MachineErrorType::NotDefined("no value `` in enum `Drink`".to_owned())
    );
    assert_eq!(
        machine.parse_enum("Coffee").unwrap_err().err_type,
        MachineErrorType::invalid_type("<Enum>::<Variant>", "Coffee", "invalid enum reference")
    );
    assert_eq!(
        machine.parse_enum("Drink::Water")?,
        Value::Enum("Drink".to_owned(), 0)
    );
    assert_eq!(
        machine.parse_enum("Drink::Coffee")?,
        Value::Enum("Drink".to_owned(), 1)
    );
    assert_eq!(
        machine.parse_enum("Drink::Tea").unwrap_err().err_type,
        MachineErrorType::NotDefined("no value `Tea` in enum `Drink`".to_owned())
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
        Version::V2,
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

#[test]
fn test_ffi_fail_without_use() -> anyhow::Result<()> {
    let text = r#"
        function test() int {
            let head_id = print::print("hi")
            return 0
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let result = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()
        .expect_err("")
        .err_type;
    assert_eq!(result, CompileErrorType::NotDefined(String::from("print")));

    Ok(())
}

#[test]
fn test_map() -> anyhow::Result<()> {
    let text = r#"
        fact F[i int]=>{n int}
        effect Result {
            value int
        }

        command Setup {
            open { return None }
            seal { return None }
            policy {
                finish {
                    create F[i:1]=>{n:1}
                    create F[i:2]=>{n:2}
                    create F[i:3]=>{n:3}
                }
            }
        }

        command Process {
            fields {
                value int
            }
            open { return None }
            seal { return None }
            policy {
                finish {
                    emit Result {
                        value: this.value
                    }
                }
            }
        }

        action test() {
            map F[i:?] as f {
                publish Process { value: f.n }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());

    // Empty results. Run test without creating facts.
    {
        let name = "test";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let prev_stack_depth = rs.stack.len();
        call_action(&mut rs, &io, name, iter::empty::<Value>())?.success();

        // Make sure we didn't leave any trailing values on the stack
        let stack = rs.stack.into_vec();
        assert_eq!(stack.len(), prev_stack_depth);
    }

    // Test with some data
    {
        let name = "Setup";
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(name, &self_struct, dummy_envelope())?
            .success();
    }
    {
        // Create a new scope so that the Runstate is fully dropped
        // before io.borrow().publish_stack is accessed
        {
            let name = "test";
            let ctx = dummy_ctx_action(name);
            let mut rs = machine.create_run_state(&io, ctx);
            let prev_stack_depth = rs.stack.len();
            call_action(&mut rs, &io, name, iter::empty::<Value>())?.success();

            // Make sure we didn't leave any trailing values on the stack
            let stack = rs.stack.into_vec();
            assert_eq!(stack.len(), prev_stack_depth);
        }

        // Assert we iterated as many times as expected, and with the correct results each time.
        assert_eq!(io.borrow().publish_stack.len(), 3);
        for (i, value) in [1, 2, 3].into_iter().enumerate() {
            let kv = &io.borrow().publish_stack[i].1;
            assert_eq!(*kv[0].value(), Value::Int(value));
        }
    }
    Ok(())
}

#[test]
fn test_optional_type_validation() -> anyhow::Result<()> {
    let text = r#"
        command TypeValidation {
            fields {
                maybe_int optional int,
                name string,
            }
            seal { return None }
            open { return None }
            policy {
                finish {}
            }
        }

        action type_validation(maybe_int_input optional int, name_input string) {
            publish TypeValidation{maybe_int: maybe_int_input, name: name_input}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let cases = [
        (
            Ok(ExitReason::Normal),
            [
                KVPair::new("maybe_int", Value::None),
                KVPair::new("name", Value::String("foo".into())),
            ],
        ),
        (
            Ok(ExitReason::Normal),
            [
                KVPair::new("maybe_int", Value::Int(5)),
                KVPair::new("name", Value::String("foo".into())),
            ],
        ),
        (
            Err(MachineErrorType::invalid_type(
                "string",
                "None",
                "invalid function argument",
            )),
            [
                KVPair::new("maybe_int", Value::None),
                KVPair::new("name", Value::None),
            ],
        ),
    ];

    for case in cases.into_iter() {
        let (expected, args) = case;

        // action call validation
        {
            let name = "type_validation";
            let ctx = dummy_ctx_action(name);
            let mut rs = machine.create_run_state(&io, ctx);
            let action_args = args.iter().map(KVPair::value).cloned();

            assert_eq!(
                call_action(&mut rs, &io, name, action_args).map_err(|e| e.err_type),
                expected
            );
        }

        // command call validation
        {
            let name = "TypeValidation";
            let ctx = dummy_ctx_policy(name);
            let mut rs = machine.create_run_state(&io, ctx);

            assert_eq!(
                rs.call_command_policy(name, &Struct::new(name, args), dummy_envelope())
                    .map_err(|e| e.err_type),
                expected
            );
        }
    }

    Ok(())
}

#[test]
fn test_block_expression() -> anyhow::Result<()> {
    let policy_text = r#"
        command TestCommand {
            fields {
                x int
            }

            seal { return None }
            open { return None }

            policy {
            }
        }

        action test() {
            let a = 3
            let b = 4
            let x = {
                let c = 5
                : a + b + c
            }

            publish TestCommand {
                x: x
            }
        }
    "#
    .trim();

    let policy = parse_policy_str(policy_text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let name = "test";
    let args: [Value; 0] = [];
    let ctx = dummy_ctx_action(name);
    let mut rs = machine.create_run_state(&io, ctx);
    let r = call_action(&mut rs, &io, name, args)?;
    assert_eq!(r, ExitReason::Normal);

    assert_eq!(
        io.borrow_mut().publish_stack.last(),
        Some(&(
            "TestCommand".to_string(),
            vec![KVPair::new("x", Value::Int(12))]
        ))
    );

    Ok(())
}
