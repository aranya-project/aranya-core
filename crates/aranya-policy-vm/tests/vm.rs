#![cfg(test)]
#![allow(clippy::unwrap_used)]

mod bits;

use std::{cell::RefCell, collections::BTreeMap, iter};

use aranya_crypto::{BaseId, DeviceId, policy::CmdId};
use aranya_policy_ast::{self as ast, Version};
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::parse_policy_str;
use aranya_policy_vm::{
    ActionContext, CommandContext, ExitReason, FactValue, Identifier, KVPair, Machine,
    MachineError, MachineErrorType, MachineIO, MachineStack, Module, OpenContext, PolicyContext,
    RunState, SealContext, Stack as _, Struct, Value, ident, text,
};
use bits::{policies::*, testio::*};
use ciborium as cbor;

fn dummy_ctx_action(name: Identifier) -> CommandContext {
    CommandContext::Action(ActionContext {
        name,
        head_id: CmdId::default(),
    })
}

fn dummy_ctx_seal(name: Identifier) -> CommandContext {
    CommandContext::Seal(SealContext {
        name,
        head_id: CmdId::default(),
    })
}

fn dummy_ctx_open(name: Identifier) -> CommandContext {
    CommandContext::Open(OpenContext { name })
}

fn dummy_ctx_policy(name: Identifier) -> CommandContext {
    CommandContext::Policy(PolicyContext {
        name,
        id: CmdId::default(),
        author: DeviceId::default(),
        version: BaseId::default(),
    })
}

fn dummy_ctx_recall(name: Identifier) -> CommandContext {
    CommandContext::Recall(PolicyContext {
        name,
        id: CmdId::default(),
        author: DeviceId::default(),
        version: BaseId::default(),
    })
}

fn dummy_envelope() -> Struct {
    Struct {
        name: ident!("Envelope"),
        fields: BTreeMap::new(),
    }
}

macro_rules! vm_struct {
    ($ident:ident { $( $field:ident : $val:expr ),* $(,)? }) => {
        Struct {
            name: ident!(stringify!($ident)),
            fields: [ $(
                (ident!(stringify!($field)), Value::from($val))
            ),* ].into()
        }
    };
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
            seal { return todo() }
            open { return todo() }
        }

        action foo(id_input id, x bytes) {
            publish Foo{id_field: id_input, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = ident!("foo");
        let ctx = dummy_ctx_action(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);

        call_action(
            &mut rs,
            &mut published,
            name,
            [Value::Id(BaseId::default()), Value::Bytes(vec![0, 255, 42])],
        )?
        .success();
    }

    assert_eq!(
        published,
        [vm_struct!(Foo {
            id_field: BaseId::default(),
            x: vec![0, 255, 42],
        })]
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
            seal { return todo() }
            open { return todo() }
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
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    assert_eq!(
        machine.struct_defs.get("Bar"),
        Some(&vec![ast::FieldDefinition {
            identifier: ast::Ident {
                name: ident!("x"),
                span: ast::Span::new(34, 35)
            },
            field_type: ast::VType {
                kind: ast::TypeKind::Int,
                span: ast::Span::new(36, 39)
            }
        }])
    );

    {
        let name = ident!("foo");
        let ctx = dummy_ctx_action(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(
            &mut rs,
            &mut published,
            name,
            [Value::Id(BaseId::default()), Value::Int(3)],
        )?
        .success();
    }

    assert_eq!(
        published,
        [vm_struct!(Foo {
            bar: vm_struct!(Bar { x: 3 }),
            id_field: BaseId::default(),
        })]
    );

    Ok(())
}

// Basic entry points - action, policy, seal, open (TODO: recall)

#[test]
fn test_action() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = ident!("foo");
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());

    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, [Value::from(3)])?.success();

    assert_eq!(published, [vm_struct!(Foo { a: 3, b: 4 })]);

    Ok(())
}

#[test]
fn test_action_wrong_args() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = ident!("foo");
    let module = Compiler::new(&policy).compile()?;
    let mut machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_action(name.clone());

    // wrong number of args
    {
        let io = RefCell::new(TestIO::new());

        let err = machine
            .call_action(
                name.clone(),
                [Value::from(text!("3")), Value::from(false)],
                &io,
                ctx.clone(),
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
            .call_action(name, [Value::from(text!("3"))], &io, ctx)
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
    let mut published = Vec::new();

    let action_name = ident!("bar");
    let ctx = dummy_ctx_action(action_name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, action_name, Vec::<i64>::new())?.success();

    assert_eq!(
        published,
        [
            vm_struct!(Foo { a: 4, b: 4 }),
            vm_struct!(Foo { a: 3, b: 4 })
        ]
    );

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2)?;

    let name = ident!("Foo");
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let mut machine = Machine::from_module(module)?;
    let ctx = dummy_ctx_policy(name.clone());
    let io = RefCell::new(TestIO::new());

    let this_data = Struct {
        name,
        fields: vec![(ident!("a"), Value::Int(3)), (ident!("b"), Value::Int(4))]
            .into_iter()
            .collect(),
    };
    machine
        .call_command_policy(this_data, dummy_envelope(), &io, ctx)
        .expect("Could not call command policy")
        .success();

    println!("effects: {:?}", io.borrow().effect_stack);

    Ok(())
}

#[test]
fn test_command_invalid_this() {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V2).expect("should parse");

    let name = ident!("Foo");
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()
        .expect("should compile");
    let mut machine = Machine::from_module(module).expect("should create machine");
    let ctx = dummy_ctx_policy(name.clone());

    // invalid field count
    {
        let io = RefCell::new(TestIO::new());
        let this_data = Struct {
            name: name.clone(),
            fields: vec![(ident!("b"), Value::Int(4))].into_iter().collect(),
        };
        let err = machine
            .call_command_policy(this_data, dummy_envelope(), &io, ctx.clone())
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
        let this_data = Struct {
            name: name.clone(),
            fields: vec![(ident!("aaa"), Value::Int(3)), (ident!("b"), Value::Int(4))]
                .into_iter()
                .collect(),
        };
        let err = machine
            .call_command_policy(this_data, dummy_envelope(), &io, ctx.clone())
            .unwrap_err()
            .err_type;
        assert_eq!(err, MachineErrorType::InvalidStructMember(ident!("aaa")));
    }

    // invalid type
    {
        let io = RefCell::new(TestIO::new());
        let this_data = Struct {
            name,
            fields: vec![
                (ident!("a"), Value::Int(3)),
                (ident!("b"), Value::Bool(false)),
            ]
            .into_iter()
            .collect(),
        };
        let err = machine
            .call_command_policy(this_data, dummy_envelope(), &io, ctx)
            .unwrap_err()
            .err_type;
        assert_eq!(
            err,
            MachineErrorType::invalid_type("int", "Bool", "invalid function argument")
        );
    }
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
        let name = ident!("Set");
        let ctx = dummy_ctx_policy(name.clone());
        let self_struct = Struct::new(name, [(KVPair::new_int(ident!("a"), 3))]);
        machine
            .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    let fk = (ident!("Foo"), vec![]);
    let fv = vec![FactValue::new(ident!("x"), Value::Int(3))];
    assert_eq!(io.borrow().facts[&fk], fv);

    {
        let name = ident!("Clear");
        let ctx = dummy_ctx_policy(name.clone());
        let self_struct = Struct::new(name, &[]);
        machine
            .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
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
        let name = ident!("Set");
        let ctx = dummy_ctx_policy(name.clone());
        let self_struct = Struct::new(name, [KVPair::new_int(ident!("a"), 3)]);
        machine
            .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
            .success();

        let name = ident!("Increment");
        let ctx = dummy_ctx_policy(name.clone());
        let self_struct = Struct::new(name, &[]);
        machine
            .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    let fk = (ident!("Foo"), vec![]);
    let fv = vec![FactValue::new(ident!("x"), Value::Int(4))];
    assert_eq!(io.borrow().facts[&fk], fv);

    Ok(())
}

#[test]
fn test_invalid_update() -> anyhow::Result<()> {
    fn run(initial_value: i64) -> anyhow::Result<ExitReason> {
        let policy = parse_policy_str(POLICY_TEST_UPDATE.trim(), Version::V2)?;

        let module = Compiler::new(&policy)
            .ffi_modules(TestIO::FFI_SCHEMAS)
            .compile()?;
        let mut machine = Machine::from_module(module)?;
        let io = RefCell::new(TestIO::new());

        let exit = {
            let name = ident!("Set");
            let ctx = dummy_ctx_policy(name.clone());
            let self_struct = Struct::new(name, [KVPair::new_int(ident!("a"), initial_value)]);
            machine
                .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
                .success();

            let name = ident!("Increment");
            let ctx = dummy_ctx_policy(name.clone());
            let self_struct = Struct::new(name, &[]);
            machine.call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
        };

        let fk = (ident!("Foo"), vec![]);
        let fv = vec![FactValue::new(ident!("x"), Value::Int(initial_value + 1))];
        assert_eq!(io.borrow().facts[&fk], fv);

        Ok(exit)
    }

    // Incrementing from '0' is valid
    assert_eq!(run(0).unwrap(), ExitReason::Normal);

    // Incrementing from a value other than '0' is invalid
    let err = run(10).unwrap_err().downcast::<MachineError>()?;
    assert_eq!(err.err_type, MachineErrorType::InvalidFact(ident!("Foo")));

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
        seal { return todo() }
        open { return todo() }
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
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    {
        let name = ident!("setup");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    {
        let name = ident!("testExists");
        let ctx = dummy_ctx_action(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(&mut rs, &mut published, name, iter::empty::<Value>())?.success();
    }

    Ok(())
}

#[test]
fn test_counting() -> anyhow::Result<()> {
    let text = r#"
        fact Foo[i int]=>{}

        command Setup {
            open { return todo() }
            seal { return todo() }
            policy {
                finish {
                    create Foo[i:1]=>{}
                    create Foo[i:2]=>{}
                    create Foo[i:3]=>{}
                }
            }
        }

        command TestUpTo {
            open { return todo() }
            seal { return todo() }
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
            open { return todo() }
            seal { return todo() }
            policy {
                check at_least 1 Foo[i:?]
                check at_least 3 Foo[i:?]
                check at_least 4 Foo[i:?] == false
            }
        }

        command TestAtMost {
            open { return todo() }
            seal { return todo() }
            policy {
                check at_most 1 Foo[i:?] == false
                check at_most 3 Foo[i:?]
                check at_most 4 Foo[i:?]
            }
        }

        command TestExactly {
            open { return todo() }
            seal { return todo() }
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
        let name = ident!("Setup");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    println!("TestUpTo...");
    {
        let name = ident!("TestUpTo");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    println!("TestAtLeast...");
    {
        let name = ident!("TestAtLeast");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    println!("TestAtMost...");
    {
        let name = ident!("TestAtMost");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    println!("TestExactly...");
    {
        let name = ident!("TestExactly");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
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

            seal { return todo() }
            open { return todo() }

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

            seal { return todo() }
            open { return todo() }

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
        let name = ident!("Set");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(
            name,
            [
                KVPair::new(ident!("a"), a.clone()),
                KVPair::new(ident!("x"), Value::Int(2)),
            ],
        );
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    // Emit fact
    {
        let cmd_name = ident!("Emit");
        let ctx = dummy_ctx_policy(cmd_name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(cmd_name, [KVPair::new(ident!("a"), a)]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }

    assert_eq!(
        io.borrow().effect_stack[0],
        (
            ident!("Result"),
            vec![KVPair::new(
                ident!("x"),
                Value::Struct(Struct {
                    name: ident!("Foo"),
                    fields: {
                        let mut test_struct_map = BTreeMap::new();
                        test_struct_map.insert(ident!("a"), Value::Int(1));
                        test_struct_map.insert(ident!("b"), Value::Int(2));
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
            seal { return todo() }
            open { return todo() }
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
        let cmd_name = ident!("Setup");
        let this_data = Struct {
            name: cmd_name.clone(),
            fields: [].into(),
        };

        let ctx = dummy_ctx_policy(cmd_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(this_data, dummy_envelope())?
            .success();
    }

    {
        let action_name = ident!("test_query");
        let ctx = dummy_ctx_action(action_name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
    }

    {
        let action_name = ident!("test_exists");
        let ctx = dummy_ctx_action(action_name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
    }

    Ok(())
}

#[test]
fn test_query_enum_keys() -> anyhow::Result<()> {
    let text = r#"
        enum Foo { A, B }
        fact Bar[i enum Foo] => {x enum Foo}

        command Setup {
            fields {}
            seal { return todo() }
            open { return todo() }
            policy {
                finish {
                    create Bar[i: Foo::A] => {x: Foo::A}
                    create Bar[i: Foo::B] => {x: Foo::B}
                }
            }
        }

        action test_query() {
            let f = unwrap query Bar[i:Foo::A] => {x: ?}
            check f.x == Foo::A
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;

    {
        let cmd_name = ident!("Setup");
        let this_data = Struct {
            name: cmd_name.clone(),
            fields: [].into(),
        };

        let ctx = dummy_ctx_policy(cmd_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(this_data, dummy_envelope())?
            .success();
    }

    {
        let action_name = ident!("test_query");
        let ctx = dummy_ctx_action(action_name.clone());
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

    let name = ident!("test");
    let ctx = dummy_ctx_action(name.clone());
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action(name, iter::empty::<Value>())?.success();

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

    let name = ident!("foo");
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name.clone());
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

    let name = ident!("foo");
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name.clone());
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
            seal { return todo() }
            open { return todo() }
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

    let name = ident!("foo");
    let policy = parse_policy_str(text, Version::V2)?;
    let ctx = dummy_ctx_action(name.clone());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    for i in 0i64..4 {
        let io = RefCell::new(TestIO::new());
        let mut published = Vec::new();
        let mut rs = machine.create_run_state(&io, ctx.clone());
        call_action(&mut rs, &mut published, name.clone(), [i])?.success();
        drop(rs);

        let s = Value::String(i.to_string().try_into().unwrap());
        assert_eq!(published, [vm_struct!(Result { s: s })]);
    }

    Ok(())
}

#[test]
fn test_match_first() -> anyhow::Result<()> {
    let name = ident!("foo");
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);

    call_action(&mut rs, &mut published, name, [5])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 5 })]);

    Ok(())
}

#[test]
fn test_match_second() -> anyhow::Result<()> {
    let name = ident!("foo");
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());

    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, [6])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 6 })]);

    Ok(())
}

#[test]
fn test_match_default_2() -> anyhow::Result<()> {
    let name = ident!("foo");
    let policy = parse_policy_str(POLICY_MATCH, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name.clone());

    let mut rs = machine.create_run_state(&io, ctx);
    let mut published = Vec::new();
    call_action(&mut rs, &mut published, name, [100])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 100 + 1 })]);

    Ok(())
}

#[test]
fn test_match_alternation() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return todo() }
            open { return todo() }
        }

        action foo(x int) {
            match x {
                0 | 1 => {
                    check false
                }
                5 | 6 | 7 => {
                    publish Result { x: x }
                }
                _ => {}
            }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let action_name = ident!("foo");
    let ctx = dummy_ctx_action(action_name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, action_name, [Value::Int(6)])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 6 })]);
    Ok(())
}

#[test]
fn test_match_default() -> anyhow::Result<()> {
    let policy_str = r#"
        command Result {
            fields {
                x int
            }
            seal { return todo() }
            open { return todo() }
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
    let name = ident!("foo");
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, [Value::Int(6)])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 0 })]);

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
                _ => { return 0 }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let name = ident!("foo");
    let ctx = dummy_ctx_action(name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action(name, [42])?.success();

    Ok(())
}

#[test]
fn test_match_expression() -> anyhow::Result<()> {
    let text = r#"
        command F {
            fields { x int }
            seal { return todo() }
            open { return todo() }
        }
        action foo(x int) {
            let y = match x {
                0 => { :1 }
                _ => { :0 }
            }
            publish F { x: y }
        }
    "#;
    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let name = ident!("foo");
    let mut rs = machine.create_run_state(&io, dummy_ctx_action(name.clone()));

    let expectations = vec![(0, 1), (1, 0), (2, 0)];
    for (arg, expected) in expectations {
        call_action(&mut rs, &mut published, name.clone(), [Value::Int(arg)])?.success();
        assert_eq!(published, [vm_struct!(F { x: expected })],);
        published.clear();
    }
    Ok(())
}

#[test]
fn test_is_some_statement() -> anyhow::Result<()> {
    let name = ident!("check_none");
    let policy = parse_policy_str(POLICY_IS, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());

    // Test with a value that is not None
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, [Value::Int(10)])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Result { x: 10 })],);

    Ok(())
}

#[test]
fn test_is_none_statement() -> anyhow::Result<()> {
    let name = ident!("check_none");
    let policy = parse_policy_str(POLICY_IS, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let ctx = dummy_ctx_action(name.clone());

    // Test with a None value
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, [Value::None])?.success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Empty {})],);

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
    let name = ident!("foo");
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name.clone());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let mut rs = machine.create_run_state(&io, ctx);
    rs.call_action(name, [true, false])?.success();

    Ok(())
}

#[test]
fn test_pure_function() -> anyhow::Result<()> {
    let text = r#"
        command Result {
            fields {
                x int
            }
            seal { return todo() }
            open { return todo() }
        }

        function f(x int) int {
            return unwrap add(x, 1)
        }

        action foo(x int) {
            publish Result { x: f(x) }
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    {
        let name = ident!("foo");
        let ctx = dummy_ctx_action(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        call_action(&mut rs, &mut published, name, [3])?.success();
    }

    assert_eq!(published, [vm_struct!(Result { x: 4 })],);

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

            seal { return todo() }
            open { return todo() }

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
        let name = ident!("Foo");
        let ctx = dummy_ctx_policy(name.clone());
        let self_struct = Struct::new(name, [KVPair::new(ident!("x"), Value::Int(3))]);
        machine
            .call_command_policy(self_struct, dummy_envelope(), &io, ctx)?
            .success();
    }

    assert_eq!(
        io.borrow().effect_stack[0],
        (
            ident!("Result"),
            vec![KVPair::new(ident!("x"), Value::Int(3)),]
        )
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
        ident!("Foo"),
        [
            KVPair::new(ident!("a"), Value::Int(1)),
            KVPair::new(ident!("b"), Value::String(text!("foo"))),
        ],
    );

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let name = ident!("Foo");
    let this_bytes: Vec<u8> = {
        let ctx = dummy_ctx_seal(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_seal(this_struct.clone())?.success();
        let result = rs.consume_return()?;
        let mut envelope: Struct = result.try_into()?;
        let payload = envelope
            .fields
            .remove("payload")
            .expect("envelope has no payload");
        payload.try_into()?
    };

    {
        let ctx = dummy_ctx_open(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        // call_open expects an envelope struct, so we smuggle the bytes
        // in through a field. The payload would normally be accessed
        // through an FFI module.
        let envelope = Struct::new(
            ident!("Env"),
            [KVPair::new(ident!("payload"), Value::Bytes(this_bytes))],
        );
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
                return todo()
            }
            open {
                return todo()
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
        let cmd_name = ident!("Setup");
        let this_data = Struct {
            name: cmd_name.clone(),
            fields: [].into(),
        };

        let ctx = dummy_ctx_policy(cmd_name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(this_data, dummy_envelope())?
            .success();
    }

    {
        let action_name = ident!("test_existing");
        let ctx = dummy_ctx_action(action_name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())?
            .success();
    }

    {
        let action_name = ident!("test_nonexistent");
        let ctx = dummy_ctx_action(action_name.clone());
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
            seal { return todo() }
            open { return todo() }

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
        let name = ident!("Foo");
        let ctx = dummy_ctx_policy(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_policy(
            Struct::new(
                ident!("Foo"),
                [KVPair::new(ident!("test"), test_data.clone().into())],
            ),
            Struct::new(
                ident!("Envelope"),
                [KVPair::new(ident!("payload"), test_data.clone().into())],
            ),
        )?
        .success();
    }

    {
        let name = ident!("Foo");
        let ctx = dummy_ctx_recall(name);
        let mut rs = machine.create_run_state(&io, ctx);
        rs.call_command_recall(
            Struct::new(
                ident!("Foo"),
                [KVPair::new(ident!("test"), test_data.clone().into())],
            ),
            Struct::new(
                ident!("Envelope"),
                [KVPair::new(ident!("payload"), test_data.into())],
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
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let module = Compiler::new(&policy).debug(true).compile()?;
    let machine = Machine::from_module(module)?;

    fn run_action(
        machine: &Machine,
        io: &RefCell<TestIO>,
        action_name: Identifier,
    ) -> Result<ExitReason, MachineError> {
        let ctx = dummy_ctx_action(action_name.clone());
        let mut rs = machine.create_run_state(io, ctx);
        rs.call_action(action_name, iter::empty::<Value>())
    }

    assert_eq!(
        run_action(&machine, &io, ident!("test_debug_assert_failure"))?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(
            &machine,
            &io,
            ident!("test_debug_assert_failure_expression")
        )?,
        ExitReason::Panic
    );

    assert_eq!(
        run_action(&machine, &io, ident!("test_debug_assert_pass"))?,
        ExitReason::Normal
    );

    let module_no_debug = Compiler::new(&policy).debug(false).compile()?;
    let machine_no_debug = Machine::from_module(module_no_debug)?;

    let test_names = vec![
        ident!("test_debug_assert_failure"),
        ident!("test_debug_assert_failure_expression"),
        ident!("test_debug_assert_pass"),
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
            seal { return todo() }
            open { return todo() }
        }

        action foo() {
            let a = unwrap add(x, 1)
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
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    // Check if the global variables are defined correctly in the machine
    assert_eq!(machine.globals, {
        BTreeMap::from([
            (
                ident!("d"),
                Value::Struct(Struct {
                    name: ident!("Bar"),
                    fields: BTreeMap::from([
                        (
                            ident!("a"),
                            Value::Struct(Struct {
                                name: ident!("Far"),
                                fields: BTreeMap::from([(ident!("a"), Value::Int(3))]),
                            }),
                        ),
                        (ident!("b"), Value::String(text!("y"))),
                        (ident!("c"), Value::Bool(false)),
                    ]),
                }),
            ),
            (ident!("x"), Value::Int(42)),
            (ident!("y"), Value::String(text!("hello world"))),
            (ident!("z"), Value::Bool(true)),
        ])
    });

    let name = ident!("foo");
    let ctx = dummy_ctx_action(name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(&mut rs, &mut published, name, iter::empty::<Value>())?.success();
    drop(rs);

    // Check if the published struct is correct
    assert_eq!(
        published,
        [vm_struct!(Result {
            a: 43,
            b: text!("hello world"),
            c: false,
            d: vm_struct!(Bar {
                a: vm_struct!(Far { a: 3 }),
                b: text!("y"),
                c: false,
            }),
        })]
    );

    Ok(())
}

#[test]
fn test_enum_reference() -> anyhow::Result<()> {
    let text = r#"
        command Sip {
            seal { return todo() }
            open { return todo() }
            fields {
                a string
            }
        }

        enum Drink {
            Water, Coffee
        }

        action test(type enum Drink) {
            match type {
                Drink::Water => {
                    publish Sip { a: "bleh" }
                }
                Drink::Coffee => {
                    publish Sip { a: "mmm" }
                }
            }
        }


    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let name = ident!("test");
    let ctx = dummy_ctx_action(name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(
        &mut rs,
        &mut published,
        name,
        [machine
            .parse_enum("Drink::Coffee")
            .expect("enum ref is valid")],
    )?
    .success();

    drop(rs);

    assert_eq!(published, [vm_struct!(Sip { a: text!("mmm") })],);

    Ok(())
}

fn call_action<M, Args>(
    rs: &mut RunState<'_, M>,
    published: &mut Vec<Struct>,
    name: Identifier,
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
        published.push(command_struct);
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
        Value::Enum(ident!("Drink"), 0)
    );
    assert_eq!(
        machine.parse_enum("Drink::Coffee")?,
        Value::Enum(ident!("Drink"), 1)
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
seal { return todo() }
open { return todo() }
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
seal { return todo() }
open { return todo() }
policy {
    finish {
        delete Foo[]
    }
}
}

command Increment {
fields {}
seal { return todo() }
open { return todo() }
policy {
    let r = unwrap query Foo[]=>{x: ?}
    let new_x = unwrap add(r.x, 1)
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
fn test_map() -> anyhow::Result<()> {
    let text = r#"
        fact F[i int]=>{n int}
        effect Result {
            value int
        }

        command Setup {
            open { return todo() }
            seal { return todo() }
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
            open { return todo() }
            seal { return todo() }
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
    let mut published = Vec::new();

    // Empty results. Run test without creating facts.
    {
        let name = ident!("test");
        let ctx = dummy_ctx_action(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let prev_stack_depth = rs.stack.len();
        call_action(&mut rs, &mut published, name, iter::empty::<Value>())?.success();

        // Make sure we didn't leave any trailing values on the stack
        let stack = rs.stack.into_vec();
        assert_eq!(stack.len(), prev_stack_depth);
        assert!(published.is_empty());
    }

    // Test with some data
    {
        let name = ident!("Setup");
        let ctx = dummy_ctx_policy(name.clone());
        let mut rs = machine.create_run_state(&io, ctx);
        let self_struct = Struct::new(name, &[]);
        rs.call_command_policy(self_struct, dummy_envelope())?
            .success();
    }
    {
        // Create a new scope so that the Runstate is fully dropped
        // before io.borrow().publish_stack is accessed
        {
            let name = ident!("test");
            let ctx = dummy_ctx_action(name.clone());
            let mut rs = machine.create_run_state(&io, ctx);
            let prev_stack_depth = rs.stack.len();
            call_action(&mut rs, &mut published, name, iter::empty::<Value>())?.success();

            // Make sure we didn't leave any trailing values on the stack
            let stack = rs.stack.into_vec();
            assert_eq!(stack.len(), prev_stack_depth);
        }

        // Assert we iterated as many times as expected, and with the correct results each time.
        let expected = [1, 2, 3].map(|value| vm_struct!(Process { value: value }));
        assert_eq!(published, expected);
    }
    Ok(())
}

#[test]
fn test_optional_type_validation() -> anyhow::Result<()> {
    let text = r#"
        command TypeValidation {
            fields {
                maybe_int option[int],
                name string,
            }
            seal { return todo() }
            open { return todo() }
            policy {
                finish {}
            }
        }

        action type_validation(maybe_int_input option[int], name_input string) {
            publish TypeValidation{maybe_int: maybe_int_input, name: name_input}
        }
    "#;

    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;

    let cases = [
        (
            Ok(ExitReason::Normal),
            [
                KVPair::new(ident!("maybe_int"), Value::None),
                KVPair::new(ident!("name"), Value::String(text!("foo"))),
            ],
        ),
        (
            Ok(ExitReason::Normal),
            [
                KVPair::new(ident!("maybe_int"), Value::Int(5)),
                KVPair::new(ident!("name"), Value::String(text!("foo"))),
            ],
        ),
        (
            Err(MachineErrorType::invalid_type(
                "string",
                "None",
                "invalid function argument",
            )),
            [
                KVPair::new(ident!("maybe_int"), Value::None),
                KVPair::new(ident!("name"), Value::None),
            ],
        ),
    ];

    for case in cases {
        let (expected, args) = case;

        // action call validation
        {
            let name = ident!("type_validation");
            let ctx = dummy_ctx_action(name.clone());
            let mut rs = machine.create_run_state(&io, ctx);
            let action_args = args.iter().map(KVPair::value).cloned();

            assert_eq!(
                call_action(&mut rs, &mut published, name.clone(), action_args)
                    .map_err(|e| e.err_type),
                expected
            );
        }

        // command call validation
        {
            let name = ident!("TypeValidation");
            let ctx = dummy_ctx_policy(name.clone());
            let mut rs = machine.create_run_state(&io, ctx);

            assert_eq!(
                rs.call_command_policy(Struct::new(name.clone(), args), dummy_envelope())
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

            seal { return todo() }
            open { return todo() }

            policy {
            }
        }

        action test() {
            let a = 3
            let b = 4
            let x = {
                let c = 5
                : saturating_add(saturating_add(a, b), c)
            }

            publish TestCommand {
                x: x
            }
        }
    "#
    .trim();

    let policy = parse_policy_str(policy_text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let module = Compiler::new(&policy)
        .ffi_modules(TestIO::FFI_SCHEMAS)
        .compile()?;
    let machine = Machine::from_module(module)?;
    let name = ident!("test");
    let args: [Value; 0] = [];
    let ctx = dummy_ctx_action(name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    let r = call_action(&mut rs, &mut published, name, args)?;
    assert_eq!(r, ExitReason::Normal);

    assert_eq!(published, [vm_struct!(TestCommand { x: 12 })]);

    Ok(())
}

#[test]
fn test_substruct_happy_path() -> anyhow::Result<()> {
    let policy_str = r#"
        command Foo {
            fields {
                x int,
                y bool,
            }
            seal { return todo() }
            open { return todo() }
        }
        struct Bar {
            x int,
            y bool,
            z string,
        }
        action baz(source struct Bar) {
            publish source substruct Foo
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let action_name = ident!("baz");
    let ctx = dummy_ctx_action(action_name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(
        &mut rs,
        &mut published,
        action_name,
        [Value::Struct(Struct::new(
            ident!("Bar"),
            [
                (ident!("x"), Value::Int(30)),
                (ident!("y"), Value::Bool(false)),
                (ident!("z"), Value::String(text!("lorem"))),
            ],
        ))],
    )?
    .success();
    drop(rs);

    assert_eq!(published, [vm_struct!(Foo { x: 30, y: false })]);
    Ok(())
}

#[test]
fn test_struct_composition() -> anyhow::Result<()> {
    let policy_str = r#"
        command Foo {
            fields {
                x int,
                y bool,
                z string,
            }
            seal { return todo() }
            open { return todo() }
        }
        struct Bar {
            x int,
            y bool,
            z string,
        }
        action baz(source struct Bar, x int) {
            publish Foo { x: x, ...source }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let mut published = Vec::new();
    let action_name = ident!("baz");
    let ctx = dummy_ctx_action(action_name.clone());
    let mut rs = machine.create_run_state(&io, ctx);
    call_action(
        &mut rs,
        &mut published,
        action_name,
        [
            Value::Struct(Struct::new(
                ident!("Bar"),
                [
                    (ident!("x"), Value::Int(30)),
                    (ident!("y"), Value::Bool(false)),
                    (ident!("z"), Value::String(text!("lorem"))),
                ],
            )),
            Value::Int(10),
        ],
    )?
    .success();
    drop(rs);

    let lorem = Value::String(text!("lorem"));

    assert_eq!(
        published,
        [vm_struct!(Foo {
            x: 10,
            y: false,
            z: lorem,
        })]
    );
    Ok(())
}

#[test]
fn test_boolean_operators() {
    fn check(expr: &str) {
        let policy = parse_policy_str(&format!("action f() {{ check {expr} }}"), Version::V2)
            .expect("parse");
        let module = Compiler::new(&policy).compile().expect("compile");
        let machine = Machine::from_module(module).expect("machine");
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_action(ident!("f"));
        let mut rs = machine.create_run_state(&io, ctx);
        let exit = rs
            .call_action(ident!("f"), iter::empty::<Value>())
            .expect("action runs");
        assert_eq!(exit, ExitReason::Normal);
        assert!(rs.stack.is_empty());
    }

    check("true && true");
    check("!(true && false)");
    check("!(false && true)");
    check("!(false && false)");

    check("!(false || false)");
    check("true || false");
    check("false || true");
    check("true || true");
}

#[test]
fn test_boolean_short_circuit() {
    fn run(expr: &str) -> ExitReason {
        let policy = parse_policy_str(&format!("action f() {{ check {expr} }}"), Version::V2)
            .expect("parse");
        let module = Compiler::new(&policy)
            .debug(true)
            .compile()
            .expect("compile");
        let machine = Machine::from_module(module).expect("machine");
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_action(ident!("f"));
        let mut rs = machine.create_run_state(&io, ctx);

        let exit = rs
            .call_action(ident!("f"), iter::empty::<Value>())
            .expect("action runs");
        assert!(rs.stack.is_empty());
        exit
    }

    assert_eq!(run("true && todo()"), ExitReason::Panic);
    assert_eq!(run("false && todo()"), ExitReason::Check);
    assert_eq!(run("true || todo()"), ExitReason::Normal);
    assert_eq!(run("false || todo()"), ExitReason::Panic);
}

#[test]
fn test_comparison_operators() {
    fn check(expr: &str) {
        let policy = parse_policy_str(&format!("action f() {{ check {expr} }}"), Version::V2)
            .expect("parse");
        let module = Compiler::new(&policy).compile().expect("compile");
        let machine = Machine::from_module(module).expect("machine");
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_action(ident!("f"));
        let mut rs = machine.create_run_state(&io, ctx);
        let exit = rs
            .call_action(ident!("f"), iter::empty::<Value>())
            .expect("action runs");
        assert_eq!(exit, ExitReason::Normal);
        assert!(rs.stack.is_empty());
    }

    check("1 < 2");
    check("1 <= 2");
    check("!(1 > 2)");
    check("!(1 >= 2)");

    check("2 > 1");
    check("2 >= 1");
    check("!(2 < 1)");
    check("!(2 <= 1)");
}

#[test]
fn test_struct_conversion() -> anyhow::Result<()> {
    let policy = r#"
        struct Foo { y string, x int }

        command Bar {
            fields { x int, y string }
            seal { return todo() }
            open { return todo() }
        }

        function new_foo(x int, y string) struct Foo {
            return Foo { y:y, x: x }
        }

        action test() {
            let foo = Foo { y: "abc", x: 42 }
            publish foo as Bar // var reference
            publish Foo { y: "b", x: 1 } as Bar // struct literal
            publish new_foo(5, "def") as Bar // function return value
            publish Bar { x: 100, y: "xyz" } as Bar
        }
        "#;

    let policy = parse_policy_str(policy, Version::V2)?;
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(ident!("test"));
    let mut rs = machine.create_run_state(&io, ctx);
    let mut published = Vec::new();
    let _ = call_action(
        &mut rs,
        &mut published,
        ident!("test"),
        iter::empty::<Value>(),
    )?;
    assert_eq!(
        published[0],
        vm_struct!(Bar {
            x: Value::Int(42),
            y: Value::String(text!("abc")),
        })
    );
    assert_eq!(
        published[1],
        vm_struct!(Bar {
            x: Value::Int(1),
            y: Value::String(text!("b")),
        })
    );
    assert_eq!(
        published[2],
        vm_struct!(Bar {
            x: Value::Int(5),
            y: Value::String(text!("def")),
        })
    );
    assert_eq!(
        published[3],
        vm_struct!(Bar {
            x: Value::Int(100),
            y: Value::String(text!("xyz")),
        })
    );
    Ok(())
}

#[test]
fn test_source_lookup() -> anyhow::Result<()> {
    let text = r#"
        action foo() {
            check true
            // before
            check false
            // after
            check true
        }
    "#;

    let name = ident!("foo");
    let policy = parse_policy_str(text, Version::V2)?;
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action(name.clone());
    let module = Compiler::new(&policy).compile()?;
    let machine = Machine::from_module(module)?;
    let mut rs = machine.create_run_state(&io, ctx);

    let result = rs.call_action(name, iter::empty::<Value>())?;
    assert_eq!(result, ExitReason::Check);

    let source = rs.source_location().expect("could not get source location");
    assert_eq!(
        source,
        concat!(
            "at row 5 col 13:\n",
            "\tcheck false\n",
            "            // after\n",
            "            "
        )
    );

    Ok(())
}
