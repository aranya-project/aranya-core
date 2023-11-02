#![cfg(test)]
#![allow(clippy::unwrap_used)]

extern crate alloc;
use alloc::collections::{btree_map, BTreeMap};
use core::fmt;

use crypto::{DefaultCipherSuite, DefaultEngine, Engine, Id, Rng};
use policy_ast::{self as ast, Version};
use policy_lang::lang::parse_policy_str;

use crate::{
    compile::CompileError,
    compile_from_policy,
    data::{
        CommandContext, Fact, FactKey, FactKeyList, FactValue, FactValueList, KVPair, Struct, Value,
    },
    error::MachineErrorType,
    ffi::{self, FfiModule},
    instructions::Instruction,
    io::{MachineIO, MachineIOError},
    machine::{Machine, MachineStatus, RunState},
    stack::Stack,
    CodeMap, Label, LabelType, MachineError, Target,
};

struct TestIO {
    facts: BTreeMap<(String, FactKeyList), FactValueList>,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    effect_stack: Vec<(String, Vec<KVPair>)>,
    modules: Vec<PrintFfi>,
    engine: DefaultEngine<Rng, DefaultCipherSuite>,
}

impl fmt::Debug for TestIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // I don't want to dive deep into the modules, so let's just list the module names.
        // But also the module names is in an unmerged PR, so punt and just enumerate them.
        let module_names: Vec<String> = self
            .modules
            .iter()
            .enumerate()
            .map(|(i, _)| format!("module {}", i))
            .collect();
        f.debug_struct("TestIO")
            .field("facts", &self.facts)
            .field("emit_stack", &self.emit_stack)
            .field("effect_stack", &self.effect_stack)
            .field("modules", &module_names)
            .finish()
    }
}

impl TestIO {
    pub fn new() -> Self {
        let (engine, _) = DefaultEngine::from_entropy(Rng);
        TestIO {
            facts: BTreeMap::new(),
            emit_stack: vec![],
            effect_stack: vec![],
            modules: Vec::new(),
            engine,
        }
    }
}

struct TestQueryIterator {
    name: String,
    key: FactKeyList,
    iter: btree_map::IntoIter<(String, FactKeyList), FactValueList>,
}

/// Calculates whether the k/v pairs in a exist in b
fn subset_key_match(a: &[FactKey], b: &[FactKey]) -> bool {
    for entry in a {
        if !b.iter().any(|e| entry == e) {
            return false;
        }
    }
    true
}

impl Iterator for TestQueryIterator {
    type Item = (FactKeyList, FactValueList);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .filter(|((n, k), _)| *n == self.name && subset_key_match(k, &self.key))
            .map(|((_, k), v)| (k, v))
    }
}

impl<S> MachineIO<S> for TestIO
where
    S: Stack,
{
    type QueryIterator = TestQueryIterator;

    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let value: Vec<_> = value.into_iter().collect();
        println!("fact insert {}[{:?}]=>{{{:?}}}", name, key, value);
        match self.facts.entry((name, key)) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            btree_map::Entry::Occupied(_) => Err(MachineIOError::FactExists),
        }
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("fact delete {}[{:?}]", name, key);
        match self.facts.entry((name, key)) {
            btree_map::Entry::Vacant(_) => Err(MachineIOError::FactNotFound),
            btree_map::Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            }
        }
    }

    fn fact_query(
        &self,
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("query {}[{:?}]", name, key);
        Ok(TestQueryIterator {
            name,
            key,
            iter: self.facts.clone().into_iter(),
        })
    }

    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort_by(|a, b| a.key().cmp(b.key()));
        println!("emit {} {{{:?}}}", name, fields);
        self.emit_stack.push((name, fields));
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort_by(|a, b| a.key().cmp(b.key()));
        println!("effect {} {{{:?}}}", name, fields);
        self.effect_stack.push((name, fields));
    }

    fn call(&mut self, module: usize, procedure: usize, stack: &mut S) -> Result<(), MachineError> {
        let mut ctx = CommandContext {
            name: "SomeCommand",
            id: Id::default(),
            author: Id::default().into(),
            version: Id::default(),
            engine: &mut self.engine,
        };
        match self.modules.get_mut(module) {
            Some(module) => module.call(procedure, stack, &mut ctx),
            None => Err(MachineError::new(MachineErrorType::FfiCall)),
        }
    }
}

#[test]
fn test_compile() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        command Foo {
            fields {}
        }
        action foo(b int) {
            let x = if b == 0 then 4+i else 3
            let y = Foo{
                a: x,
                b: 4
            }
        }
    "#
        .trim(),
        Version::V3,
    )
    .map_err(anyhow::Error::msg)?;

    compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    Ok(())
}

const TEST_POLICY_1: &str = r#"
effect Bar {
    x int
}

command Foo {
    fields {
        a int,
        b int,
    }
    policy {
        let sum = this.a + this.b
        finish {
            effect Bar{x: sum}
        }
    }
}

action foo(b int) {
    let x = if b == 0 then 4 else 3
    let y = Foo{
        a: x,
        b: 4
    }
    emit y
}
"#;

#[test]
fn test_action() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let mut rs = RunState::new(&machine, &mut io);

    rs.call_action("foo", &[Value::from(3), Value::from("foo")])
        .map_err(anyhow::Error::msg)?;

    println!("emit stack: {:?}", io.emit_stack);

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let mut rs = RunState::new(&machine, &mut io);

    let self_data = Struct {
        name: String::from("Bar"),
        fields: vec![
            (String::from("a"), Value::Int(3)),
            (String::from("b"), Value::Int(4)),
        ]
        .into_iter()
        .collect(),
    };
    rs.call_command_policy("Foo", &self_data)
        .expect("Could not call command policy");

    println!("effects: {:?}", io.effect_stack);

    Ok(())
}

const TEST_POLICY_2: &str = r#"
fact Foo[]=>{x int}
effect Update {
    value int
}

command Set {
    fields {
        a int,
    }
    policy {
        let x = this.a
        finish {
            create Foo[]=>{x: x}
            effect Update{value: x}
        }
    }
}

command Clear {
    fields {}
    policy {
        finish {
            delete Foo[]
        }
    }
}

command Increment {
    fields {}
    policy {
        let r = unwrap query Foo[]=>{x: ?}
        let new_x = r.x + 1
        finish {
            update Foo[]=>{x: r.x} to {x: new_x}
            effect Update{value: new_x}
        }
    }
}
"#;

#[test]
fn test_fact_create_delete() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();

    // We have to scope the RunState so that it and its mutable
    // reference to IO is dropped before we inspect the IO struct.
    {
        let mut rs = RunState::new(&machine, &mut io);
        let self_struct = Struct::new("Set", &[(KVPair::new_int("a", 3))]);
        rs.call_command_policy("Set", &self_struct)
            .map_err(anyhow::Error::msg)?;
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(3))];
    assert_eq!(io.facts[&fk], fv);

    {
        let mut rs = RunState::new(&machine, &mut io);
        let self_struct = Struct::new("Set", &[]);
        rs.call_command_policy("Clear", &self_struct)
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(io.facts.get(&fk), None);

    Ok(())
}

#[test]
fn test_fact_query() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
    println!("{}", machine);
    let mut io = TestIO::new();

    {
        let mut rs = RunState::new(&machine, &mut io);
        let self_struct = Struct::new("Set", &[KVPair::new_int("a", 3)]);
        rs.call_command_policy("Set", &self_struct)
            .map_err(anyhow::Error::msg)?;
        let self_struct = Struct::new("Increment", &[]);
        rs.call_command_policy("Increment", &self_struct)
            .map_err(anyhow::Error::msg)?;
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(4))];
    assert_eq!(io.facts[&fk], fv);

    Ok(())
}

#[test]
fn test_pop() {
    let machine = Machine::new([Instruction::Pop]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Add something to the stack
    rs.stack.push(5).unwrap();

    // Pop value
    assert!(
        rs.step().unwrap() == MachineStatus::Executing,
        "Still running"
    );
    assert!(rs.stack.is_empty(), "Stack is empty");

    // Try to pop from empty stack
    assert!(rs.step().is_err(), "Popping empty stack aborts");
}

#[test]
fn test_swap_empty() {
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Empty stack - should fail
    let result = rs.step();
    assert!(result.is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_swap_top() {
    let machine = Machine::new([
        // Swap with self (first) - should fail
        Instruction::Swap(0),
    ]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    rs.stack.push(5).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::InvalidInstruction));
}

#[test]
fn test_swap_middle() {
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Swap with second - should succeed
    rs.stack.push(3).unwrap();
    rs.stack.push(5).unwrap();
    rs.stack.push(8).unwrap();
    assert!(rs.step().unwrap() == MachineStatus::Executing);
    assert!(rs.stack.0[0] == Value::Int(3));
    assert!(rs.stack.0[1] == Value::Int(8));
    assert!(rs.stack.0[2] == Value::Int(5));
}

#[test]
fn test_dup_underflow() {
    let machine = Machine::new([Instruction::Dup(2)]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Try to dup with invalid stack index - should fail
    rs.stack.push(3).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_dup() {
    let machine = Machine::new([Instruction::Dup(1)]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Dup second value in stack - should succeed.
    rs.stack.push(3).unwrap();
    rs.stack.push(5).unwrap();
    assert!(rs.step().unwrap() == MachineStatus::Executing);
    assert!(rs.stack.len() == 3);
    assert!(rs.stack.0[0] == Value::Int(3));
    assert!(rs.stack.0[1] == Value::Int(5));
    assert!(rs.stack.0[2] == Value::Int(3));
}

#[test]
fn test_add() {
    // expect t.0+t.1==t.2
    let tups: [(i64, i64, i64); 5] = [
        (5, 3, 8),
        (5, 8, 13),
        (-10, 8, -2),
        (-10, -5, -15),
        (-10, 20, 10),
    ];

    for t in tups.iter() {
        let machine = Machine::new([Instruction::Add]);
        let mut io = TestIO::new();
        let mut rs = machine.create_run_state(&mut io);

        // adds t.0+t.1
        rs.stack.push(t.0).unwrap();
        rs.stack.push(t.1).unwrap();
        assert!(rs.step().unwrap() == MachineStatus::Executing);
        assert!(rs.stack.len() == 1);
        assert_eq!(rs.stack.0[0], Value::Int(t.2));
    }
}

#[test]
fn test_add_overflow() {
    // add p.0+p.1
    // we expect all these pairs to overflow
    let pairs: [(i64, i64); 3] = [
        (i64::MAX, 2),
        (1, i64::MAX),
        (i64::MAX / 2, (i64::MAX / 2) + 2),
    ];

    for p in pairs.iter() {
        let machine = Machine::new([Instruction::Add]);
        let mut io = TestIO::new();
        let mut rs = machine.create_run_state(&mut io);

        rs.stack.push(p.0).unwrap();
        rs.stack.push(p.1).unwrap();
        let step = rs.step();
        assert!(step.is_err());
        assert_eq!(
            step.unwrap_err().err_type,
            MachineErrorType::IntegerOverflow
        );
    }
}

#[test]
fn test_sub() {
    // expect t.0-t.1==t.2
    let tups: [(i64, i64, i64); 4] = [(5, 3, 2), (5, 8, -3), (-10, 8, -18), (-10, -5, -5)];

    for t in tups.iter() {
        let machine = Machine::new([Instruction::Sub]);
        let mut io = TestIO::new();
        let mut rs = machine.create_run_state(&mut io);

        // sub t.0-t.1
        rs.stack.push(t.0).unwrap();
        rs.stack.push(t.1).unwrap();
        assert!(rs.step().unwrap() == MachineStatus::Executing);
        assert!(rs.stack.len() == 1);
        assert_eq!(rs.stack.0[0], Value::Int(t.2));
    }
}

#[test]
fn test_sub_overflow() {
    // pairs to check, in the format p.0-p.1
    // we expect all these pairs to overflow
    let pairs: [(i64, i64); 5] = [
        (i64::MIN, 1),
        (i64::MIN, 2),
        (i64::MIN / 2, (i64::MAX / 2) + 2),
        ((i64::MAX / 2) + 2, i64::MIN / 2),
        (i64::MAX, -1),
    ];

    for p in pairs.iter() {
        let machine = Machine::new([Instruction::Sub]);
        let mut io = TestIO::new();
        let mut rs = machine.create_run_state(&mut io);

        rs.stack.push(p.0).unwrap();
        rs.stack.push(p.1).unwrap();
        let step = rs.step();
        assert!(step.is_err());
        assert_eq!(
            step.unwrap_err().err_type,
            MachineErrorType::IntegerOverflow
        );
    }
}

struct TestStack {
    stack: Vec<Value>,
}

impl TestStack {
    pub fn new() -> TestStack {
        TestStack { stack: vec![] }
    }
}

impl Stack for TestStack {
    fn push_value(&mut self, value: Value) -> Result<(), MachineErrorType> {
        self.stack.push(value);
        Ok(())
    }

    fn pop_value(&mut self) -> Result<Value, MachineErrorType> {
        self.stack.pop().ok_or(MachineErrorType::StackUnderflow)
    }

    fn peek_value(&mut self) -> Result<&mut Value, MachineErrorType> {
        self.stack
            .last_mut()
            .ok_or(MachineErrorType::StackUnderflow)
    }
}

#[test]
fn test_stack() -> anyhow::Result<()> {
    let mut s = TestStack::new();

    // Test pushing every type
    s.push(3).map_err(anyhow::Error::msg)?;
    s.push(true).map_err(anyhow::Error::msg)?;
    s.push("hello").map_err(anyhow::Error::msg)?;
    s.push(Struct::new("Foo", &[]))
        .map_err(anyhow::Error::msg)?;
    s.push(Fact::new("Bar".to_owned()))
        .map_err(anyhow::Error::msg)?;
    s.push_value(Value::None).map_err(anyhow::Error::msg)?;
    assert_eq!(
        s.stack,
        vec![
            Value::Int(3),
            Value::Bool(true),
            Value::String(String::from("hello")),
            Value::Struct(Struct::new("Foo", &[])),
            Value::Fact(Fact::new("Bar".to_owned())),
            Value::None,
        ]
    );

    // Test pop and peek
    let v = s.peek_value().map_err(anyhow::Error::msg)?;
    assert_eq!(v, &Value::None);
    let v = s.pop_value().map_err(anyhow::Error::msg)?;
    assert_eq!(v, Value::None);

    let v: &Fact = s.peek().map_err(anyhow::Error::msg)?;
    assert_eq!(v, &Fact::new("Bar".to_owned()));
    let v: Fact = s.pop().map_err(anyhow::Error::msg)?;
    assert_eq!(v, Fact::new("Bar".to_owned()));

    let v: &Struct = s.peek().map_err(anyhow::Error::msg)?;
    assert_eq!(v, &Struct::new("Foo", &[]));
    let v: Struct = s.pop().map_err(anyhow::Error::msg)?;
    assert_eq!(v, Struct::new("Foo", &[]));

    let v: &str = s.peek().map_err(anyhow::Error::msg)?;
    assert_eq!(v, "hello");
    let v: String = s.pop().map_err(anyhow::Error::msg)?;
    assert_eq!(v, "hello".to_owned());

    let v: &bool = s.peek().map_err(anyhow::Error::msg)?;
    assert_eq!(v, &true);
    let v: bool = s.pop().map_err(anyhow::Error::msg)?;
    assert!(v);

    let v: &i64 = s.peek().map_err(anyhow::Error::msg)?;
    assert_eq!(v, &3);
    let v: i64 = s.pop().map_err(anyhow::Error::msg)?;
    assert_eq!(v, 3);
    Ok(())
}

#[test]
fn test_bytes() -> anyhow::Result<()> {
    let text = r#"
        command Foo {
            fields {
                id id,
                x bytes,
            }
        }

        action foo(id id, x bytes) {
            emit Foo{id: id, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    {
        let mut rs = machine.create_run_state(&mut io);

        rs.call_action(
            "foo",
            &[
                Value::Bytes(vec![0xa, 0xb, 0xc]),
                Value::Bytes(vec![0, 255, 42]),
            ],
        )
        .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.emit_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new("id", Value::Bytes(vec![0xa, 0xb, 0xc])),
                KVPair::new("x", Value::Bytes(vec![0, 255, 42]))
            ]
        )
    );
    assert_eq!(
        format!("{}", io.emit_stack[0].1[0]),
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
        }

        action foo(id id, x int) {
            emit Foo{
                id: id,
                bar: Bar {
                    x: x
                },
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    assert_eq!(
        machine.struct_defs.get("Bar"),
        Some(&vec![ast::FieldDefinition {
            identifier: String::from("x"),
            field_type: ast::VType::Int
        }])
    );

    let mut io = TestIO::new();
    {
        let mut rs = machine.create_run_state(&mut io);
        rs.call_action("foo", &[Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.emit_stack[0],
        (
            "Foo".to_string(),
            vec![
                KVPair::new(
                    "bar",
                    Value::Struct(Struct::new("Bar", &[KVPair::new("x", Value::Int(3))]))
                ),
                KVPair::new("id", Value::Bytes(vec![0xa, 0xb, 0xc])),
            ]
        )
    );

    Ok(())
}

#[test]
fn test_undefined_struct() -> anyhow::Result<()> {
    let text = r#"
        action foo() {
            let v = Bar {}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    assert_eq!(
        compile_from_policy(&policy).unwrap_err(),
        CompileError::BadArgument
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    let mut io = TestIO::new();
    let err = {
        let mut rs = machine.create_run_state(&mut io);
        rs.call_action("foo", &[Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])
            .unwrap_err()
    };

    assert_eq!(
        err.err_type,
        MachineErrorType::InvalidStructMember(String::from("y")),
    );

    Ok(())
}

// --- FFI ---

struct PrintFfi {}

impl FfiModule for PrintFfi {
    type Error = MachineError;

    const TABLE: &'static [ffi::Func<'static>] = &[ffi::Func {
        name: "print",
        args: &[ffi::Arg {
            name: "s",
            vtype: ffi::Type::String,
        }],
        color: ffi::Color::Pure(ffi::Type::String),
    }];

    fn call<E: Engine + ?Sized>(
        &mut self,
        procedure: usize,
        stack: &mut impl Stack,
        _ctx: &mut CommandContext<'_, E>,
    ) -> Result<(), Self::Error> {
        match procedure {
            0 => {
                // pop args off the stack
                let s: String = stack.pop()?;

                // Push something (the uppercased value) back onto the stack so the caller can verify this function was called.
                stack
                    .push(Value::String(s.to_uppercase()))
                    .expect("can't push");

                Ok(())
            }
            _ => Err(MachineError::new(MachineErrorType::NotDefined(format!(
                "procedure {}",
                procedure
            )))),
        }
    }
}

#[test]
fn test_ffi() {
    // Add FFI module to TestIO
    let mut io = TestIO::new();
    io.modules.push(PrintFfi {});

    // Push value onto stack, and call FFI function
    let mut stack = TestStack::new();
    stack
        .push(Value::String("hello".to_string()))
        .expect("can't push");
    io.call(0, 0, &mut stack).expect("Should succeed");

    // Verify function was called
    assert!(stack.pop::<String>().expect("should have return value") == "HELLO");
}

#[test]
fn test_extcall() {
    let machine = Machine::new([
        Instruction::Const(Value::String("hi".to_string())),
        Instruction::ExtCall(0, 0),
        Instruction::Exit,
    ]);
    let mut io = TestIO::new();
    io.modules.push(PrintFfi {});
    let mut rs = machine.create_run_state(&mut io);

    rs.run().expect("Should succeed");

    // Verify we got expected return value
    let ret_val = rs
        .stack
        .peek_value()
        .expect("Should have return value on the stack");
    assert!(*ret_val == Value::String("HI".to_string()));
}

#[test]
fn test_extcall_invalid_module() {
    let machine = Machine::new([
        Instruction::Const(Value::String("hi".to_string())),
        Instruction::ExtCall(1, 0), // invalid module id
        Instruction::Exit,
    ]);
    let mut io = TestIO::new();
    io.modules.push(PrintFfi {});
    let mut rs = machine.create_run_state(&mut io);

    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::FfiCall)
    );
}

#[test]
fn test_extcall_invalid_proc() {
    let machine = Machine::new([
        Instruction::Const(Value::String("hi".to_string())),
        Instruction::ExtCall(0, 1), // invalid proc id
        Instruction::Exit,
    ]);
    let mut io = TestIO::new();
    io.modules.push(PrintFfi {});
    let mut rs = machine.create_run_state(&mut io);

    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::NotDefined(String::from("procedure 1")))
    );
}

#[test]
fn test_extcall_invalid_arg() {
    let machine = Machine::new([
        Instruction::Const(Value::Int(0)), // function expects string
        Instruction::ExtCall(0, 0),
        Instruction::Exit,
    ]);
    let mut io = TestIO::new();
    io.modules.push(PrintFfi {});
    let mut rs = machine.create_run_state(&mut io);

    // Empty stack - should fail
    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::InvalidType)
    );
}

#[test]
fn test_pure_function() -> anyhow::Result<()> {
    let text = r#"
        command Result {
            fields {
                x int
            }
        }

        function f(x int) int {
            return x + 1
        }

        action foo(x int) {
            emit Result { x: f(x) }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    let mut io = TestIO::new();
    {
        let mut rs = machine.create_run_state(&mut io);
        rs.call_action("foo", &[Value::Int(3)])
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.emit_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(4)),])
    );

    Ok(())
}

#[test]
fn test_function_no_return() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            let y = x + 1
            // no return value
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    assert_eq!(err, CompileError::NoReturn);

    Ok(())
}

#[test]
fn test_function_not_defined() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return g()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    assert_eq!(err, CompileError::NotDefined);

    Ok(())
}

#[test]
fn test_function_already_defined() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function f() int {}
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    assert_eq!(err, CompileError::AlreadyDefined);

    Ok(())
}

#[test]
fn test_function_wrong_number_arguments() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return 1
        }

        function g() int {
            return f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    assert_eq!(err, CompileError::BadArgument);

    Ok(())
}

#[test]
fn test_function_wrong_color_pure() -> anyhow::Result<()> {
    let text = r#"
        function f(x int) int {
            return x
        }

        finish function g() {
            f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    assert_eq!(err, CompileError::InvalidElement);

    Ok(())
}

#[test]
fn test_function_wrong_color_finish() -> anyhow::Result<()> {
    let text = r#"
        finish function f(x int) {
            effect Foo {}
        }

        function g() int {
            return f()
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let err = compile_from_policy(&policy).unwrap_err();

    // Quirk: this gives us NotDefined because the compiler compiles all of the regular
    // functions _before_ the finish functions. So the finish function isn't yet defined.
    // Fixing this will require a two-pass compilation.
    assert_eq!(err, CompileError::NotDefined);

    Ok(())
}

#[test]
fn test_finish_function() -> anyhow::Result<()> {
    let text = r#"
        effect Result {
            x int
        }

        finish function f(x int) {
            effect Result { x: x + 1 }
        }

        command Foo {
            fields {
                x int,
            }

            policy {
                finish {
                    f(this.x)
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    let mut io = TestIO::new();
    {
        let mut rs = machine.create_run_state(&mut io);
        let self_struct = Struct::new("Foo", &[KVPair::new("x", Value::Int(3))]);
        rs.call_command_policy("Foo", &self_struct)
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.effect_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(4)),])
    );

    Ok(())
}

#[test]
fn test_span_lookup() -> anyhow::Result<()> {
    let test_str = "I've got a lovely bunch of coconuts";
    let ranges = vec![(0, 8), (9, 23), (24, 34)];
    let mut cm = CodeMap::new(test_str, ranges);
    // instruction ranges are inclusive of the instruction, up until
    // the next instruction, and must be inserted in order. So the
    // first range is 0-11, the second is 12-21, etc.
    cm.map_instruction_range(0, 0).map_err(anyhow::Error::msg)?;
    cm.map_instruction_range(12, 9)
        .map_err(anyhow::Error::msg)?;
    cm.map_instruction_range(22, 24)
        .map_err(anyhow::Error::msg)?;

    // An instruction at the boundary returns the range starting
    // at that boundary.
    let s = cm.span_from_instruction(0).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 0);

    // An instruction between boundaries returns the range starting
    // at the last instruction boundary.
    let s = cm.span_from_instruction(3).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 0);

    let s = cm.span_from_instruction(12).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 9);

    let s = cm.span_from_instruction(21).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 9);

    let s = cm.span_from_instruction(22).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 24);

    // An instruction beyond the last instruction boundary always
    // returns the last range.
    let s = cm.span_from_instruction(30).map_err(anyhow::Error::msg)?;
    assert_eq!(s.start(), 24);

    Ok(())
}

fn general_test_harness<F, G>(
    instructions: &[Instruction],
    mut machine_closure: F,
    mut rs_closure: G,
) where
    F: FnMut(&mut Machine) -> anyhow::Result<()>,
    G: FnMut(&mut RunState<'_, TestIO>) -> anyhow::Result<()>,
{
    let mut m = Machine::new(instructions.to_owned());

    machine_closure(&mut m).unwrap();

    let mut io = TestIO::new();
    let mut rs = m.create_run_state(&mut io);
    rs_closure(&mut rs).unwrap();
}

fn error_test_harness(instructions: &[Instruction], error_type: MachineErrorType) {
    let m = Machine::new(instructions.to_owned());

    let mut io = TestIO::new();
    let mut rs = m.create_run_state(&mut io);
    assert_eq!(rs.run(), Err(MachineError::new(error_type)));
}

#[test]
// There are a lot of clones in here. Technically the last one isn't
// needed, but maintenance is easier when you don't need to worry about
// it.
#[allow(clippy::redundant_clone)]
fn test_errors() {
    let x = String::from("x");

    // StackUnderflow: Pop an empty stack
    error_test_harness(&[Instruction::Get], MachineErrorType::StackUnderflow);

    // StackOverflow untested as the stack has no maximum size

    // NotDefined: Get a name that isn't defined
    error_test_harness(
        &[
            Instruction::Const(Value::String(x.clone())),
            Instruction::Get,
        ],
        MachineErrorType::NotDefined(x.clone()),
    );

    // AlreadyDefined: Define a name twice
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::Dup(1),
            Instruction::Dup(1),
            Instruction::Def,
            Instruction::Def,
        ],
        MachineErrorType::AlreadyDefined(x.clone()),
    );

    // InvalidType: 3 > "x" (same case as 3 < "x")
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::Gt,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: 3 + "x" (same case as 3 - "x")
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::Add,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: 3 && "x"
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::And,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: !3
    error_test_harness(
        &[Instruction::Const(Value::Int(3)), Instruction::Not],
        MachineErrorType::InvalidType,
    );

    // InvalidType: Set a struct value on a thing that isn't a struct
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::StructSet,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: Set a fact key on a thing that isn't a fact
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::FactKeySet,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: Set a fact value on a thing that isn't a fact
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::FactValueSet,
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidType: Branch on a non-bool value
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Branch(Target::Unresolved(x.clone())),
        ],
        MachineErrorType::InvalidType,
    );

    // InvalidStructGet: Access `foo.x` when `x` is not a member of `foo`
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct::new("foo", &[]))),
            Instruction::Const(Value::String(x.clone())),
            Instruction::StructGet,
        ],
        MachineErrorType::InvalidStructMember(x.clone()),
    );

    // InvalidFact: Update a fact that does not exist
    error_test_harness(
        &[
            Instruction::Const(Value::Fact(Fact {
                name: x.clone(),
                keys: vec![],
                values: vec![],
            })),
            Instruction::Dup(0),
            Instruction::Update,
        ],
        MachineErrorType::InvalidFact,
    );

    // InvalidSchema: Emit a command that was not defined
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct {
                name: x.clone(),
                fields: BTreeMap::new(),
            })),
            Instruction::Emit,
        ],
        MachineErrorType::InvalidSchema,
    );

    // InvalidSchema: Produce an effect that was not defined
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct {
                name: x.clone(),
                fields: BTreeMap::new(),
            })),
            Instruction::Effect,
        ],
        MachineErrorType::InvalidSchema,
    );

    // UnresolvedTarget: Jump to an unresolved target
    error_test_harness(
        &[Instruction::Jump(Target::Unresolved(x.clone()))],
        MachineErrorType::UnresolvedTarget,
    );

    // InvalidAddress: Run empty program
    error_test_harness(&[], MachineErrorType::InvalidAddress);

    // InvalidAddress: Set PC to non-existent label
    general_test_harness(
        &[],
        |_| Ok(()),
        |rs| {
            let r = rs.set_pc_by_name("x", LabelType::Action);
            assert_eq!(r, Err(MachineError::new(MachineErrorType::InvalidAddress)));
            Ok(())
        },
    );

    // InvalidAddress: Set PC to a label of the wrong type
    general_test_harness(
        &[],
        |m| {
            m.labels.insert(
                x.clone(),
                Label {
                    addr: 0,
                    ltype: LabelType::Action,
                },
            );
            Ok(())
        },
        |rs| {
            let r = rs.set_pc_by_name("x", LabelType::Command);
            assert_eq!(r, Err(MachineError::new(MachineErrorType::InvalidAddress)));
            Ok(())
        },
    );

    // InvalidInstruction: Swap of depth zero
    error_test_harness(
        &[Instruction::Swap(0)],
        MachineErrorType::InvalidInstruction,
    );

    // IO: Delete a fact that does not exist
    error_test_harness(
        &[
            Instruction::Const(Value::Fact(Fact {
                name: x.clone(),
                keys: vec![],
                values: vec![],
            })),
            Instruction::Delete,
        ],
        MachineErrorType::IO(MachineIOError::FactNotFound),
    );

    // IO: Create a fact that already exists
    // This _should_ be failing because the fact has not been declared
    // in schema, but TestIO does not care about fact schema and the
    // machine does not check it.
    error_test_harness(
        &[
            Instruction::Const(Value::Fact(Fact {
                name: x.clone(),
                keys: vec![],
                values: vec![],
            })),
            Instruction::Dup(0),
            Instruction::Create,
            Instruction::Create,
        ],
        MachineErrorType::IO(MachineIOError::FactExists),
    );

    // Unknown untested as it cannot be created
}