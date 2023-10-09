extern crate alloc;
use alloc::collections::{btree_map, BTreeMap};

use anyhow;

use super::ffi::{FfiModule, ProcedureIdentifier};
use crate::lang::ast::{self, FfiFunctionDefinition, FieldDefinition, VType};
use crate::lang::{parse_policy_str, Version};
use crate::machine::{
    CompileError, Fact, FactKey, FactKeyList, FactValue, FactValueList, Instruction, KVPair,
    Machine, MachineError, MachineErrorType, MachineIO, MachineIOError, MachineStatus, RunState,
    Stack, Struct, Value,
};

struct TestIO<S>
where
    S: Stack,
{
    facts: BTreeMap<(String, FactKeyList), FactValueList>,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    effect_stack: Vec<(String, Vec<KVPair>)>,
    modules: Vec<Box<dyn FfiModule<S, Error = MachineError>>>,
}

impl<S> TestIO<S>
where
    S: Stack,
{
    pub fn new() -> Self {
        TestIO {
            facts: BTreeMap::new(),
            emit_stack: vec![],
            effect_stack: vec![],
            modules: Vec::new(),
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

impl<S> MachineIO<S> for TestIO<S>
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

    fn call(
        &self,
        procedure_id: ProcedureIdentifier,
        stack: &mut S,
    ) -> Result<(), super::MachineError> {
        let module = self
            .modules
            .get(procedure_id.module)
            .expect("Module not found");
        module.call(procedure_id.procedure, stack)
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

    Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

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

    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
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

    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
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

    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
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

    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
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
        .is_err_and(|result| result.err_type == MachineErrorType::BadState));
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
                id ID,
                x bytes,
            }
        }

        action foo(id ID, x bytes) {
            emit Foo{id: id, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;
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
                id ID,
                bar struct Bar,
            }
        }

        action foo(id ID, x int) {
            emit Foo{
                id: id,
                bar: Bar {
                    x: x
                },
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

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
        Machine::compile_from_policy(&policy).unwrap_err(),
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

        action foo(id ID, x int) {
            let v = Bar {
                y: x
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

    let mut io = TestIO::new();
    let err = {
        let mut rs = machine.create_run_state(&mut io);
        rs.call_action("foo", &[Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])
            .unwrap_err()
    };

    assert_eq!(
        err,
        MachineError::new_with_position(MachineErrorType::InvalidStruct, 9)
    );

    Ok(())
}

// --- FFI ---

struct PrintFFI {}

impl<S> FfiModule<S> for PrintFFI
where
    S: Stack,
{
    type Error = MachineError;

    fn function_table(&self) -> Vec<FfiFunctionDefinition> {
        vec![FfiFunctionDefinition {
            name: "print".to_string(),
            args: vec![FieldDefinition {
                identifier: "a".to_string(),
                field_type: VType::String,
            }],
        }]
    }

    fn call(&self, procedure: usize, stack: &mut S) -> Result<(), Self::Error> {
        match procedure {
            0 => {
                // pop args off the stack
                let a: String = stack.pop().unwrap_or_else(|_| panic!("Stack underflow"));
                println!("a: {}", a);

                // Push something (the uppercased value) back onto the stack so the caller can verify this function was called.
                stack
                    .push(Value::String(a.to_uppercase()))
                    .expect("can't push");

                Ok(())
            }
            _ => panic!("Invalid procedure."),
        }
    }
}

#[test]
fn test_ffi() {
    // Add FFI module to TestIO
    let mut io = TestIO::new();
    io.modules.push(Box::new(PrintFFI {}));

    // Push value onto stack, and call FFI function
    let mut stack = TestStack::new();
    stack
        .push(Value::String("hello".to_string()))
        .expect("can't push");
    let result = io.call(
        ProcedureIdentifier {
            module: 0,
            procedure: 0,
        },
        &mut stack,
    );

    // Verify function was called
    assert!(result.is_ok());
    assert!(stack.pop::<String>().expect("should have return value") == "HELLO");
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
    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let err = Machine::compile_from_policy(&policy).unwrap_err();

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
    let machine = Machine::compile_from_policy(&policy).map_err(anyhow::Error::msg)?;

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
