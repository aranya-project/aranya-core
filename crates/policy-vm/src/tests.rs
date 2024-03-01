#![cfg(test)]
#![allow(clippy::unwrap_used)]

extern crate alloc;
use alloc::collections::{btree_map, BTreeMap};
use core::fmt;

use crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Engine, Id, Rng,
};
use policy_ast::{self as ast, Version};
use policy_lang::lang::parse_policy_str;

use crate::{
    compile_from_policy,
    data::{
        CommandContext, Fact, FactKey, FactKeyList, FactValue, FactValueList, KVPair, Struct, Value,
    },
    error::MachineErrorType,
    ffi::{self, FfiModule, ModuleSchema},
    instructions::Instruction,
    io::{MachineIO, MachineIOError},
    machine::{Machine, MachineStatus, RunState},
    stack::Stack,
    ActionContext, CodeMap, CompileError, CompileErrorType, ExitReason, Label, LabelType,
    MachineError, OpenContext, PolicyContext, SealContext, Target,
};

struct TestIO {
    facts: BTreeMap<(String, FactKeyList), FactValueList>,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    effect_stack: Vec<(String, Vec<KVPair>)>,
    engine: DefaultEngine<Rng, DefaultCipherSuite>,
    print_ffi: PrintFfi,
}

impl fmt::Debug for TestIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let module_names = ["print"];
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
            engine,
            print_ffi: PrintFfi {},
        }
    }

    /// List of schemas for the FFI modules provided by this MachineIO implementation.
    pub const FFI_SCHEMAS: &'static [ModuleSchema<'static>] = &[PrintFfi::SCHEMA];
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

impl<S> MachineIO<S> for TestIO
where
    S: Stack,
{
    type QueryIterator<'c> = Box<dyn Iterator<Item=Result<(FactKeyList, FactValueList), MachineIOError>>> where Self: 'c;

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
    ) -> Result<Self::QueryIterator<'_>, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("query {}[{:?}]", name, key);
        let iter = self
            .facts
            .clone()
            .into_iter()
            .filter(move |f| f.0 .0 == name && subset_key_match(&f.0 .1, &key))
            .map(|((_, k), v)| Ok::<(FactKeyList, FactValueList), MachineIOError>((k, v)));

        Ok(Box::new(iter))
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
        &mut self,
        module: usize,
        procedure: usize,
        stack: &mut S,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError> {
        match module {
            0 => self.print_ffi.call(procedure, stack, ctx, &mut self.engine),
            _ => Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
                module,
            ))),
        }
    }
}

#[test]
fn test_compile() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        command Foo {
            fields {}
            seal { return None }
            open { return None }
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

    compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;

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
    seal { return None }
    open { return None }
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

fn dummy_ctx_action(name: &str) -> CommandContext<'_> {
    CommandContext::Action(ActionContext {
        name,
        head_id: Id::default(),
    })
}

fn dummy_ctx_seal(name: &str) -> CommandContext<'_> {
    CommandContext::Seal(SealContext {
        name,
        parent_id: Id::default(),
    })
}

fn dummy_ctx_open(name: &str) -> CommandContext<'_> {
    CommandContext::Open(OpenContext {
        name,
        parent_id: Id::default(),
    })
}

fn dummy_ctx_policy(name: &str) -> CommandContext<'_> {
    CommandContext::Policy(PolicyContext {
        name,
        id: Id::default(),
        author: Id::default().into(),
        version: Id::default(),
        parent_id: Id::default(),
    })
}

fn dummy_envelope() -> Struct {
    Struct {
        name: "Envelope".into(),
        fields: BTreeMap::new(),
    }
}

#[test]
fn test_action() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let name = "foo";
    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    machine
        .call_action(name, [Value::from(3), Value::from("foo")], &mut io, &ctx)
        .map_err(anyhow::Error::msg)?;

    println!("emit stack: {:?}", io.emit_stack);

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let name = "Foo";
    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
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
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let name = "Foo";
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
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

    assert_eq!(rs.stack.0[0], Value::None);

    Ok(())
}

#[test]
fn test_open() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let name = "Foo";
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let ctx = dummy_ctx_open(name);
    let mut io = TestIO::new();
    let mut rs = RunState::new(&machine, &mut io, &ctx);

    rs.call_open(name, dummy_envelope())
        .expect("Could not call command policy");

    assert_eq!(rs.stack.0[0], Value::None);

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
    seal { return None }
    open { return None }
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
            effect Update{value: new_x}
        }
    }
}

"#;

#[test]
fn test_fact_create_delete() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();

    // We have to scope the RunState so that it and its mutable
    // reference to IO is dropped before we inspect the IO struct.
    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [(KVPair::new_int("a", 3))]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)
            .map_err(anyhow::Error::msg)?;
    }

    let fk = ("Foo".to_owned(), vec![]);
    let fv = vec![FactValue::new("x", Value::Int(3))];
    assert_eq!(io.facts[&fk], fv);

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Set", &[]);
        machine
            .call_command_policy("Clear", &self_struct, dummy_envelope(), &mut io, &ctx)
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(io.facts.get(&fk), None);

    Ok(())
}

#[test]
fn test_fact_query() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_2.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();

    {
        let name = "Set";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, [KVPair::new_int("a", 3)]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)
            .map_err(anyhow::Error::msg)?;

        let name = "Increment";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new(name, &[]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)
            .map_err(anyhow::Error::msg)?;
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

        // NOTE: expressions with bind (?) values are commented out because we don't allow Bind values at the moment.

        // check exists Foo[] => {x: ?}
        // check exists Bar[i: ?] => {s: ?, b: ?}

        // Not-exists

        // no values

        // no such key
        //check !exists Foo[i: ?]

        // incomplete values
        // check !exists Bar[i: 0]=>{s: ?}

        // no fact with such values
        check !exists Bar[i:0] => {s:"ab", b:true}
        check !exists Bar[i:1] => {s:"", b:true}
        // check !exists Bar[i: ?]=>{s: "ab", b: ?}
    }
    "#;

    let policy = parse_policy_str(text.trim(), Version::V3).map_err(anyhow::Error::msg)?;

    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    {
        let name = "setup";
        let ctx = dummy_ctx_policy(name);
        let mut rs = RunState::new(&machine, &mut io, &ctx);
        let self_struct = Struct::new(name, &[]);
        let result = rs
            .call_command_policy(name, &self_struct, dummy_envelope())
            .map_err(anyhow::Error::msg)?;
        assert_eq!(result, ExitReason::Normal);
    }

    {
        let name = "testExists";
        let ctx = dummy_ctx_action(name);
        let mut rs = RunState::new(&machine, &mut io, &ctx);
        let result = rs.call_action(name, [false]).map_err(anyhow::Error::msg)?;
        assert_eq!(result, ExitReason::Normal);
    }

    Ok(())
}

#[test]
fn test_not_operator() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
        action test() {
            check !false
        }
    "#,
        Version::V3,
    )?;

    let name = "test";
    let ctx = dummy_ctx_policy(name);
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, &[])?;
    let mut rs = RunState::new(&machine, &mut io, &ctx);
    let result = rs.run()?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

#[test]
fn test_pop() {
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Pop]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

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
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

    // Empty stack - should fail
    let result = rs.step();
    assert!(result.is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_swap_top() {
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([
        // Swap with self (first) - should fail
        Instruction::Swap(0),
    ]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

    rs.stack.push(5).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::InvalidInstruction));
}

#[test]
fn test_swap_middle() {
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

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
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Dup(2)]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

    // Try to dup with invalid stack index - should fail
    rs.stack.push(3).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_dup() {
    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Dup(1)]);
    let mut rs = machine.create_run_state(&mut io, &ctx);

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
        let mut io = TestIO::new();
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Add]);
        let mut rs = machine.create_run_state(&mut io, &ctx);

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
        let mut io = TestIO::new();
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Add]);
        let mut rs = machine.create_run_state(&mut io, &ctx);

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
        let mut io = TestIO::new();
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Sub]);
        let mut rs = machine.create_run_state(&mut io, &ctx);

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
        let mut io = TestIO::new();
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Sub]);
        let mut rs = machine.create_run_state(&mut io, &ctx);

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
fn test_when_true() -> anyhow::Result<()> {
    let text = r#"
        action foo(x bool) {
            when x == true {
                check true == false
            }
        }
    "#;

    let name = "foo";
    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [true]).map_err(anyhow::Error::msg)?;
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
    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [false]).map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);

    Ok(())
}

const POLICY_MATCH: &str = r#"
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
                    emit Result { x: x }
                }
                6 => {
                    emit Result { x: x }
                }
            }
        }
    "#;

#[test]
fn test_match_first() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut rs = machine.create_run_state(&mut io, &ctx);

    let result = rs.call_action(name, [5]).map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.emit_stack.len(), 1);
    assert_eq!(
        io.emit_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(5)),])
    );

    Ok(())
}

#[test]
fn test_match_second() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [6]).map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.emit_stack.len(), 1);
    assert_eq!(
        io.emit_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(6)),])
    );

    Ok(())
}

#[test]
fn test_match_none() -> anyhow::Result<()> {
    let name = "foo";
    let policy = parse_policy_str(POLICY_MATCH, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs
        .call_action("foo", [Value::Int(0)])
        .map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Panic);

    Ok(())
}

#[test]
fn test_match_duplicate() -> anyhow::Result<()> {
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
                    emit Result { x: x }
                }
                6=> {
                    emit Result { x: x }
                }
                5 => {
                    emit Result { x: x }
                }
            }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V3).map_err(anyhow::Error::msg)?;
    let res = compile_from_policy(&policy, &[]);
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::AlreadyDefined(_),
            ..
        })
    ));

    Ok(())
}

const POLICY_IS: &str = r#"
    command Result {
        fields {
            x int
        }
        seal { return None }
        open { return None }
    }
    action check_none(x int) {
        when x is None {
            emit Result { x: None }
        }
        when x is Some {
            emit Result { x: x }
        }
    }
"#;

#[test]
fn test_is_some_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    // Test with a value that is not None
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs
        .call_action(name, [Value::Int(10)])
        .map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.emit_stack.len(), 1);
    assert_eq!(
        io.emit_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(10))])
    );

    Ok(())
}

#[test]
fn test_is_none_statement() -> anyhow::Result<()> {
    let name = "check_none";
    let policy = parse_policy_str(POLICY_IS, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);

    // Test with a None value
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs
        .call_action(name, [Value::None])
        .map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.emit_stack.len(), 1);
    assert_eq!(
        io.emit_stack[0],
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
    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [-1]).map_err(anyhow::Error::msg)?;
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
    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs
        .call_action(name, [true, false])
        .map_err(anyhow::Error::msg)?;
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
    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs.call_action(name, [i64::MIN]).map_err(anyhow::Error::msg);

    assert!(result.is_err());

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
                    emit Result { x: x }
                }
                _ => {
                    emit Result { x: 0 }
                }
            }
        }
    "#;
    let name = "foo";
    let policy = parse_policy_str(policy_str, Version::V3).map_err(anyhow::Error::msg)?;
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action(name);
    let mut rs = machine.create_run_state(&mut io, &ctx);
    let result = rs
        .call_action(name, [Value::Int(6)])
        .map_err(anyhow::Error::msg)?;
    assert_eq!(result, ExitReason::Normal);
    assert_eq!(io.emit_stack.len(), 1);
    assert_eq!(
        io.emit_stack[0],
        ("Result".to_string(), vec![KVPair::new("x", Value::Int(0)),])
    );

    Ok(())
}

#[test]
fn test_match_default_not_last() -> anyhow::Result<()> {
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
                    emit Result { x: x }
                }
                _ => {
                    emit Result { x: 0 }
                }
                6 => {
                    emit Result { x: x }
                }
            }
        }
    "#;
    let policy = parse_policy_str(policy_str, Version::V3).map_err(anyhow::Error::msg)?;
    let res = compile_from_policy(&policy, &[]);
    assert!(matches!(
        res,
        Err(CompileError {
            err_type: CompileErrorType::Unknown(_),
            ..
        })
    ));

    Ok(())
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
            seal { return None }
            open { return None }
        }

        action foo(id id, x bytes) {
            emit Foo{id: id, x: x}
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;
    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);

        rs.call_action(name, [vec![0xa, 0xb, 0xc], vec![0, 255, 42]])
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
            seal { return None }
            open { return None }
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
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

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
        rs.call_action(name, [Value::Bytes(vec![0xa, 0xb, 0xc]), Value::Int(3)])
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.emit_stack[0],
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

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

// --- FFI ---

struct PrintFfi {}

impl FfiModule for PrintFfi {
    type Error = MachineError;

    const SCHEMA: ModuleSchema<'static> = ModuleSchema {
        name: "print",
        functions: &[ffi::Func {
            name: "print",
            args: &[ffi::Arg {
                name: "s",
                vtype: ffi::Type::String,
            }],
            color: ffi::Color::Pure(ffi::Type::String),
        }],
    };

    fn call<E: Engine>(
        &mut self,
        procedure: usize,
        stack: &mut impl Stack,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
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
            _ => Err(MachineError::new(MachineErrorType::FfiProcedureNotDefined(
                Self::SCHEMA.name.to_string(),
                procedure,
            ))),
        }
    }
}

#[test]
fn test_ffi() {
    let mut io = TestIO::new();

    // Push value onto stack, and call FFI function
    let mut stack = TestStack::new();
    stack
        .push(Value::String("hello".to_string()))
        .expect("can't push");
    let ctx = dummy_ctx_action("test");
    io.call(0, 0, &mut stack, &ctx).expect("Should succeed");

    // Verify function was called
    assert!(stack.pop::<String>().expect("should have return value") == "HELLO");
}

#[test]
fn test_extcall() {
    let machine = Machine::new([
        Instruction::Const(Value::String("hi".to_string())),
        Instruction::ExtCall(0, 0),
        Instruction::Exit(ExitReason::Normal),
    ]);
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&mut io, &ctx);

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
        Instruction::Exit(ExitReason::Normal),
    ]);
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&mut io, &ctx);

    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::FfiModuleNotDefined(1))
    );
}

#[test]
fn test_extcall_invalid_proc() {
    let machine = Machine::new([
        Instruction::Const(Value::String("hi".to_string())),
        Instruction::ExtCall(0, 1), // invalid proc id
        Instruction::Exit(ExitReason::Normal),
    ]);
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&mut io, &ctx);

    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::FfiProcedureNotDefined(
            "print".to_string(),
            1
        ))
    );
}

#[test]
fn test_extcall_invalid_arg() {
    let machine = Machine::new([
        Instruction::Const(Value::Int(0)), // function expects string
        Instruction::ExtCall(0, 0),
        Instruction::Exit(ExitReason::Normal),
    ]);
    let mut io = TestIO::new();
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&mut io, &ctx);

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
            seal { return None }
            open { return None }
        }

        function f(x int) int {
            return x + 1
        }

        action foo(x int) {
            emit Result { x: f(x) }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    {
        let name = "foo";
        let ctx = dummy_ctx_action(name);
        machine
            .call_action(name, [3], &mut io, &ctx)
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.emit_stack[0],
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
            effect Result { x: x + 1 }
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let mut machine =
        compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    {
        let name = "Foo";
        let ctx = dummy_ctx_policy(name);
        let self_struct = Struct::new("Foo", [KVPair::new("x", Value::Int(3))]);
        machine
            .call_command_policy(name, &self_struct, dummy_envelope(), &mut io, &ctx)
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
    ctx: &CommandContext<'_>,
) where
    F: FnMut(&mut Machine) -> anyhow::Result<()>,
    G: FnMut(&mut RunState<'_, TestIO>) -> anyhow::Result<()>,
{
    let mut m = Machine::new(instructions.to_owned());

    machine_closure(&mut m).unwrap();

    let mut io = TestIO::new();
    let mut rs = m.create_run_state(&mut io, ctx);
    rs_closure(&mut rs).unwrap();
}

fn error_test_harness(instructions: &[Instruction], error_type: MachineErrorType) {
    let m = Machine::new(instructions.to_owned());

    let mut io = TestIO::new();
    let ctx = dummy_ctx_policy("test");
    let mut rs = m.create_run_state(&mut io, &ctx);
    assert_eq!(rs.run(), Err(MachineError::new(error_type)));
}

#[test]
// There are a lot of clones in here. Technically the last one isn't
// needed, but maintenance is easier when you don't need to worry about
// it.
#[allow(clippy::redundant_clone)]
fn test_errors() {
    let ctx = dummy_ctx_policy("test");
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
            Instruction::Branch(Target::Unresolved(Label::new_temp(&x))),
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
        &[Instruction::Jump(Target::Unresolved(Label::new_temp(&x)))],
        MachineErrorType::UnresolvedTarget,
    );

    // InvalidAddress: Run empty program
    error_test_harness(&[], MachineErrorType::InvalidAddress("pc".to_owned()));

    // InvalidAddress: Set PC to non-existent label
    general_test_harness(
        &[],
        |_| Ok(()),
        |rs| {
            let r = rs.set_pc_by_label(Label::new("x", LabelType::Action));
            assert_eq!(
                r,
                Err(MachineError::new(MachineErrorType::InvalidAddress(
                    "x".to_owned()
                )))
            );
            Ok(())
        },
        &ctx,
    );

    // InvalidAddress: Set PC to a label of the wrong type
    general_test_harness(
        &[],
        |m| {
            m.labels.insert(Label::new(&x, LabelType::Action), 0);
            Ok(())
        },
        |rs| {
            let r = rs.set_pc_by_label(Label::new("x", LabelType::CommandPolicy));
            assert_eq!(
                r,
                Err(MachineError::new(MachineErrorType::InvalidAddress(
                    "x".to_owned()
                )))
            );
            Ok(())
        },
        &ctx,
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

// Note: this test is not exhaustive
#[test]
fn test_bad_statements() -> anyhow::Result<()> {
    let texts = &[
        r#"
            action foo() {
                create Foo[]=>{}
            }
        "#,
        r#"
            finish function foo() {
                let x = 3
            }
        "#,
        r#"
            function foo(x int) int {
                emit Bar{}
            }
        "#,
    ];

    for text in texts {
        let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
        let res = compile_from_policy(&policy, &[]);
        assert!(matches!(
            res,
            Err(CompileError {
                err_type: CompileErrorType::InvalidStatement(_),
                ..
            })
        ));
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
                    effect Result { x: get_foo(this.a) }
                }
            }
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

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
        rs.call_command_policy(name, &self_struct, dummy_envelope())
            .map_err(anyhow::Error::msg)?;
    }

    assert_eq!(
        io.effect_stack[0],
        (
            "Result".to_string(),
            vec![KVPair::new(
                "x",
                Value::Struct(Struct {
                    name: "Foo".to_string(),
                    fields: {
                        let mut test_struct_map = BTreeMap::new();
                        test_struct_map.insert("a".to_string(), Value::Int(1));
                        test_struct_map.insert("b".to_string(), Value::Int(2));
                        test_struct_map
                    }
                })
            ),]
        )
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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

    let name = "Foo";
    let this_bytes: Vec<u8> = {
        let ctx = dummy_ctx_seal(name);
        let mut rs = machine.create_run_state(&mut io, &ctx);
        rs.call_seal(name, &this_struct)
            .map_err(anyhow::Error::msg)?;
        let result = rs.consume_return()?;
        result.try_into().map_err(anyhow::Error::msg)?
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
        rs.call_open(name, envelope).map_err(anyhow::Error::msg)?;
        let result = rs.consume_return()?;
        let got_this: Struct = result.try_into().map_err(anyhow::Error::msg)?;
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
            let f = check_unwrap query Foo[i: 1]=>{}
            check f.i == 1
        }

        action test_nonexistent() {
            let f = check_unwrap query Foo[i: 0]=>{}
            check false // would exit(panic), but check_unwrap should exit(check) first
        }
    "#;

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, TestIO::FFI_SCHEMAS).map_err(anyhow::Error::msg)?;

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

    let policy = parse_policy_str(text, Version::V3).map_err(anyhow::Error::msg)?;
    let mut io = TestIO::new();
    let machine = compile_from_policy(&policy, &[]).map_err(anyhow::Error::msg)?;

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
