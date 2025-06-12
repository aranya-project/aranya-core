#![cfg(test)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

mod ffi;
mod io;

use alloc::collections::BTreeMap;
use core::cell::RefCell;

use aranya_crypto::{DeviceId, Id};
use io::TestIO;

use crate::{
    error::MachineErrorType,
    io::{MachineIO, MachineIOError},
    machine::{Machine, MachineStatus, RunState},
    stack::Stack,
    ActionContext, CodeMap, CommandContext, ExitReason, Fact, Instruction, Label, LabelType,
    MachineError, PolicyContext, Struct, Target, Value,
};

fn dummy_ctx_action(name: &str) -> CommandContext<'_> {
    CommandContext::Action(ActionContext {
        name,
        head_id: Id::default(),
    })
}

fn dummy_ctx_policy(name: &str) -> CommandContext<'_> {
    CommandContext::Policy(PolicyContext {
        name,
        id: Id::default(),
        author: DeviceId::default(),
        version: Id::default(),
    })
}

#[test]
fn test_pop() {
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Pop]);
    let mut rs = machine.create_run_state(&io, ctx);

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut rs = machine.create_run_state(&io, ctx);

    // Empty stack - should fail
    let result = rs.step();
    assert!(result.is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_swap_top() {
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([
        // Swap with self (first) - should fail
        Instruction::Swap(0),
    ]);
    let mut rs = machine.create_run_state(&io, ctx);

    rs.stack.push(5).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::InvalidInstruction));
}

#[test]
fn test_swap_middle() {
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Swap(1)]);
    let mut rs = machine.create_run_state(&io, ctx);

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Dup(2)]);
    let mut rs = machine.create_run_state(&io, ctx);

    // Try to dup with invalid stack index - should fail
    rs.stack.push(3).unwrap();
    assert!(rs
        .step()
        .is_err_and(|result| result.err_type == MachineErrorType::StackUnderflow));
}

#[test]
fn test_dup() {
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let machine = Machine::new([Instruction::Dup(1)]);
    let mut rs = machine.create_run_state(&io, ctx);

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
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Add]);
        let mut rs = machine.create_run_state(&io, ctx);

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
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Add]);
        let mut rs = machine.create_run_state(&io, ctx);

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
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Sub]);
        let mut rs = machine.create_run_state(&io, ctx);

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
        let io = RefCell::new(TestIO::new());
        let ctx = dummy_ctx_policy("test");
        let machine = Machine::new([Instruction::Sub]);
        let mut rs = machine.create_run_state(&io, ctx);

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
    s.push(3)?;
    s.push(true)?;
    s.push("hello")?;
    s.push(Struct::new("Foo", &[]))?;
    s.push(Fact::new("Bar".to_owned()))?;
    s.push_value(Value::None)?;
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
    let v = s.peek_value()?;
    assert_eq!(v, &Value::None);
    let v = s.pop_value()?;
    assert_eq!(v, Value::None);

    let v: &Fact = s.peek()?;
    assert_eq!(v, &Fact::new("Bar".to_owned()));
    let v: Fact = s.pop()?;
    assert_eq!(v, Fact::new("Bar".to_owned()));

    let v: &Struct = s.peek()?;
    assert_eq!(v, &Struct::new("Foo", &[]));
    let v: Struct = s.pop()?;
    assert_eq!(v, Struct::new("Foo", &[]));

    let v: &str = s.peek()?;
    assert_eq!(v, "hello");
    let v: String = s.pop()?;
    assert_eq!(v, "hello".to_owned());

    let v: &bool = s.peek()?;
    assert_eq!(v, &true);
    let v: bool = s.pop()?;
    assert!(v);

    let v: &i64 = s.peek()?;
    assert_eq!(v, &3);
    let v: i64 = s.pop()?;
    assert_eq!(v, 3);
    Ok(())
}

// --- FFI ---

#[test]
fn test_ffi() {
    let io = RefCell::new(TestIO::new());

    // Push value onto stack, and call FFI function
    let mut stack = TestStack::new();
    stack
        .push(Value::String("hello".to_string()))
        .expect("can't push");
    let ctx = dummy_ctx_action("test");
    io.borrow_mut()
        .call(0, 0, &mut stack, &ctx)
        .expect("Should succeed");

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&io, ctx);

    rs.run().expect("Should succeed").success();

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&io, ctx);

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&io, ctx);

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
    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_action("test");
    let mut rs = machine.create_run_state(&io, ctx);

    // Empty stack - should fail
    assert_eq!(
        rs.run().unwrap_err(),
        MachineError::new(MachineErrorType::invalid_type(
            "String",
            "Int",
            "Value -> String"
        ))
    );
}

#[test]
fn test_span_lookup() -> anyhow::Result<()> {
    let test_str = "I've got a lovely bunch of coconuts";
    let ranges = vec![(0, 8), (9, 23), (24, 34)];
    let mut cm = CodeMap::new(test_str, ranges);
    // instruction ranges are inclusive of the instruction, up until
    // the next instruction, and must be inserted in order. So the
    // first range is 0-11, the second is 12-21, etc.
    cm.map_instruction_range(0, 0)?;
    cm.map_instruction_range(12, 9)?;
    cm.map_instruction_range(22, 24)?;

    // An instruction at the boundary returns the range starting
    // at that boundary.
    let s = cm.span_from_instruction(0)?;
    assert_eq!(s.start(), 0);

    // An instruction between boundaries returns the range starting
    // at the last instruction boundary.
    let s = cm.span_from_instruction(3)?;
    assert_eq!(s.start(), 0);

    let s = cm.span_from_instruction(12)?;
    assert_eq!(s.start(), 9);

    let s = cm.span_from_instruction(21)?;
    assert_eq!(s.start(), 9);

    let s = cm.span_from_instruction(22)?;
    assert_eq!(s.start(), 24);

    // An instruction beyond the last instruction boundary always
    // returns the last range.
    let s = cm.span_from_instruction(30)?;
    assert_eq!(s.start(), 24);

    Ok(())
}

fn general_test_harness<F, G>(
    instructions: &[Instruction],
    mut machine_closure: F,
    mut rs_closure: G,
    ctx: CommandContext<'_>,
) where
    F: FnMut(&mut Machine) -> anyhow::Result<()>,
    G: FnMut(&mut RunState<'_, TestIO>) -> anyhow::Result<()>,
{
    let mut m = Machine::new(instructions.to_owned());

    machine_closure(&mut m).unwrap();

    let io = RefCell::new(TestIO::new());
    let mut rs = m.create_run_state(&io, ctx);
    rs_closure(&mut rs).unwrap();
}

fn error_test_harness(instructions: &[Instruction], error_type: MachineErrorType) {
    let m = Machine::new(instructions.to_owned());

    let io = RefCell::new(TestIO::new());
    let ctx = dummy_ctx_policy("test");
    let mut rs = m.create_run_state(&io, ctx);
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
    error_test_harness(
        &[Instruction::Def(x.clone())],
        MachineErrorType::StackUnderflow,
    );

    // StackOverflow untested as the stack has no maximum size

    // NotDefined: Get a name that isn't defined
    error_test_harness(
        &[Instruction::Get(x.clone())],
        MachineErrorType::NotDefined(x.clone()),
    );

    // AlreadyDefined: Define a name twice
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Dup(0),
            Instruction::Def(x.clone()),
            Instruction::Def(x.clone()),
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
        MachineErrorType::invalid_type("Int, Int", "Int, String", "Greater-than comparison"),
    );

    // InvalidType: 3 + "x" (same case as 3 - "x")
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::Add,
        ],
        MachineErrorType::invalid_type("Int", "String", "Value -> i64"),
    );

    // InvalidType: 3 && "x"
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::String(x.clone())),
            Instruction::And,
        ],
        MachineErrorType::invalid_type("Bool", "String", "Value -> bool"),
    );

    // InvalidType: !3
    error_test_harness(
        &[Instruction::Const(Value::Int(3)), Instruction::Not],
        MachineErrorType::invalid_type("bool", "Int", "Value -> bool"),
    );

    // InvalidType: Set a struct value on a thing that isn't a struct
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::StructSet(x.clone()),
        ],
        MachineErrorType::invalid_type("Struct", "Int", "Value -> Struct"),
    );

    // InvalidType: Set a fact key on a thing that isn't a fact
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::FactKeySet(x.clone()),
        ],
        MachineErrorType::invalid_type("Fact", "Int", "Value -> Fact"),
    );

    // InvalidType: Set a fact value on a thing that isn't a fact
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Const(Value::Int(3)),
            Instruction::FactValueSet(x.clone()),
        ],
        MachineErrorType::invalid_type("Fact", "Int", "Value -> Fact"),
    );

    // InvalidType: Branch on a non-bool value
    error_test_harness(
        &[
            Instruction::Const(Value::Int(3)),
            Instruction::Branch(Target::Unresolved(Label::new_temp(&x))),
        ],
        MachineErrorType::invalid_type("Bool", "Int", "Value -> bool"),
    );

    // InvalidStructGet: Access `foo.x` when `x` is not a member of `foo`
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct::new("foo", &[]))),
            Instruction::StructGet(x.clone()),
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
        MachineErrorType::InvalidFact(x.clone()),
    );

    // InvalidSchema: Publish a command that was not defined
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct {
                name: x.clone(),
                fields: BTreeMap::new(),
            })),
            Instruction::Publish,
        ],
        MachineErrorType::InvalidSchema(x.clone()),
    );

    // InvalidSchema: Emit an effect that was not defined
    error_test_harness(
        &[
            Instruction::Const(Value::Struct(Struct {
                name: x.clone(),
                fields: BTreeMap::new(),
            })),
            Instruction::Emit,
        ],
        MachineErrorType::InvalidSchema(x.clone()),
    );

    // UnresolvedTarget: Jump to an unresolved target
    error_test_harness(
        &[Instruction::Jump(Target::Unresolved(Label::new_temp(&x)))],
        MachineErrorType::UnresolvedTarget(Label::new_temp(&x)),
    );

    // InvalidAddress: Run empty program
    error_test_harness(&[], MachineErrorType::InvalidAddress("pc".to_owned()));

    // InvalidAddress: Set PC to non-existent label
    general_test_harness(
        &[],
        |_| Ok(()),
        |rs| {
            let r = rs.set_pc_by_label(&Label::new("x", LabelType::Action));
            assert_eq!(
                r,
                Err(MachineError::new(MachineErrorType::InvalidAddress(
                    "x".to_owned()
                )))
            );
            Ok(())
        },
        ctx.to_owned(),
    );

    // InvalidAddress: Set PC to a label of the wrong type
    general_test_harness(
        &[],
        |m| {
            m.labels.insert(Label::new(&x, LabelType::Action), 0);
            Ok(())
        },
        |rs| {
            let r = rs.set_pc_by_label(&Label::new("x", LabelType::CommandPolicy));
            assert_eq!(
                r,
                Err(MachineError::new(MachineErrorType::InvalidAddress(
                    "x".to_owned()
                )))
            );
            Ok(())
        },
        ctx,
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
