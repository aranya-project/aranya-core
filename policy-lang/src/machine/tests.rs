extern crate alloc;
use alloc::collections::{btree_map, BTreeMap};

use anyhow;

use crate::lang::{parse_policy_str, Version};
use crate::machine::{
    FactKey, FactKeyList, FactValue, FactValueList, Instruction, KVPair, Machine, MachineErrorType,
    MachineIO, MachineIOError, MachineStatus, RunState, Struct, Value,
};

#[derive(Debug)]
struct TestIO {
    facts: BTreeMap<(String, FactKeyList), FactValueList>,
    emit_stack: Vec<(String, Vec<KVPair>)>,
    effect_stack: Vec<(String, Vec<KVPair>)>,
}

impl TestIO {
    pub fn new() -> Self {
        TestIO {
            facts: BTreeMap::new(),
            emit_stack: vec![],
            effect_stack: vec![],
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

impl MachineIO for TestIO {
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
        let fields: Vec<_> = fields.into_iter().collect();
        println!("emit {} {{{:?}}}", name, fields);
        self.emit_stack.push((name, fields));
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let fields: Vec<_> = fields.into_iter().collect();
        println!("effect {} {{{:?}}}", name, fields);
        self.effect_stack.push((name, fields));
    }
}

#[test]
fn test_compile() -> anyhow::Result<()> {
    let policy = parse_policy_str(
        r#"
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
        let sum = self.a + self.b
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
        let x = self.a
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
    rs.push_value(Value::Int(5)).unwrap();

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

    rs.push_value(Value::Int(5)).unwrap();
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
    rs.push_value(Value::Int(3)).unwrap();
    rs.push_value(Value::Int(5)).unwrap();
    rs.push_value(Value::Int(8)).unwrap();
    assert!(rs.step().unwrap() == MachineStatus::Executing);
    assert!(rs.stack[0].try_to_int().unwrap() == 3);
    assert!(rs.stack[1].try_to_int().unwrap() == 8);
    assert!(rs.stack[2].try_to_int().unwrap() == 5);
}

#[test]
fn test_dup_underflow() {
    let machine = Machine::new([Instruction::Dup(2)]);
    let mut io = TestIO::new();
    let mut rs = machine.create_run_state(&mut io);

    // Try to dup with invalid stack index - should fail
    rs.push_value(Value::Int(3)).unwrap();
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
    rs.push_value(Value::Int(3)).unwrap();
    rs.push_value(Value::Int(5)).unwrap();
    assert!(rs.step().unwrap() == MachineStatus::Executing);
    assert!(rs.stack.len() == 3);
    assert!(rs.stack[0].try_to_int().unwrap() == 3);
    assert!(rs.stack[1].try_to_int().unwrap() == 5);
    assert!(rs.stack[2].try_to_int().unwrap() == 3);
}
