use anyhow;

use crate::lang::{parse_policy_str, Version};
use crate::machine::{
    FactIterator, HashableValue, Machine, MachineError, MachineIO, RunState, Struct, Value,
};

#[derive(Debug)]
struct TestIO {
    emit_stack: Vec<(String, Vec<(String, Value)>)>,
    effect_stack: Vec<(String, Vec<(String, Value)>)>,
}

impl TestIO {
    pub fn new() -> Self {
        TestIO {
            emit_stack: vec![],
            effect_stack: vec![],
        }
    }
}

impl MachineIO for TestIO {
    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
        value: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<(), MachineError> {
        let key: Vec<_> = key.into_iter().collect();
        let value: Vec<_> = value.into_iter().collect();
        println!("fact insert {}[{:?}]=>{{{:?}}}", name, key, value);
        Ok(())
    }

    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<(), MachineError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("fact delete {}[{:?}]", name, key);
        Ok(())
    }

    fn fact_query<'a>(
        &self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<FactIterator<'a>, MachineError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("query {}[{:?}]", name, key);
        Err(MachineError::Unknown)
    }

    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>) {
        let fields: Vec<_> = fields.into_iter().collect();
        println!("emit {} {{{:?}}}", name, fields);
        self.emit_stack.push((name, fields));
    }

    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>) {
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
    )?;

    Machine::compile_from_policy(&policy)?;

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
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3)?;

    let machine = Machine::compile_from_policy(&policy)?;
    let mut io = TestIO::new();
    let mut rs = RunState::new(&machine, &mut io);

    rs.call_action("foo", &[Value::from(3), Value::from("foo")])?;

    println!("emit stack: {:?}", io.emit_stack);

    Ok(())
}

#[test]
fn test_command_policy() -> anyhow::Result<()> {
    let policy = parse_policy_str(TEST_POLICY_1.trim(), Version::V3)?;

    let machine = Machine::compile_from_policy(&policy)?;
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
