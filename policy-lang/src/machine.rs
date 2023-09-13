extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt::Display;

use crate::lang::ast;

mod data;
pub use data::{
    Fact, FactKey, FactKeyList, FactValue, FactValueList, HashableValue, KVPair, Struct, Value,
};

mod error;
pub use error::{MachineError, MachineErrorType};

mod instructions;
pub use instructions::{Instruction, Target};

mod io;
pub use io::{MachineIO, MachineIOError};

mod compile;
pub use self::compile::{CompileError, CompileState};

/// Returns true if all of the k/v pairs in a exist in b, or false
/// otherwise.
fn fact_value_subset_match(a: &[FactValue], b: &[FactValue]) -> bool {
    for entry in a {
        if !b.iter().any(|e| e == entry) {
            return false;
        }
    }
    true
}

/// Status of machine execution after stepping through each
/// instruction. These are expected states entered after executing
/// instructions, as opposed to MachineErrors, which are produced by
/// invalid instructions or data.
#[derive(Debug, PartialEq)]
pub enum MachineStatus {
    /// Execution will proceed as normal to the next instruction
    Executing,
    /// Execution has ended normally
    Exited,
    /// Execution has ended with some expected failure
    Panicked,
}

impl Display for MachineStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MachineStatus::Executing => write!(f, "Executing"),
            MachineStatus::Exited => write!(f, "Exited"),
            MachineStatus::Panicked => write!(f, "Panicked"),
        }
    }
}

/// Types of Labels
#[derive(Debug, Clone, PartialEq)]
pub enum LabelType {
    /// This label represents the entry point of an action
    Action,
    /// This label represents the entry point of a command policy block
    Command,
    /// This label is a temporary destination for implementing
    /// branching constructs.
    Temporary,
}

/// Labels are branch targets and execution entry points.
#[derive(Debug, Clone)]
struct Label {
    /// The address of the label
    addr: usize,
    /// The type of the label
    ltype: LabelType,
}

/// This is the core policy machine type, which contains all of the state
/// of the machine and associated facts.
#[derive(Debug)]
pub struct Machine {
    // static state (things which do not change after compilation)
    /// The program memory
    progmem: Vec<Instruction>,
    /// Mapping of Label names to addresses
    labels: BTreeMap<String, Label>,
    /// Fact schemas
    fact_defs: BTreeMap<String, ast::FactDefinition>,
    /// Struct schemas
    struct_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
}

impl Machine {
    pub fn new<I>(instructions: I) -> Self
    where
        I: IntoIterator<Item = Instruction>,
    {
        Machine {
            progmem: Vec::from_iter(instructions),
            labels: BTreeMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
        }
    }

    /// Create a new Machine by compiling a policy AST.
    pub fn compile_from_policy(policy: &ast::Policy) -> Result<Machine, CompileError> {
        let mut cs = CompileState::new(Machine {
            progmem: vec![],
            labels: BTreeMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
        });
        cs.compile(policy)?;
        Ok(cs.into_machine())
    }

    /// Create a RunState associated with this Machine.
    pub fn create_run_state<'a, M>(&'a self, io: &'a mut M) -> RunState<M>
    where
        M: MachineIO,
    {
        RunState::new(self, io)
    }
}

impl Display for Machine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Program memory:")?;
        for (addr, instr) in self.progmem.iter().enumerate() {
            writeln!(f, "  {:4}  {}", addr, instr)?;
        }
        writeln!(f, "Labels:")?;
        for (k, v) in &self.labels {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        writeln!(f, "Fact definitions:")?;
        for (k, v) in &self.fact_defs {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        writeln!(f, "Struct definitions:")?;
        for (k, v) in &self.struct_defs {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        Ok(())
    }
}

/// The "run state" of the machine. It's separated from the rest of
/// the VM so that it can be managed independently and potentially in
/// multiple simultaneous instances.
pub struct RunState<'a, M>
where
    M: MachineIO,
{
    /// Reference to the underlying static machine data
    machine: &'a Machine,
    /// Named value definitions ("variables")
    defs: BTreeMap<String, Value>,
    /// The stack
    stack: Vec<Value>,
    /// The program counter
    pc: usize,
    /// I/O callbacks
    io: &'a mut M,
}

impl<'a, M> RunState<'a, M>
where
    M: MachineIO,
{
    /// Create a new, empty MachineState
    pub fn new<'b>(machine: &'b Machine, io: &'b mut M) -> RunState<'a, M>
    where
        'b: 'a,
    {
        RunState {
            machine,
            defs: BTreeMap::new(),
            stack: vec![],
            pc: 0,
            io,
        }
    }

    fn err(&self, err_type: MachineErrorType) -> MachineError {
        MachineError::new_with_position(err_type, self.pc)
    }

    /// Reset the machine state - undefine all named values, empty the
    /// stack, and set the program counter to zero.
    pub fn reset(&mut self) {
        self.defs = BTreeMap::new();
        self.stack = vec![];
        self.pc = 0;
    }

    /// Get the program counter.
    pub fn pc(&self) -> usize {
        self.pc
    }

    /// Push a Value onto the machine stack.
    pub fn push_value(&mut self, v: Value) -> Result<(), MachineError> {
        // No size checking yet
        self.stack.push(v);
        Ok(())
    }

    /// Push an integer onto the machine stack as a [Value::Int].
    pub fn push_int(&mut self, i: i64) -> Result<(), MachineError> {
        self.push_value(Value::Int(i))
    }

    /// Return a mutable reference to the top Value of the machine
    /// stack.
    fn peek_value(&mut self) -> Result<&mut Value, MachineError> {
        // Can't borrow self for .err() while it's being borrowed &mut
        // by last_mut(), so this error has to be created ahead of
        // time.
        let err = self.err(MachineErrorType::StackUnderflow);
        self.stack.last_mut().ok_or(err)
    }

    /// Return the value on the top of the machine stack.
    fn pop_value(&mut self) -> Result<Value, MachineError> {
        self.stack
            .pop()
            .ok_or_else(|| self.err(MachineErrorType::StackUnderflow))
    }

    /// Return the value on the top of the machine stack if it is a
    /// Value::String.
    fn pop_string(&mut self) -> Result<String, MachineError> {
        self.pop_value()?.try_into_string().map_err(|t| self.err(t))
    }

    /// Execute one machine instruction and return the status of the
    /// machine or a MachineError.
    pub fn step(&mut self) -> Result<MachineStatus, MachineError> {
        if self.pc() >= self.machine.progmem.len() {
            return Err(self.err(MachineErrorType::InvalidAddress));
        }
        // Clone the instruction so we don't take an immutable
        // reference to self while we manipulate the stack later.
        let instruction = self.machine.progmem[self.pc()].clone();
        match instruction {
            Instruction::Const(v) => self.stack.push(v),
            Instruction::Def => {
                let key = self.pop_string()?;
                let value = self.pop_value()?;
                if self.defs.contains_key(&key) {
                    return Err(self.err(MachineErrorType::AlreadyDefined));
                }
                self.defs.insert(key, value);
            }
            Instruction::Get => {
                let key = self.pop_string()?;
                let v = self
                    .defs
                    .get(&key)
                    .ok_or_else(|| self.err(MachineErrorType::NotDefined))?;
                self.stack.push(v.to_owned());
            }
            Instruction::Swap(d) => {
                if d > self.stack.len() {
                    return Err(self.err(MachineErrorType::StackUnderflow));
                }
                if d == 0 {
                    return Err(self.err(MachineErrorType::BadState));
                }
                let i1 = self.stack.len() - 1;
                let i2 = i1 - d;
                self.stack.swap(i1, i2);
            }
            Instruction::Dup(d) => {
                if d > self.stack.len() {
                    return Err(self.err(MachineErrorType::StackUnderflow));
                }
                let v = self.stack[self.stack.len() - d - 1].clone();
                self.stack.push(v);
            }
            Instruction::Pop => {
                let _ = self.pop_value();
            }
            Instruction::Block => todo!(),
            Instruction::End => todo!(),
            Instruction::Jump(t) => {
                match t {
                    Target::Unresolved(_) => {
                        return Err(self.err(MachineErrorType::UnresolvedTarget))
                    }
                    Target::Resolved(n) => {
                        // subtract one to account for the PC increment below.
                        self.pc = n - 1;
                    }
                }
            }
            Instruction::Branch(t) => {
                let conditional = self.pop_value()?.try_to_bool().map_err(|t| self.err(t))?;
                if conditional {
                    match t {
                        Target::Unresolved(_) => {
                            return Err(self.err(MachineErrorType::UnresolvedTarget))
                        }
                        Target::Resolved(n) => {
                            // subtract one to account for the PC increment below.
                            self.pc = n - 1;
                        }
                    }
                }
            }
            Instruction::Next => todo!(),
            Instruction::Last => todo!(),
            Instruction::Call(_t) => todo!(),
            Instruction::Return => todo!(),
            Instruction::Exit => return Ok(MachineStatus::Exited),
            Instruction::Panic => return Ok(MachineStatus::Panicked),
            Instruction::Add | Instruction::Sub => {
                let a = self.pop_value()?.try_to_int().map_err(|t| self.err(t))?;
                let b = self.pop_value()?.try_to_int().map_err(|t| self.err(t))?;
                let r = match instruction {
                    Instruction::Add => a + b,
                    Instruction::Sub => a - b,
                    _ => unreachable!(),
                };
                self.stack.push(Value::Int(r));
            }
            Instruction::And | Instruction::Or => {
                let a = self.pop_value()?.try_to_bool().map_err(|t| self.err(t))?;
                let b = self.pop_value()?.try_to_bool().map_err(|t| self.err(t))?;
                let r = match instruction {
                    Instruction::And => a && b,
                    Instruction::Or => a || b,
                    _ => unreachable!(),
                };
                self.stack.push(Value::Bool(r));
            }
            Instruction::Not => {
                let a = self.pop_value()?.try_to_bool().map_err(|t| self.err(t))?;
                self.stack.push(Value::Bool(!a));
            }
            Instruction::Gt | Instruction::Lt | Instruction::Eq => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let v = match instruction {
                    Instruction::Gt => match (a, b) {
                        (Value::Int(a), Value::Int(b)) => a > b,
                        _ => return Err(self.err(MachineErrorType::InvalidType)),
                    },
                    Instruction::Lt => match (a, b) {
                        (Value::Int(a), Value::Int(b)) => a < b,
                        _ => return Err(self.err(MachineErrorType::InvalidType)),
                    },
                    // This leans heavily on PartialEq to do the work.
                    // Equality depends on values having the same type and
                    // interior value.
                    Instruction::Eq => a == b,
                    _ => unreachable!(),
                };
                self.stack.push(Value::Bool(v));
            }
            Instruction::FactNew => {
                let name = self.pop_string()?;
                let fact = Fact::new(name);
                self.push_value(Value::Fact(fact))?;
            }
            Instruction::FactKeySet => {
                let varname = self.pop_string()?;
                let v: HashableValue = self.pop_value()?.try_into().map_err(|t| self.err(t))?;
                if let Value::Fact(f) = self.peek_value()? {
                    f.set_key(varname, v);
                } else {
                    return Err(self.err(MachineErrorType::InvalidType));
                }
            }
            Instruction::FactValueSet => {
                let varname = self.pop_string()?;
                let value = self.pop_value()?;
                if let Value::Fact(f) = self.peek_value()? {
                    f.set_value(varname, value);
                } else {
                    return Err(self.err(MachineErrorType::InvalidType));
                }
            }
            Instruction::StructNew => {
                let name = self.pop_string()?;
                let fields = BTreeMap::new();
                self.stack.push(Value::Struct(Struct { name, fields }));
            }
            Instruction::StructSet => {
                let varname = self.pop_string()?;
                let value = self.pop_value()?;
                if let Value::Struct(s) = self.peek_value()? {
                    s.fields.insert(varname, value);
                } else {
                    return Err(self.err(MachineErrorType::InvalidType));
                }
            }
            Instruction::StructGet => {
                let varname = self.pop_string()?;
                let v = if let Value::Struct(s) = self.pop_value()? {
                    let v = s
                        .fields
                        .get(&varname)
                        .ok_or_else(|| self.err(MachineErrorType::InvalidStruct))?;
                    v.clone()
                } else {
                    return Err(self.err(MachineErrorType::StackUnderflow));
                };
                self.push_value(v)?;
            }
            Instruction::Emit => {
                let s = self
                    .pop_value()?
                    .try_into_struct()
                    .map_err(|t| self.err(t))?;
                let def = self
                    .machine
                    .struct_defs
                    .get(&s.name)
                    .ok_or(self.err(MachineErrorType::InvalidStruct))?;
                for field_def in def {
                    if !s.fields.contains_key(&field_def.identifier) {
                        return Err(self.err(MachineErrorType::InvalidStruct));
                    }
                }

                let fields = s.fields.into_iter().map(|(k, v)| KVPair::new(&k, v));

                self.io.emit(s.name, fields);
            }
            Instruction::Create => {
                let f = self.pop_value()?.try_into_fact().map_err(|t| self.err(t))?;
                println!("fact: {}", f);
                self.io.fact_insert(f.name, f.keys, f.values)?;
            }
            Instruction::Delete => {
                // Find all facts matching our (possibly partial) key,
                // then iterate over them to find which ones match the
                // values.
                // TODO(chip) describe this better as it is very confusing
                let f = self.pop_value()?.try_into_fact().map_err(|t| self.err(t))?;
                self.io.fact_delete(f.name, f.keys)?;
            }
            Instruction::Update => {
                let fact_to = self.pop_value()?.try_into_fact().map_err(|t| self.err(t))?;
                let fact_from = self.pop_value()?.try_into_fact().map_err(|t| self.err(t))?;
                let replaced_fact = {
                    let mut iter = self.io.fact_query(fact_from.name.clone(), fact_from.keys)?;
                    iter.next()
                        .ok_or_else(|| self.err(MachineErrorType::InvalidFact))?
                };
                self.io.fact_delete(fact_from.name, replaced_fact.0)?;
                self.io
                    .fact_insert(fact_to.name, fact_to.keys, fact_to.values)?;
            }
            Instruction::Effect => {
                let s = self
                    .pop_value()?
                    .try_into_struct()
                    .map_err(|t| self.err(t))?;
                let fields = s.fields.into_iter().map(|(k, v)| KVPair::new(&k, v));
                self.io.effect(s.name, fields);
            }
            Instruction::Query => {
                let qf = self.pop_value()?.try_into_fact().map_err(|t| self.err(t))?;
                let result = {
                    let mut iter = self.io.fact_query(qf.name.clone(), qf.keys)?;
                    iter.find(|f| fact_value_subset_match(&qf.values, &f.1))
                };
                match result {
                    Some(f) => {
                        let mut fields: Vec<KVPair> = vec![];
                        fields.append(&mut f.0.into_iter().map(|e| e.into()).collect());
                        fields.append(&mut f.1.into_iter().map(|e| e.into()).collect());
                        let f = Struct::new(&qf.name, &fields);
                        self.push_value(Value::Struct(f))?;
                    }
                    None => self.push_value(Value::None)?,
                }
            }
            Instruction::Exists => todo!(),
            Instruction::Id => todo!(),
            Instruction::AuthorId => todo!(),
        }
        self.pc += 1;

        Ok(MachineStatus::Executing)
    }

    /// Execute machine instructions while each instruction returns
    /// MachineStatus::Executing. Returns the MachineStatus it exited
    /// with, or an error.
    pub fn run(&mut self) -> Result<MachineStatus, MachineError> {
        loop {
            let status = self.step()?;
            if status == MachineStatus::Executing {
                continue;
            }
            return Ok(status);
        }
    }

    /// Set the program counter to the given label.
    pub fn set_pc_by_name(&mut self, name: &str, ltype: LabelType) -> Result<(), MachineError> {
        let name = self
            .machine
            .labels
            .get(name)
            .ok_or_else(|| self.err(MachineErrorType::InvalidAddress))?;
        if name.ltype == ltype {
            self.pc = name.addr;
            Ok(())
        } else {
            Err(self.err(MachineErrorType::InvalidAddress))
        }
    }

    /// Set up machine state for a command policy call
    pub fn setup_command_policy(
        &mut self,
        name: &str,
        self_data: &Struct,
    ) -> Result<(), MachineError> {
        self.set_pc_by_name(name, LabelType::Command)?;
        self.defs.clear();
        self.defs
            .insert(String::from("self"), Value::Struct(self_data.to_owned()));
        Ok(())
    }

    /// Call a command policy loaded into the VM by name. Accepts a
    /// `Struct` containing the Command's data. Returns a Vec of effect
    /// structs or a MachineError.
    pub fn call_command_policy(
        &mut self,
        name: &str,
        self_data: &Struct,
    ) -> Result<MachineStatus, MachineError> {
        self.setup_command_policy(name, self_data)?;
        self.run()
    }

    /// Set up machine state for an action call.
    pub fn setup_action<V>(&mut self, name: &str, args: &[V]) -> Result<(), MachineError>
    where
        V: Into<Value> + Clone,
    {
        self.set_pc_by_name(name, LabelType::Action)?;
        for a in args {
            self.push_value(a.to_owned().into())?;
        }
        self.defs.clear();

        Ok(())
    }

    /// Call an action loaded into the VM by name. Accepts a list of
    /// arguments to the function, which must match the number of
    /// arguments expected. Returns a MachineError on failure.
    // TODO(chip): I don't really like how V: Into<Value> works here
    // because it still means all of the args have to have the same
    // type.
    pub fn call_action<V>(&mut self, name: &str, args: &[V]) -> Result<MachineStatus, MachineError>
    where
        V: Into<Value> + Clone,
    {
        self.setup_action(name, args)?;
        self.run()
    }
}

impl<'a, M> Display for RunState<'a, M>
where
    M: MachineIO,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "# Name table:")?;
        for (k, v) in &self.machine.labels {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        writeln!(f, "# Defs:")?;
        for (k, v) in &self.defs {
            writeln!(f, "  {}: {}", k, v)?;
        }
        writeln!(f, "# Stack:")?;
        for v in &self.stack {
            write!(f, "{} ", v)?;
        }
        writeln!(f)?;
        writeln!(f, "# Program:")?;
        for (addr, instr) in self.machine.progmem.iter().enumerate() {
            for (k, v) in &self.machine.labels {
                if v.addr == addr {
                    writeln!(f, "{}:", k)?;
                }
            }
            if addr == self.pc() {
                write!(f, "*")?;
            } else {
                write!(f, " ")?;
            }
            writeln!(f, "  {:4}  {}", addr, instr)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
