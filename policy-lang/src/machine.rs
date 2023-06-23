extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt::Display;

use crate::lang::ast;

mod data;
pub use data::{Fact, FactIterator, HashableValue, Struct, Value};

mod instructions;
pub use instructions::{Instruction, Target};

mod compile;
pub use self::compile::{CompileError, CompileState};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "error_in_core")] {
        use core::error;
    } else {
        use std::error;
    }
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

/// Possible machine errors.
// TODO(chip): These should be elaborated with additional data, and/or
// more fine grained types.
#[derive(Debug)]
pub enum MachineError {
    /// Stack underflow - an operation tried to consume a value from an
    /// empty stack.
    StackUnderflow,
    /// Stack overflow - an operation tried to push a value onto a full
    /// stack. N.B. that there are currently no size limits on the
    /// stack, so this cannot be reached.
    StackOverflow,
    /// Name already defined - an attempt was made to define a name
    /// that was already defined.
    AlreadyDefined,
    /// Name not defined - an attempt was made to access a name that
    /// has not been defined.
    NotDefined,
    /// Invalid type - An operation was given a value of the wrong
    /// type. E.g. addition with strings.
    InvalidType,
    /// Invalid struct - An attempt to access a member not present in a
    /// struct, or an attempt to emit a Command struct that does not
    /// match its definition.
    InvalidStruct,
    /// Invalid fact - An attempt was made to access a fact in a way
    /// that does not match the Fact schema.
    InvalidFact,
    /// Unresolved target - A branching instruction attempted to jump
    /// to a target whose address has not yet been resolved.
    UnresolvedTarget,
    /// Target not found - An attempt to resolve an unresolved branch
    /// target did not find anything.
    TargetNotFound,
    /// Invalid address - An attempt to execute an instruction went
    /// beyond instruction bounds, or an action/command lookup did not
    /// find an address for the given name.
    InvalidAddress,
    /// Bad state - Some internal state is invalid and execution cannot
    /// continue.
    BadState,
    /// Unknown - every other possible problem
    Unknown,
}

impl Display for MachineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MachineError::StackUnderflow => write!(f, "stack underflow"),
            MachineError::StackOverflow => write!(f, "stack overflow"),
            MachineError::AlreadyDefined => write!(f, "name already defined"),
            MachineError::NotDefined => write!(f, "name not defined"),
            MachineError::InvalidType => write!(f, "invalid type for operation"),
            MachineError::InvalidStruct => write!(f, "invalid struct"),
            MachineError::InvalidFact => write!(f, "invalid fact"),
            MachineError::UnresolvedTarget => write!(f, "unresolved branch/jump target"),
            MachineError::TargetNotFound => write!(f, "target not found"),
            MachineError::InvalidAddress => write!(f, "invalid address"),
            MachineError::BadState => write!(f, "Bad state"),
            MachineError::Unknown => write!(f, "unknown error"),
        }
    }
}

// Implementing Display and deriving Debug implements
// error::Error with default behavior by declaring this empty
// implementation.
impl error::Error for MachineError {}

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

pub trait MachineIO {
    // Insert a fact
    fn fact_insert(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
        value: impl IntoIterator<Item = (String, Value)>,
    ) -> Result<(), MachineError>;

    /// Delete a fact
    fn fact_delete(
        &mut self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<(), MachineError>;

    /// Query a fact
    fn fact_query<'a>(
        &self,
        name: String,
        key: impl IntoIterator<Item = (String, HashableValue)>,
    ) -> Result<FactIterator<'a>, MachineError>;

    /// Emit a command
    fn emit(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>);

    /// Create an effect
    fn effect(&mut self, name: String, fields: impl IntoIterator<Item = (String, Value)>);
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
    pub fn new<'b>(machine: &'b Machine, io: &'b mut M) -> RunState<'b, M> {
        RunState {
            machine,
            defs: BTreeMap::new(),
            stack: vec![],
            pc: 0,
            io,
        }
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
        self.stack.last_mut().ok_or(MachineError::StackUnderflow)
    }

    /// Return the value on the top of the machine stack.
    fn pop_value(&mut self) -> Result<Value, MachineError> {
        self.stack.pop().ok_or(MachineError::StackUnderflow)
    }

    /// Return the value on the top of the machine stack if it is a
    /// Value::String.
    fn pop_string(&mut self) -> Result<String, MachineError> {
        self.pop_value()?.try_into_string()
    }

    /// Execute one machine instruction and return the status of the
    /// machine or a MachineError.
    pub fn step(&mut self) -> Result<MachineStatus, MachineError> {
        if self.pc() >= self.machine.progmem.len() {
            return Err(MachineError::InvalidAddress);
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
                    return Err(MachineError::AlreadyDefined);
                }
                self.defs.insert(key, value);
            }
            Instruction::Get => {
                let key = self.pop_string()?;
                let v = self.defs.get(&key).ok_or(MachineError::NotDefined)?;
                self.stack.push(v.to_owned());
            }
            Instruction::Swap(_d) => todo!(),
            Instruction::Dup(_d) => todo!(),
            Instruction::Pop => todo!(),
            Instruction::Block => todo!(),
            Instruction::End => todo!(),
            Instruction::Jump(t) => {
                match t {
                    Target::Unresolved(_) => return Err(MachineError::UnresolvedTarget),
                    Target::Resolved(n) => {
                        // subtract one to account for the PC increment below.
                        self.pc = n - 1;
                    }
                }
            }
            Instruction::Branch(t) => {
                let conditional = self.pop_value()?.try_to_bool()?;
                if conditional {
                    match t {
                        Target::Unresolved(_) => return Err(MachineError::UnresolvedTarget),
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
                let a = self.pop_value()?.try_to_int()?;
                let b = self.pop_value()?.try_to_int()?;
                let r = match instruction {
                    Instruction::Add => a + b,
                    Instruction::Sub => a - b,
                    _ => unreachable!(),
                };
                self.stack.push(Value::Int(r));
            }
            Instruction::And | Instruction::Or => {
                let a = self.pop_value()?.try_to_bool()?;
                let b = self.pop_value()?.try_to_bool()?;
                let r = match instruction {
                    Instruction::And => a && b,
                    Instruction::Or => a || b,
                    _ => unreachable!(),
                };
                self.stack.push(Value::Bool(r));
            }
            Instruction::Not => {
                let a = self.pop_value()?.try_to_bool()?;
                self.stack.push(Value::Bool(!a));
            }
            Instruction::Gt | Instruction::Lt | Instruction::Eq => {
                let b = self.pop_value()?;
                let a = self.pop_value()?;
                let v = match instruction {
                    Instruction::Gt => match (a, b) {
                        (Value::Int(a), Value::Int(b)) => a > b,
                        _ => return Err(MachineError::InvalidType),
                    },
                    Instruction::Lt => match (a, b) {
                        (Value::Int(a), Value::Int(b)) => a < b,
                        _ => return Err(MachineError::InvalidType),
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
                let fact = Fact {
                    name,
                    keys: BTreeMap::new(),
                    values: BTreeMap::new(),
                };
                self.push_value(Value::Fact(fact))?;
            }
            Instruction::FactKeySet => {
                let varname = self.pop_string()?;
                let value = self.pop_value()?;
                if let Value::Fact(f) = self.peek_value()? {
                    f.keys.insert(varname, value.try_into()?);
                } else {
                    return Err(MachineError::InvalidType);
                }
            }
            Instruction::FactValueSet => {
                let varname = self.pop_string()?;
                let value = self.pop_value()?;
                if let Value::Fact(f) = self.peek_value()? {
                    f.values.insert(varname, value);
                } else {
                    return Err(MachineError::InvalidType);
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
                    return Err(MachineError::InvalidType);
                }
            }
            Instruction::StructGet => {
                let varname = self.pop_string()?;
                let v = if let Value::Struct(s) = self.pop_value()? {
                    let v = s.fields.get(&varname).ok_or(MachineError::InvalidStruct)?;
                    v.clone()
                } else {
                    return Err(MachineError::StackUnderflow);
                };
                self.push_value(v)?;
            }
            Instruction::Emit => {
                let s = self.pop_value()?.try_into_struct()?;
                let def = self
                    .machine
                    .struct_defs
                    .get(&s.name)
                    .ok_or(MachineError::InvalidStruct)?;
                for field_def in def {
                    if !s.fields.contains_key(&field_def.identifier) {
                        return Err(MachineError::InvalidStruct);
                    }
                }

                self.io.emit(s.name, s.fields);
            }
            Instruction::Create => {
                let f = self.pop_value()?.try_into_fact()?;
                self.io.fact_insert(f.name, f.keys, f.values)?;
            }
            Instruction::Delete => {
                // Find all facts matching our (possibly partial) key,
                // then iterate over them to find which ones match the
                // values.
                // TODO(chip) describe this better as it is very confusing
                let f = self.pop_value()?.try_into_fact()?;
                self.io.fact_delete(f.name, f.keys)?;
            }
            Instruction::Update => todo!(),
            Instruction::Effect => {
                let s = self.pop_value()?.try_into_struct()?;
                self.io.effect(s.name, s.fields);
            }
            Instruction::Query => todo!(),
            Instruction::Exists => todo!(),
            Instruction::Id => todo!(),
            Instruction::AuthorId => todo!(),
        }
        self.pc += 1;

        Ok(MachineStatus::Executing)
    }

    /// Execute machine instructions while each instruction returns
    /// MachineStatus::Executing.
    pub fn run(&mut self) -> Result<(), MachineError> {
        while self.step()? == MachineStatus::Executing {}
        Ok(())
    }

    /// Set the program counter to the given label.
    pub fn set_pc_by_name(&mut self, name: &str, ltype: LabelType) -> Result<(), MachineError> {
        let name = self
            .machine
            .labels
            .get(name)
            .ok_or(MachineError::InvalidAddress)?;
        if name.ltype == ltype {
            self.pc = name.addr;
            Ok(())
        } else {
            Err(MachineError::InvalidAddress)
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
    ) -> Result<(), MachineError> {
        self.setup_command_policy(name, self_data)?;
        self.run()?;
        Ok(())
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
    pub fn call_action<V>(&mut self, name: &str, args: &[V]) -> Result<(), MachineError>
    where
        V: Into<Value> + Clone,
    {
        self.setup_action(name, args)?;
        self.run()?;
        Ok(())
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
