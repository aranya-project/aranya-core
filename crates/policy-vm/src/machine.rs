extern crate alloc;

use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, vec, vec::Vec};
use core::fmt::{self, Display};

use policy_ast as ast;

use crate::{
    data::{Fact, FactValue, HashableValue, KVPair, Struct, TryAsMut, Value},
    error::{MachineError, MachineErrorType},
    instructions::{Instruction, Target},
    io::MachineIO,
    stack::Stack,
    CodeMap, Span,
};

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
#[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq)]
pub enum LabelType {
    /// This label represents the entry point of an action
    Action,
    /// This label represents the entry point of a command policy block
    CommandPolicy,
    /// This label represents the entry point of a command recall block
    CommandRecall,
    /// A command seal block
    CommandSeal,
    /// A command open block
    CommandOpen,
    /// This label is a temporary destination for implementing
    /// branching constructs.
    Temporary,
}

impl Display for LabelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelType::Action => write!(f, "action"),
            LabelType::CommandPolicy => write!(f, "policy"),
            LabelType::CommandRecall => write!(f, "recall"),
            LabelType::CommandSeal => write!(f, "seal"),
            LabelType::CommandOpen => write!(f, "open"),
            LabelType::Temporary => write!(f, "temp"),
        }
    }
}

/// Labels are branch targets and execution entry points.
#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct Label {
    /// The address of the label
    pub(crate) name: String,
    /// The type of the label
    pub(crate) ltype: LabelType,
}

impl Label {
    pub(crate) fn new(name: &str, ltype: LabelType) -> Label {
        Label {
            name: name.to_owned(),
            ltype,
        }
    }

    pub(crate) fn new_temp(name: &str) -> Label {
        Label {
            name: name.to_owned(),
            ltype: LabelType::Temporary,
        }
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ltype, self.name)
    }
}

/// This is the core policy machine type, which contains all of the state
/// of the machine and associated facts.
#[derive(Debug)]
pub struct Machine {
    // static state (things which do not change after compilation)
    /// The program memory
    pub(crate) progmem: Vec<Instruction>,
    /// Mapping of Label names to addresses
    pub(crate) labels: BTreeMap<Label, usize>,
    /// Fact schemas
    fact_defs: BTreeMap<String, ast::FactDefinition>,
    /// Struct schemas
    pub(crate) struct_defs: BTreeMap<String, Vec<ast::FieldDefinition>>,
    /// Mapping between program instructions and original code
    pub(crate) codemap: Option<CodeMap>,
}

impl Machine {
    /// Creates a `Machine` from a list of instructions.
    pub fn new<I>(instructions: I) -> Self
    where
        I: IntoIterator<Item = Instruction>,
    {
        Machine {
            progmem: Vec::from_iter(instructions),
            labels: BTreeMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            codemap: None,
        }
    }

    /// Creates an empty `Machine` with a given codemap. Used by the compiler.
    pub(crate) fn from_codemap(codemap: CodeMap) -> Self {
        Machine {
            progmem: vec![],
            labels: BTreeMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            codemap: Some(codemap),
        }
    }

    /// Create a RunState associated with this Machine.
    pub fn create_run_state<'a, M>(&'a self, io: &'a mut M) -> RunState<'a, M>
    where
        M: MachineIO<MachineStack>,
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

/// State stored when a call is made, and restored when it returns.
struct CallState {
    return_address: usize,
    defs: BTreeMap<String, Value>,
}

/// The "run state" of the machine. It's separated from the rest of
/// the VM so that it can be managed independently and potentially in
/// multiple simultaneous instances.
pub struct RunState<'a, M> {
    /// Reference to the underlying static machine data
    machine: &'a Machine,
    /// Named value definitions ("variables")
    defs: BTreeMap<String, Value>,
    /// The stack
    pub(crate) stack: MachineStack,
    /// The call state stack - stores return addresses and previous
    /// definitions when a function is called
    call_state: Vec<CallState>,
    /// The program counter
    pc: usize,
    /// I/O callbacks
    io: &'a mut M,
}

impl<'a, M> RunState<'a, M>
where
    M: MachineIO<MachineStack>,
{
    /// Create a new, empty MachineState
    pub fn new<'b>(machine: &'b Machine, io: &'b mut M) -> RunState<'a, M>
    where
        'b: 'a,
    {
        RunState {
            machine,
            defs: BTreeMap::new(),
            stack: MachineStack(vec![]),
            call_state: vec![],
            pc: 0,
            io,
        }
    }

    /// Get the source line associated with the current PC, if source
    /// is available.
    pub fn source_text(&self) -> Option<Span<'_>> {
        self.machine
            .codemap
            .as_ref()?
            .span_from_instruction(self.pc)
            .ok()
    }

    /// Internal function to produce a MachineError with location
    /// information.
    fn err(&self, err_type: MachineErrorType) -> MachineError {
        MachineError::from_position(err_type, self.pc, self.machine.codemap.as_ref())
    }

    /// Reset the machine state - undefine all named values, empty the
    /// stack, and set the program counter to zero.
    pub fn reset(&mut self) {
        self.defs.clear();
        self.stack.clear();
        self.pc = 0;
    }

    /// Get the program counter.
    pub fn pc(&self) -> usize {
        self.pc
    }

    /// Internal wrapper around [Stack::push] that translates
    /// [StackError] into [MachineError] with location information.
    fn ipush<V>(&mut self, value: V) -> Result<(), MachineError>
    where
        V: Into<Value>,
    {
        self.stack.push(value).map_err(|e| self.err(e))
    }

    /// Internal wrapper around [Stack::pop] that translates
    /// [StackError] into [MachineError] with location information.
    fn ipop<V>(&mut self) -> Result<V, MachineError>
    where
        V: TryFrom<Value, Error = MachineErrorType>,
    {
        self.stack.pop().map_err(|e| self.err(e))
    }

    /// Internal wrapper around [Stack::pop_value] that translates
    /// [StackError] into [MachineError] with location information.
    fn ipop_value(&mut self) -> Result<Value, MachineError> {
        self.stack.pop_value().map_err(|e| self.err(e))
    }

    /// Internal wrapper around [Stack::peek] that translates
    /// [StackError] into [MachineError] with location information.
    fn ipeek<V>(&mut self) -> Result<&mut V, MachineError>
    where
        V: ?Sized,
        Value: TryAsMut<V, Error = MachineErrorType>,
    {
        // A little bit of chicanery - copy the PC now so we don't
        // borrow from self when creating the error (as self.err()
        // does). We can't do that inside the closure because peek()
        // takes a mutable reference to self.
        let pc = self.pc;
        self.stack
            .peek()
            .map_err(|e| MachineError::from_position(e, pc, self.machine.codemap.as_ref()))
    }

    /// Validate a struct against defined schema.
    // TODO(chip): This does not distinguish between Commands and
    // Effects and it should.
    fn validate_struct_schema(&self, s: &Struct) -> Result<(), MachineError> {
        let err = self.err(MachineErrorType::InvalidSchema);

        match self.machine.struct_defs.get(&s.name) {
            Some(fields) => {
                // Check for struct fields that do not exist in the
                // definition.
                for f in &s.fields {
                    if !fields.iter().any(|v| &v.identifier == f.0) {
                        return Err(err);
                    }
                }
                // Ensure all defined fields exist and have the same
                // types.
                for f in fields {
                    match s.fields.get(&f.identifier) {
                        Some(f) => {
                            if f.vtype() != f.vtype() {
                                return Err(err);
                            }
                        }
                        None => return Err(err),
                    }
                }
                Ok(())
            }
            None => Err(err),
        }
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
            Instruction::Const(v) => {
                self.ipush(v)?;
            }
            Instruction::Def => {
                let key = self.ipop()?;
                let value = self.ipop_value()?;
                if self.defs.contains_key(&key) {
                    return Err(self.err(MachineErrorType::AlreadyDefined(key)));
                }
                self.defs.insert(key, value);
            }
            Instruction::Get => {
                let key: String = self.ipop()?;
                let v = self
                    .defs
                    .get(&key)
                    .ok_or_else(|| self.err(MachineErrorType::NotDefined(key)))?;
                self.ipush(v.to_owned())?;
            }
            Instruction::Swap(d) => {
                if d > self.stack.len() {
                    return Err(self.err(MachineErrorType::StackUnderflow));
                }
                if d == 0 {
                    return Err(self.err(MachineErrorType::InvalidInstruction));
                }
                let i1 = self.stack.len() - 1;
                let i2 = i1 - d;
                self.stack.0.swap(i1, i2);
            }
            Instruction::Dup(d) => {
                if d > self.stack.len() {
                    return Err(self.err(MachineErrorType::StackUnderflow));
                }
                let v = self.stack.0[self.stack.len() - d - 1].clone();
                self.ipush(v)?;
            }
            Instruction::Pop => {
                let _ = self.stack.pop_value();
            }
            Instruction::Block => todo!(),
            Instruction::End => todo!(),
            Instruction::Jump(t) => match t {
                Target::Unresolved(_) => return Err(self.err(MachineErrorType::UnresolvedTarget)),
                Target::Resolved(n) => {
                    // We set the PC and return here to skip the
                    // increment below. We could subtract 1 here to
                    // compensate, but that doesn't work when we jump
                    // to address 0.
                    self.pc = n;
                    return Ok(MachineStatus::Executing);
                }
            },
            Instruction::Branch(t) => {
                let conditional = self.ipop()?;
                if conditional {
                    match t {
                        Target::Unresolved(_) => {
                            return Err(self.err(MachineErrorType::UnresolvedTarget))
                        }
                        Target::Resolved(n) => {
                            self.pc = n;
                            return Ok(MachineStatus::Executing);
                        }
                    }
                }
            }
            Instruction::Next => todo!(),
            Instruction::Last => todo!(),
            Instruction::Call(t) => match t {
                Target::Unresolved(_) => return Err(self.err(MachineErrorType::UnresolvedTarget)),
                Target::Resolved(n) => {
                    // Take the old defs, emptying defs
                    let old_defs = core::mem::take(&mut self.defs);
                    // Store the current PC and name definitions. The
                    // PC will be incremented after return, so there's
                    // no need to increment here.
                    self.call_state.push(CallState {
                        return_address: self.pc,
                        defs: old_defs,
                    });
                    self.pc = n;
                    return Ok(MachineStatus::Executing);
                }
            },
            Instruction::Return => {
                let s = self
                    .call_state
                    .pop()
                    .ok_or_else(|| self.err(MachineErrorType::CallStack))?;
                self.defs = s.defs;
                self.pc = s.return_address;
            }
            Instruction::ExtCall(module, proc) => self.io.call(module, proc, &mut self.stack)?,
            Instruction::Exit => return Ok(MachineStatus::Exited),
            Instruction::Panic => return Ok(MachineStatus::Panicked),
            Instruction::Add | Instruction::Sub => {
                let b: i64 = self.ipop()?;
                let a: i64 = self.ipop()?;
                let r = match instruction {
                    Instruction::Add => a
                        .checked_add(b)
                        .ok_or(self.err(MachineErrorType::IntegerOverflow))?,
                    Instruction::Sub => a
                        .checked_sub(b)
                        .ok_or(self.err(MachineErrorType::IntegerOverflow))?,
                    _ => unreachable!(),
                };
                self.ipush(r)?;
            }
            Instruction::And | Instruction::Or => {
                let a = self.ipop()?;
                let b = self.ipop()?;
                let r = match instruction {
                    Instruction::And => a && b,
                    Instruction::Or => a || b,
                    _ => unreachable!(),
                };
                self.ipush(r)?;
            }
            Instruction::Not => {
                let a: &mut bool = self.ipeek()?;
                *a = !*a;
            }
            Instruction::Gt | Instruction::Lt | Instruction::Eq => {
                let b = self.ipop_value()?;
                let a = self.ipop_value()?;
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
                self.ipush(v)?;
            }
            Instruction::FactNew => {
                let name = self.ipop()?;
                let fact = Fact::new(name);
                self.ipush(fact)?;
            }
            Instruction::FactKeySet => {
                let varname = self.ipop()?;
                let v: HashableValue = self.ipop()?;
                let f: &mut Fact = self.ipeek()?;
                f.set_key(varname, v);
            }
            Instruction::FactValueSet => {
                let varname = self.ipop()?;
                let value = self.ipop_value()?;
                let f: &mut Fact = self.ipeek()?;
                f.set_value(varname, value);
            }
            Instruction::StructNew => {
                let name = self.ipop()?;
                let fields = BTreeMap::new();
                self.ipush(Struct { name, fields })?;
            }
            Instruction::StructSet => {
                let field_name = self.ipop()?;
                let value = self.ipop_value()?;
                let mut s: Struct = self.ipop()?;
                // Validate that the field is part of this structure
                // schema.
                let struct_def_fields = self
                    .machine
                    .struct_defs
                    .get(&s.name)
                    .ok_or_else(|| self.err(MachineErrorType::InvalidSchema))?;
                if !struct_def_fields.iter().any(|f| f.identifier == field_name) {
                    return Err(self.err(MachineErrorType::InvalidStructMember(field_name)));
                }
                s.fields.insert(field_name, value);
                self.ipush(s)?;
            }
            Instruction::StructGet => {
                let varname: String = self.ipop()?;
                let mut s: Struct = self.ipop()?;
                let v = s
                    .fields
                    .remove(&varname)
                    .ok_or_else(|| self.err(MachineErrorType::InvalidStructMember(varname)))?;
                self.ipush(v)?;
            }
            Instruction::Emit => {
                let s: Struct = self.ipop()?;
                self.validate_struct_schema(&s)?;

                let fields = s.fields.into_iter().map(|(k, v)| KVPair::new(&k, v));

                self.io.emit(s.name, fields);
            }
            Instruction::Create => {
                let f: Fact = self.ipop()?;
                self.io.fact_insert(f.name, f.keys, f.values)?;
            }
            Instruction::Delete => {
                let f: Fact = self.ipop()?;
                self.io.fact_delete(f.name, f.keys)?;
            }
            Instruction::Update => {
                let fact_to: Fact = self.ipop()?;
                let fact_from: Fact = self.ipop()?;
                let replaced_fact = {
                    let mut iter = self.io.fact_query(fact_from.name.clone(), fact_from.keys)?;
                    iter.next()
                        .ok_or_else(|| self.err(MachineErrorType::InvalidFact))??
                };
                self.io.fact_delete(fact_from.name, replaced_fact.0)?;
                self.io
                    .fact_insert(fact_to.name, fact_to.keys, fact_to.values)?;
            }
            Instruction::Effect => {
                let s: Struct = self.ipop()?;
                self.validate_struct_schema(&s)?;
                let fields = s.fields.into_iter().map(|(k, v)| KVPair::new(&k, v));
                self.io.effect(s.name, fields);
            }
            Instruction::Query => {
                let qf: Fact = self.ipop()?;
                let result = {
                    let mut iter = self.io.fact_query(qf.name.clone(), qf.keys)?;
                    // Find the first match, or the first error
                    iter.find_map(|r| match r {
                        Ok(f) => {
                            if fact_value_subset_match(&qf.values, &f.1) {
                                Some(Ok(f))
                            } else {
                                None
                            }
                        }
                        Err(e) => Some(Err(e)),
                    })
                };
                match result {
                    Some(r) => {
                        let f = r?;
                        let mut fields: Vec<KVPair> = vec![];
                        fields.append(&mut f.0.into_iter().map(|e| e.into()).collect());
                        fields.append(&mut f.1.into_iter().map(|e| e.into()).collect());
                        let s = Struct::new(&qf.name, &fields);
                        self.ipush(s)?;
                    }
                    None => self.ipush(Value::None)?,
                }
            }
            Instruction::Exists => {
                let qf: Fact = self.ipop()?;
                let exists = {
                    let mut iter = self.io.fact_query(qf.name.clone(), qf.keys)?;
                    iter.find_map(|r| match r {
                        Ok(f) => {
                            if fact_value_subset_match(&qf.values, &f.1) {
                                Some(Ok(true))
                            } else {
                                None
                            }
                        }
                        Err(e) => Some(Err(e)),
                    })
                };
                match exists {
                    Some(res) => self.ipush(Value::Bool(res?))?,
                    None => self.ipush(Value::Bool(false))?,
                }
            }
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
    pub fn set_pc_by_label(&mut self, label: Label) -> Result<(), MachineError> {
        let addr = self
            .machine
            .labels
            .get(&label)
            .ok_or_else(|| self.err(MachineErrorType::InvalidAddress))?;
        self.pc = *addr;
        Ok(())
    }

    /// Set up machine state for a command policy call
    pub fn setup_command(
        &mut self,
        name: &str,
        label_type: LabelType,
        this_data: &Struct,
    ) -> Result<(), MachineError> {
        self.set_pc_by_label(Label::new(name, label_type))?;
        self.defs.clear();
        self.call_state.clear();
        self.defs
            .insert(String::from("this"), Value::Struct(this_data.to_owned()));
        Ok(())
    }

    /// Call a command policy loaded into the VM by name. Accepts a
    /// `Struct` containing the Command's data. Returns a Vec of effect
    /// structs or a MachineError.
    pub fn call_command_policy(
        &mut self,
        name: &str,
        this_data: &Struct,
    ) -> Result<MachineStatus, MachineError> {
        self.setup_command(name, LabelType::CommandPolicy, this_data)?;
        self.run()
    }

    /// Call a command policy loaded into the VM by name. Accepts a
    /// `Struct` containing the Command's data. Returns a Vec of effect
    /// structs or a MachineError.
    pub fn call_command_recall(
        &mut self,
        name: &str,
        this_data: &Struct,
    ) -> Result<MachineStatus, MachineError> {
        self.setup_command(name, LabelType::CommandRecall, this_data)?;
        self.run()
    }

    /// Set up machine state for an action call.
    pub fn setup_action<Args>(&mut self, name: &str, args: Args) -> Result<(), MachineError>
    where
        Args: IntoIterator,
        Args::Item: Into<Value>,
    {
        self.set_pc_by_label(Label::new(name, LabelType::Action))?;
        for a in args {
            self.ipush(a.into())?;
        }
        self.defs.clear();
        self.call_state.clear();

        Ok(())
    }

    /// Call an action loaded into the VM by name. Accepts a list of
    /// arguments to the function, which must match the number of
    /// arguments expected. Returns a MachineError on failure.
    // TODO(chip): I don't really like how V: Into<Value> works here
    // because it still means all of the args have to have the same
    // type.
    pub fn call_action<Args>(
        &mut self,
        name: &str,
        args: Args,
    ) -> Result<MachineStatus, MachineError>
    where
        Args: IntoIterator,
        Args::Item: Into<Value>,
    {
        self.setup_action(name, args)?;
        self.run()
    }
}

/// An implementation of [`Stack`].
pub struct MachineStack(pub(crate) Vec<Value>);

impl MachineStack {
    /// Creates an empty stack.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Returns the number of values in the stack.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

impl Stack for MachineStack {
    fn push_value(&mut self, value: Value) -> Result<(), MachineErrorType> {
        self.0.push(value);
        Ok(())
    }

    fn pop_value(&mut self) -> Result<Value, MachineErrorType> {
        self.0.pop().ok_or(MachineErrorType::StackUnderflow)
    }

    fn peek_value(&mut self) -> Result<&mut Value, MachineErrorType> {
        self.0.last_mut().ok_or(MachineErrorType::StackUnderflow)
    }
}

impl<'a, M> Display for RunState<'a, M>
where
    M: MachineIO<MachineStack>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "# Name table:")?;
        for (k, v) in &self.machine.labels {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        write!(f, "# Current defs")?;
        if !self.call_state.is_empty() {
            write!(f, " ({} stacked)", self.call_state.len())?;
        }
        writeln!(f, ":")?;
        for (k, v) in &self.defs {
            writeln!(f, "  {}: {}", k, v)?;
        }
        writeln!(f, "# Stack:")?;
        for v in &self.stack.0 {
            write!(f, "{} ", v)?;
        }
        writeln!(f)?;
        writeln!(f, "# Program:")?;
        for (addr, instr) in self.machine.progmem.iter().enumerate() {
            for (k, v) in &self.machine.labels {
                if *v == addr {
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
