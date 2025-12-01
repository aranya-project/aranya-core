extern crate alloc;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use core::{
    cell::RefCell,
    fmt::{self, Display},
};

use aranya_crypto::policy::CmdId;
use aranya_policy_ast::{self as ast, Identifier, ident};
use aranya_policy_module::{
    ActionDef, CodeMap, CommandDef, ExitReason, Fact, FactKey, FactValue, HashableValue,
    Instruction, KVPair, Label, LabelType, Module, ModuleData, ModuleV0, Struct, Target, TryAsMut,
    UnsupportedVersion, Value, ValueConversionError, named::NamedMap,
};
use buggy::{Bug, BugExt as _};
use heapless::Vec as HVec;

#[cfg(feature = "bench")]
use crate::bench::{Stopwatch, bench_aggregate};
use crate::{
    ActionContext, CommandContext, OpenContext, PolicyContext, SealContext,
    error::{MachineError, MachineErrorType},
    io::MachineIO,
    scope::ScopeManager,
    stack::Stack,
};

const STACK_SIZE: usize = 100;

/// Compares a fact's keys and values to its schema.
/// Bind values are omitted from keys/values, so we only compare the given keys/values. This allows us to do partial matches.
fn validate_fact_schema(fact: &Fact, schema: &ast::FactDefinition) -> bool {
    if fact.name != schema.identifier.name {
        return false;
    }

    for key in &fact.keys {
        let Some(key_value) = schema
            .key
            .iter()
            .find(|k| k.identifier.name == key.identifier)
        else {
            return false;
        };

        if !key.value.vtype().matches(&key_value.field_type.kind) {
            return false;
        }
    }

    for value in &fact.values {
        // Ensure named value exists in schema
        let Some(schema_value) = schema
            .value
            .iter()
            .find(|v| v.identifier.name == value.identifier)
        else {
            return false;
        };

        // Ensure fact value type matches schema
        let Some(value_type) = value.value.vtype() else {
            return false;
        };
        if !value_type.matches(&schema_value.field_type.kind) {
            return false;
        }
    }
    true
}

/// Compares a fact to the given keys and values.
/// NOTE that Bind keys/values are not included in the fact literal (see compile_fact_literal), so we only compare key/value pairs with exact values.
///
/// Returns true if all given keys and values match the fact.
fn fact_match(query: &Fact, keys: &[FactKey], values: &[FactValue]) -> bool {
    if !keys.starts_with(&query.keys) {
        return false;
    }

    for qv in &query.values {
        if let Some(v) = values.iter().find(|v| v.identifier == qv.identifier) {
            // value found, but types don't match
            if v.value != qv.value {
                return false;
            }
        } else {
            // invalid value name
            return false;
        }
    }

    true
}

/// Status of machine execution after stepping through each instruction.
///
/// These are expected states entered after executing instructions, as opposed to MachineErrors,
/// which are produced by invalid instructions or data.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum MachineStatus {
    /// Execution will proceed as normal to the next instruction
    Executing,
    /// Execution has ended
    Exited(ExitReason),
}

impl Display for MachineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Executing => write!(f, "Executing"),
            Self::Exited(reason) => write!(f, "Exited: {}", reason),
        }
    }
}

/// The core policy VM type.
///
/// This contains the static data for the VM - instructions, entry points, schemas, globally scoped
/// static values, and optionally a mapping between instructions and source code locations. For the
/// VM's runtime data, see [`create_run_state()`](Self::create_run_state) and [`RunState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Machine {
    /// The program memory
    pub progmem: Vec<Instruction>,
    /// Mapping of Label names to addresses
    pub labels: BTreeMap<Label, usize>,
    /// Action definitions
    pub action_defs: NamedMap<ActionDef>,
    /// Command definitions
    pub command_defs: NamedMap<CommandDef>,
    /// Fact schemas
    pub fact_defs: BTreeMap<Identifier, ast::FactDefinition>,
    /// Struct schemas
    pub struct_defs: BTreeMap<Identifier, Vec<ast::FieldDefinition>>,
    /// Enum definitions
    pub enum_defs: BTreeMap<Identifier, BTreeMap<Identifier, i64>>,
    /// Mapping between program instructions and original code
    pub codemap: Option<CodeMap>,
    /// Globally scoped variables
    pub globals: BTreeMap<Identifier, Value>,
}

impl Machine {
    /// Creates a `Machine` from a list of instructions.
    pub fn new<I>(instructions: I) -> Self
    where
        I: IntoIterator<Item = Instruction>,
    {
        Self {
            progmem: Vec::from_iter(instructions),
            labels: BTreeMap::new(),
            action_defs: NamedMap::new(),
            command_defs: NamedMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            enum_defs: BTreeMap::new(),
            codemap: None,
            globals: BTreeMap::new(),
        }
    }

    /// Creates an empty `Machine` with a given codemap. Used by the compiler.
    pub fn from_codemap(codemap: CodeMap) -> Self {
        Self {
            progmem: vec![],
            labels: BTreeMap::new(),
            action_defs: NamedMap::new(),
            command_defs: NamedMap::new(),
            fact_defs: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            enum_defs: BTreeMap::new(),
            codemap: Some(codemap),
            globals: BTreeMap::new(),
        }
    }

    /// Creates a `Machine` from a `Module`.
    pub fn from_module(m: Module) -> Result<Self, UnsupportedVersion> {
        match m.data {
            ModuleData::V0(m) => Ok(Self {
                progmem: m.progmem.into(),
                labels: m.labels,
                action_defs: m.action_defs,
                command_defs: m.command_defs,
                fact_defs: m.fact_defs,
                struct_defs: m.struct_defs,
                enum_defs: m.enum_defs,
                codemap: m.codemap,
                globals: m.globals,
            }),
        }
    }

    /// Converts the `Machine` into a `Module`.
    pub fn into_module(self) -> Module {
        Module {
            data: ModuleData::V0(ModuleV0 {
                progmem: self.progmem.into_boxed_slice(),
                labels: self.labels,
                action_defs: self.action_defs,
                command_defs: self.command_defs,
                fact_defs: self.fact_defs,
                struct_defs: self.struct_defs,
                enum_defs: self.enum_defs,
                codemap: self.codemap,
                globals: self.globals,
            }),
        }
    }

    /// Parses an enum reference (e.g. `Color::Red`) into a [`Value::Enum`].
    pub fn parse_enum(&self, value: &str) -> Result<Value, MachineError> {
        let Some((name, variant)) = value.split_once("::") else {
            return Err(MachineError::new(MachineErrorType::invalid_type(
                "<Enum>::<Variant>",
                value,
                "invalid enum reference",
            )));
        };

        let (name, variants) = self
            .enum_defs
            .get_key_value(name)
            .ok_or_else(|| MachineErrorType::NotDefined(alloc::format!("enum {name}")))?;
        let int_value = variants.get(variant).ok_or_else(|| {
            MachineErrorType::NotDefined(alloc::format!("no value `{variant}` in enum `{name}`"))
        })?;

        Ok(Value::Enum(name.clone(), *int_value))
    }

    /// Create a RunState associated with this Machine.
    pub fn create_run_state<'a, M>(
        &'a self,
        io: &'a RefCell<M>,
        ctx: CommandContext,
    ) -> RunState<'a, M>
    where
        M: MachineIO<MachineStack>,
    {
        RunState::new(self, io, ctx)
    }

    /// Call an action
    pub fn call_action<Args, M>(
        &mut self,
        name: Identifier,
        args: Args,
        io: &'_ RefCell<M>,
        ctx: CommandContext,
    ) -> Result<ExitReason, MachineError>
    where
        Args: IntoIterator,
        Args::Item: Into<Value>,
        M: MachineIO<MachineStack>,
    {
        let mut rs = self.create_run_state(io, ctx);
        rs.call_action(name, args)
    }

    /// Call a command
    pub fn call_command_policy<M>(
        &mut self,
        this_data: Struct,
        envelope: Struct,
        io: &'_ RefCell<M>,
        ctx: CommandContext,
    ) -> Result<ExitReason, MachineError>
    where
        M: MachineIO<MachineStack>,
    {
        let mut rs = self.create_run_state(io, ctx);
        rs.call_command_policy(this_data, envelope)
    }
}

impl Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// The "run state" of the machine.
///
/// This includes variables, the stack, the call stack, the program counter, I/O, and the current
/// execution context. Most commonly created from [`Machine::create_run_state()`]. It's separated
/// from the rest of the VM so that it can be managed independently and potentially in multiple
/// simultaneous instances.
pub struct RunState<'a, M: MachineIO<MachineStack>> {
    /// Reference to the underlying static machine data
    machine: &'a Machine,
    /// Named value definitions ("variables")
    scope: ScopeManager<'a>,
    /// The stack
    pub stack: MachineStack,
    /// The call state stack - stores return addresses
    call_state: Vec<usize>,
    /// The program counter
    pc: usize,
    /// I/O callbacks
    io: &'a RefCell<M>,
    /// Execution Context (actually used for more than Commands)
    ctx: CommandContext,
    // Cursors for `QueryStart` results
    query_iter_stack: Vec<M::QueryIterator>,
    #[cfg(feature = "bench")]
    stopwatch: Stopwatch,
}

impl<'a, M> RunState<'a, M>
where
    M: MachineIO<MachineStack>,
{
    /// Create a new, empty MachineState
    pub fn new(machine: &'a Machine, io: &'a RefCell<M>, ctx: CommandContext) -> Self {
        RunState {
            machine,
            scope: ScopeManager::new(&machine.globals),
            stack: MachineStack(HVec::new()),
            call_state: vec![],
            pc: 0,
            io,
            ctx,
            query_iter_stack: vec![],
            #[cfg(feature = "bench")]
            stopwatch: Stopwatch::new(),
        }
    }

    /// Returns the current context
    pub fn get_context(&self) -> &CommandContext {
        &self.ctx
    }

    /// Set the internal context object to a new reference. The old reference is not
    /// preserved. This is a hack to allow a policy context to mutate into a recall context
    /// when recall happens.
    pub fn set_context(&mut self, ctx: CommandContext) {
        self.ctx = ctx;
    }

    /// Update the context with a new head ID, e.g. after publishing a command.
    pub fn update_context_with_new_head(&mut self, new_head_id: CmdId) -> Result<(), Bug> {
        self.ctx = self.ctx.with_new_head(new_head_id)?;
        Ok(())
    }

    /// Returns a string describing the source code at the current PC,
    /// if available.
    pub fn source_location(&self) -> Option<String> {
        let source_span = self
            .machine
            .codemap
            .as_ref()?
            .span_from_instruction(self.pc)
            .ok();
        if let Some(span) = source_span {
            let (row, col) = span.start_linecol();
            Some(alloc::format!(
                "at row {} col {}:\n\t{}",
                row,
                col,
                span.as_str()
            ))
        } else {
            None
        }
    }

    /// Internal function to produce a MachineError with location
    /// information.
    fn err(&self, err_type: MachineErrorType) -> MachineError {
        MachineError::from_position(err_type, self.pc, self.machine.codemap.as_ref())
    }

    /// Reset the machine state - undefine all named values, empty the
    /// stack, and set the program counter to zero.
    pub fn reset(&mut self) {
        self.scope.clear();
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
        V: TryFrom<Value, Error = ValueConversionError>,
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
        Value: TryAsMut<V, Error = ValueConversionError>,
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
    fn validate_struct_schema(&mut self, s: &Struct) -> Result<(), MachineError> {
        #[cfg(feature = "bench")]
        self.stopwatch.start("validate_struct_schema");

        let mk_err = || self.err(MachineErrorType::InvalidSchema(s.name.clone()));

        match self.machine.struct_defs.get(&s.name) {
            Some(fields) => {
                // Check for struct fields that do not exist in the
                // definition.
                for f in &s.fields {
                    if !fields.iter().any(|v| &v.identifier.name == f.0) {
                        return Err(mk_err());
                    }
                }
                // Ensure all defined fields exist and have the same
                // types.
                for f in fields {
                    match s.fields.get(&f.identifier.name) {
                        Some(v) => {
                            if !v.fits_type(&f.field_type) {
                                return Err(mk_err());
                            }
                        }
                        None => {
                            return Err(mk_err());
                        }
                    }
                }

                #[cfg(feature = "bench")]
                self.stopwatch.stop();

                Ok(())
            }
            None => Err(mk_err()),
        }
    }

    /// Execute one machine instruction and return the status of the
    /// machine or a MachineError.
    pub fn step(&mut self) -> Result<MachineStatus, MachineError> {
        if self.pc() >= self.machine.progmem.len() {
            return Err(self.err(MachineErrorType::InvalidAddress(ident!("pc"))));
        }
        // Clone the instruction so we don't take an immutable
        // reference to self while we manipulate the stack later.
        let instruction = self.machine.progmem[self.pc()].clone();

        match instruction {
            Instruction::Const(v) => {
                self.ipush(v)?;
            }
            Instruction::Def(key) => {
                let value = self.ipop_value()?;
                self.scope.set(key, value)?;
            }
            Instruction::Get(key) => {
                let value = self.scope.get(&key)?;
                self.ipush(value)?;
            }
            Instruction::Dup => {
                let v = self.stack.peek_value()?.clone();
                self.ipush(v)?;
            }
            Instruction::Pop => {
                let _ = self.stack.pop_value();
            }
            Instruction::Block => self.scope.enter_block().map_err(|e| self.err(e))?,
            Instruction::End => self.scope.exit_block().map_err(|e| self.err(e))?,
            Instruction::Jump(t) => match t {
                Target::Unresolved(label) => {
                    return Err(self.err(MachineErrorType::UnresolvedTarget(label)));
                }
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
                        Target::Unresolved(label) => {
                            return Err(self.err(MachineErrorType::UnresolvedTarget(label)));
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
                Target::Unresolved(label) => {
                    return Err(self.err(MachineErrorType::UnresolvedTarget(label)));
                }
                Target::Resolved(n) => {
                    self.scope.enter_function();
                    // Store the current PC. The PC will be incremented after return,
                    // so there's no need to increment here.
                    self.call_state.push(self.pc);
                    self.pc = n;
                    return Ok(MachineStatus::Executing);
                }
            },
            Instruction::Return => {
                // When the outermost function completes, there is nothing left to do, so exit.
                if self.call_state.is_empty() {
                    return Ok(MachineStatus::Exited(ExitReason::Normal));
                }
                self.pc = self
                    .call_state
                    .pop()
                    .ok_or_else(|| self.err(MachineErrorType::CallStack))?;
                self.scope.exit_function().map_err(|e| self.err(e))?;
            }
            Instruction::ExtCall(module, proc) => {
                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .call(module, proc, &mut self.stack, &self.ctx)?;
            }
            Instruction::Exit(reason) => return Ok(MachineStatus::Exited(reason)),
            Instruction::Add | Instruction::Sub => {
                let b: i64 = self.ipop()?;
                let a: i64 = self.ipop()?;
                let r = match instruction {
                    Instruction::Add => a.checked_add(b),
                    Instruction::Sub => a.checked_sub(b),
                    _ => unreachable!(),
                };
                // Checked operations return Optional<Int>
                self.ipush(r)?;
            }
            Instruction::SaturatingAdd | Instruction::SaturatingSub => {
                let b: i64 = self.ipop()?;
                let a: i64 = self.ipop()?;
                let r = match instruction {
                    Instruction::SaturatingAdd => a.saturating_add(b),
                    Instruction::SaturatingSub => a.saturating_sub(b),
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
                    Instruction::Gt => match (&a, &b) {
                        (Value::Int(ia), Value::Int(ib)) => ia > ib,
                        _ => {
                            let a_type = a.type_name();
                            let b_type = b.type_name();
                            return Err(self.err(MachineErrorType::invalid_type(
                                "Int, Int",
                                alloc::format!("{a_type}, {b_type}"),
                                "Greater-than comparison",
                            )));
                        }
                    },
                    Instruction::Lt => match (&a, &b) {
                        (Value::Int(ia), Value::Int(ib)) => ia < ib,
                        _ => {
                            let a_type = a.type_name();
                            let b_type = b.type_name();
                            return Err(self.err(MachineErrorType::invalid_type(
                                "Int, Int",
                                alloc::format!("{a_type}, {b_type}"),
                                "Less-than comparison",
                            )));
                        }
                    },
                    // This leans heavily on PartialEq to do the work.
                    // Equality depends on values having the same type and
                    // interior value.
                    Instruction::Eq => a == b,
                    _ => unreachable!(),
                };
                self.ipush(v)?;
            }
            Instruction::FactNew(name) => {
                let fact = Fact::new(name);
                self.ipush(fact)?;
            }
            Instruction::FactKeySet(varname) => {
                let v: HashableValue = self.ipop()?;
                let f: &mut Fact = self.ipeek()?;
                f.set_key(varname, v);
            }
            Instruction::FactValueSet(varname) => {
                let value = self.ipop_value()?;
                let f: &mut Fact = self.ipeek()?;
                f.set_value(varname, value);
            }
            Instruction::StructNew(name) => {
                let fields = BTreeMap::new();
                self.ipush(Struct { name, fields })?;
            }
            Instruction::StructSet(field_name) => {
                let value = self.ipop_value()?;
                let mut s: Struct = self.ipop()?;
                // Validate that the field is part of this structure
                // schema.
                let struct_def_fields = self
                    .machine
                    .struct_defs
                    .get(&s.name)
                    .ok_or_else(|| self.err(MachineErrorType::InvalidSchema(s.name.clone())))?;
                if !struct_def_fields
                    .iter()
                    .any(|f| f.identifier.name == field_name)
                {
                    return Err(self.err(MachineErrorType::InvalidStructMember(field_name)));
                }
                s.fields.insert(field_name, value);
                self.ipush(s)?;
            }
            Instruction::StructGet(varname) => {
                let mut s: Struct = self.ipop()?;
                let v = s
                    .fields
                    .remove(&varname)
                    .ok_or_else(|| self.err(MachineErrorType::InvalidStructMember(varname)))?;
                self.ipush(v)?;
            }
            Instruction::MStructSet(n) => {
                let n: usize = n.into();
                let mut field_name_value_pairs = Vec::with_capacity(n);

                for _ in 0..n {
                    let field_val = self.ipop_value()?;
                    let field_name = self.ipop::<Identifier>()?;

                    field_name_value_pairs.push((field_name, field_val));
                }

                let mut target: Struct = self.ipop()?;
                let struct_def_fields =
                    self.machine.struct_defs.get(&target.name).ok_or_else(|| {
                        self.err(MachineErrorType::InvalidSchema(target.name.clone()))
                    })?;

                for (field_name, field_val) in field_name_value_pairs {
                    let Some(field_defn) = struct_def_fields
                        .iter()
                        .find(|f| f.identifier.name == field_name)
                    else {
                        return Err(self.err(MachineErrorType::InvalidStructMember(field_name)));
                    };

                    if !field_val.fits_type(&field_defn.field_type) {
                        return Err(self.err(MachineErrorType::InvalidStructMember(field_name)));
                    }

                    target.fields.insert(field_name, field_val);
                }
                self.ipush(target)?;
            }
            Instruction::MStructGet(n) => {
                let field_names = (0..n.into())
                    .map(|_| self.ipop::<Identifier>())
                    .collect::<Result<Vec<_>, _>>()?;
                let mut s: Struct = self.ipop()?;

                for field_name in field_names {
                    let v = s.fields.remove(&field_name).ok_or_else(|| {
                        self.err(MachineErrorType::InvalidStructMember(field_name.clone()))
                    })?;

                    self.ipush(field_name)?;
                    self.ipush(v)?;
                }
            }
            Instruction::Publish => {
                let command_struct: Struct = self.ipop()?;
                self.validate_struct_schema(&command_struct)?;
                self.ipush(Value::Struct(command_struct))?;

                self.pc = self.pc.checked_add(1).assume("self.pc + 1 must not wrap")?;
                return Ok(MachineStatus::Exited(ExitReason::Yield));
            }
            Instruction::Create => {
                let f: Fact = self.ipop()?;
                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .fact_insert(f.name, f.keys, f.values)?;
            }
            Instruction::Delete => {
                let f: Fact = self.ipop()?;
                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .fact_delete(f.name, f.keys)?;
            }
            Instruction::Update => {
                let fact_to: Fact = self.ipop()?;
                let mut fact_from: Fact = self.ipop()?;
                let mut replaced_fact = {
                    let mut iter = self
                        .io
                        .try_borrow()
                        .assume("should be able to borrow io")?
                        .fact_query(fact_from.name.clone(), fact_from.keys)?;
                    iter.next().ok_or_else(|| {
                        self.err(MachineErrorType::InvalidFact(fact_from.name.clone()))
                    })??
                };

                if !fact_from.values.is_empty() {
                    let replaced_fact_values = &mut replaced_fact.1;

                    replaced_fact_values
                        .sort_unstable_by(|v1, v2| v1.identifier.cmp(&v2.identifier));
                    fact_from
                        .values
                        .sort_unstable_by(|v1, v2| v1.identifier.cmp(&v2.identifier));

                    if replaced_fact_values.as_slice() != fact_from.values.as_slice() {
                        return Err(self.err(MachineErrorType::InvalidFact(fact_from.name.clone())));
                    }
                }

                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .fact_delete(fact_from.name, replaced_fact.0)?;
                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .fact_insert(fact_to.name, fact_to.keys, fact_to.values)?;
            }
            Instruction::Emit => {
                let s: Struct = self.ipop()?;
                self.validate_struct_schema(&s)?;
                let fields = s.fields.into_iter().map(|(k, v)| KVPair::new(k, v));
                let (command, recall) = match &self.ctx {
                    CommandContext::Policy(ctx) => (ctx.id, false),
                    CommandContext::Recall(ctx) => (ctx.id, true),
                    _ => {
                        return Err(
                            self.err(MachineErrorType::BadState("Emit: wrong command context"))
                        );
                    }
                };
                self.io
                    .try_borrow_mut()
                    .assume("should be able to borrow io")?
                    .effect(s.name, fields, command, recall);
            }
            Instruction::Query => {
                let qf: Fact = self.ipop()?;

                // Before we spend time fetching facts from storage, make sure the given fact literal is valid.
                self.validate_fact_literal(&qf)?;

                let result = {
                    let mut iter = self
                        .io
                        .try_borrow()
                        .assume("should be able to borrow io")?
                        .fact_query(qf.name.clone(), qf.keys.clone())?;
                    // Find the first match, or the first error
                    iter.find_map(|r| match r {
                        Ok(f) => {
                            if fact_match(&qf, &f.0, &f.1) {
                                Some(Ok(f))
                            } else {
                                None
                            }
                        }
                        Err(e) => Some(Err(e)),
                    })
                };
                let maybe_fact = result.transpose()?.map(|f| {
                    let mut fields: Vec<KVPair> = vec![];
                    fields.append(&mut f.0.into_iter().map(Into::into).collect());
                    fields.append(&mut f.1.into_iter().map(Into::into).collect());
                    Struct::new(qf.name, fields)
                });
                self.ipush(maybe_fact)?;
            }
            Instruction::FactCount(limit) => {
                let fact: Fact = self.ipop()?;
                self.validate_fact_literal(&fact)?;

                let mut count = 0;
                {
                    let mut iter = self
                        .io
                        .try_borrow()
                        .assume("should be able to borrow io")?
                        .fact_query(fact.name.clone(), fact.keys.clone())?;

                    while count < limit {
                        let Some(r) = iter.next() else { break };
                        match r {
                            Ok(f) => {
                                if fact_match(&fact, &f.0, &f.1) {
                                    count = count
                                        .checked_add(1)
                                        .assume("should be able to increment fact counter")?;
                                }
                            }
                            Err(e) => return Err(self.err(MachineErrorType::IO(e))),
                        }
                    }
                }

                self.ipush(Value::Int(count))?;
            }
            Instruction::QueryStart => {
                let fact: Fact = self.ipop()?;
                self.validate_fact_literal(&fact)?;
                let iter = self
                    .io
                    .try_borrow()
                    .assume("should be able to borrow io")?
                    .fact_query(fact.name, fact.keys)?;
                self.query_iter_stack.push(iter);
            }
            Instruction::QueryNext(ident) => {
                // Fetch next fact from iterator
                let iter = self.query_iter_stack.last_mut().ok_or_else(|| {
                    MachineError::from_position(
                        MachineErrorType::BadState("QueryNext: no results"),
                        self.pc,
                        self.machine.codemap.as_ref(),
                    )
                })?;
                // Update `as` variable value and push an end-of-results bool.
                match iter.next() {
                    Some(result) => {
                        let (k, v) = result?;
                        let mut fields: Vec<KVPair> = vec![];
                        fields.append(&mut k.into_iter().map(Into::into).collect());
                        fields.append(&mut v.into_iter().map(Into::into).collect());
                        let s = Struct::new(ident.clone(), fields);
                        self.scope.set(ident, Value::Struct(s))?;
                        self.ipush(Value::Bool(false))?;
                    }
                    None => {
                        // When there are no more results, dispose of the iterator.
                        self.query_iter_stack.pop();
                        self.ipush(Value::Bool(true))?;
                    }
                }
            }
            Instruction::Serialize => {
                let CommandContext::Seal(SealContext { name, .. }) = &self.ctx else {
                    return Err(self.err(MachineErrorType::BadState(
                        "Serialize: expected seal context",
                    )));
                };
                let name = name.clone();

                let command_struct: Struct = self.ipop()?;
                if command_struct.name != name {
                    return Err(MachineError::from_position(
                        MachineErrorType::BadState(
                            "Serialize: context name doesn't match command name",
                        ),
                        self.pc,
                        self.machine.codemap.as_ref(),
                    ));
                }
                let bytes = postcard::to_allocvec(&command_struct).map_err(|_| {
                    self.err(MachineErrorType::Unknown(String::from(
                        "could not serialize command Struct",
                    )))
                })?;
                self.ipush(bytes)?;
            }
            Instruction::Deserialize => {
                let CommandContext::Open(OpenContext { name, .. }) = &self.ctx else {
                    return Err(MachineError::from_position(
                        MachineErrorType::InvalidInstruction,
                        self.pc,
                        self.machine.codemap.as_ref(),
                    ));
                };
                let name = name.clone();

                let bytes: Vec<u8> = self.ipop()?;
                let s: Struct = postcard::from_bytes(&bytes).map_err(|_| {
                    MachineError::from_position(
                        MachineErrorType::Unknown(String::from("could not deserialize Struct")),
                        self.pc,
                        self.machine.codemap.as_ref(),
                    )
                })?;
                if name != s.name.as_str() {
                    return Err(MachineError::from_position(
                        MachineErrorType::InvalidInstruction,
                        self.pc,
                        self.machine.codemap.as_ref(),
                    ));
                }
                self.ipush(s)?;
            }
            Instruction::Some => {
                let value = self.ipop_value()?;
                self.ipush(Value::Option(Some(Box::new(value))))?;
            }
            Instruction::Unwrap => {
                let value = self.ipop_value()?;
                if let Value::Option(opt) = value {
                    if let Some(inner) = opt {
                        self.ipush(*inner)?;
                    } else {
                        return Err(self.err(MachineErrorType::Unknown("unwrapped None".into())));
                    }
                } else {
                    return Err(self.err(MachineErrorType::invalid_type(
                        "Option[_]",
                        value.type_name(),
                        "Option[T] -> T",
                    )));
                }
            }
            Instruction::Meta(_m) => {}
            Instruction::Cast(identifier) => {
                let value = self.ipop_value()?;
                match value {
                    Value::Struct(s) => {
                        // make sure identifier is a valid struct name
                        let rhs_struct =
                            self.machine.struct_defs.get(&identifier).ok_or_else(|| {
                                self.err(MachineErrorType::NotDefined(alloc::format!(
                                    "struct `{}`",
                                    identifier
                                )))
                            })?;

                        // Check that all required fields exist and have matching types
                        for field in rhs_struct {
                            let field_name = &field.identifier;
                            let field_type = &field.field_type;

                            // Check if the source struct has this field
                            let value = s.fields.get(&field_name.name).ok_or_else(|| {
                                self.err(MachineErrorType::Unknown(alloc::format!(
                                    "cannot cast to `struct {}`: missing field `{}`",
                                    identifier,
                                    field_name
                                )))
                            })?;

                            // Check if the type matches
                            if !value.fits_type(field_type) {
                                return Err(self.err(MachineErrorType::Unknown(alloc::format!(
                                    "cannot cast to `struct {}`: field `{}` has wrong type (expected `{}`, found `{}`)",
                                    identifier, field_name, field_type, value.type_name()
                                ))));
                            }
                        }

                        // replace value on stack with clone, under new name
                        let mut s = s;
                        s.name = identifier.clone();
                        self.ipush(Value::Struct(s))?;
                    }
                    _ => {
                        return Err(self.err(MachineErrorType::invalid_type(
                            "Struct",
                            value.type_name(),
                            "Cast LHS",
                        )));
                    }
                }
            }
        }

        self.pc = self.pc.checked_add(1).assume("self.pc + 1 must not wrap")?;

        Ok(MachineStatus::Executing)
    }

    /// Execute machine instructions while each instruction returns
    /// MachineStatus::Executing. Returns the ExitReason it exited
    /// with, or an error.
    pub fn run(&mut self) -> Result<ExitReason, MachineError> {
        loop {
            #[cfg(feature = "bench")]
            {
                if let Some(instruction) = self.machine.progmem.get(self.pc()) {
                    if let Some(name) = instruction.to_string().split_whitespace().next() {
                        self.stopwatch.start(name);
                    }
                }
            }

            let result = self
                .step()
                .map_err(|err| err.with_position(self.pc, self.machine.codemap.as_ref()))?;

            #[cfg(feature = "bench")]
            if !self.stopwatch.measurement_stack.is_empty() {
                self.stopwatch.stop();
            }

            if let MachineStatus::Exited(reason) = result {
                #[cfg(feature = "bench")]
                bench_aggregate(&mut self.stopwatch);
                return Ok(reason);
            }
        }
    }

    /// Set the program counter to the given label.
    pub fn set_pc_by_label(&mut self, label: &Label) -> Result<(), MachineError> {
        let addr: &usize = self
            .machine
            .labels
            .get(label)
            .ok_or_else(|| self.err(MachineErrorType::InvalidAddress(label.name.clone())))?;
        self.pc = *addr;
        Ok(())
    }

    /// Set up machine state for a command policy call
    pub fn setup_command(
        &mut self,
        label_type: LabelType,
        this_data: Struct,
    ) -> Result<(), MachineError> {
        let name = this_data.name.clone();

        #[cfg(feature = "bench")]
        self.stopwatch
            .start(format!("setup_command: {}", name).as_str());

        self.setup_function(&Label::new(name.clone(), label_type))?;

        // Verify 'this' arg matches command's fields
        let command_def = self
            .machine
            .command_defs
            .get(&name)
            .ok_or_else(|| self.err(MachineErrorType::NotDefined(name.to_string())))?;

        if this_data.fields.len() != command_def.fields.len() {
            return Err(self.err(MachineErrorType::Unknown(alloc::format!(
                "command `{}` expects {} field(s), but `this` contains {}",
                name,
                command_def.fields.len(),
                this_data.fields.len()
            ))));
        }
        for (name, value) in &this_data.fields {
            let expected_type = &command_def
                .fields
                .get(name)
                .ok_or_else(|| self.err(MachineErrorType::InvalidStructMember(name.clone())))?
                .ty;

            if !value.fits_type(expected_type) {
                return Err(self.err(MachineErrorType::invalid_type(
                    expected_type.to_string(),
                    value.type_name(),
                    "invalid function argument",
                )));
            }
        }
        self.scope
            .set(ident!("this"), Value::Struct(this_data))
            .map_err(|e| self.err(e))?;

        #[cfg(feature = "bench")]
        self.stopwatch.stop();

        Ok(())
    }

    /// Call a command policy loaded into the VM by name. Accepts a
    /// `Struct` containing the Command's data. Returns a Vec of effect
    /// structs or a MachineError.
    /// If the command check-exits, its recall block will be executed.
    pub fn call_command_policy(
        &mut self,
        this_data: Struct,
        envelope: Struct,
    ) -> Result<ExitReason, MachineError> {
        if !matches!(&self.ctx, CommandContext::Policy(PolicyContext{name: ctx_name,..}) if *ctx_name == this_data.name)
        {
            return Err(MachineErrorType::ContextMismatch.into());
        }
        self.setup_command(LabelType::CommandPolicy, this_data)?;
        self.ipush(envelope)?;
        self.run()
    }

    /// Call a command policy loaded into the VM by name. Accepts a
    /// `Struct` containing the Command's data. Returns a Vec of effect
    /// structs or a MachineError.
    pub fn call_command_recall(
        &mut self,
        this_data: Struct,
        envelope: Struct,
    ) -> Result<ExitReason, MachineError> {
        if !matches!(&self.ctx, CommandContext::Recall(PolicyContext{name: ctx_name,..}) if *ctx_name == this_data.name)
        {
            return Err(MachineErrorType::ContextMismatch.into());
        }
        self.setup_command(LabelType::CommandRecall, this_data)?;
        self.ipush(envelope)?;
        self.run()
    }

    fn setup_function(&mut self, label: &Label) -> Result<(), MachineError> {
        self.set_pc_by_label(label)?;
        self.call_state.clear();
        self.scope.clear();

        Ok(())
    }

    /// Set up machine state for an action call.
    pub fn setup_action<Args>(&mut self, name: Identifier, args: Args) -> Result<(), MachineError>
    where
        Args: IntoIterator,
        Args::Item: Into<Value>,
    {
        #[cfg(feature = "bench")]
        self.stopwatch
            .start(format!("setup_action: {}", name).as_str());

        // verify number and types of arguments
        let action_def = self
            .machine
            .action_defs
            .get(&name)
            .ok_or_else(|| MachineError::new(MachineErrorType::NotDefined(name.to_string())))?;
        let args: Vec<Value> = args.into_iter().map(Into::into).collect();
        if args.len() != action_def.params.len() {
            return Err(MachineError::new(MachineErrorType::Unknown(
                alloc::format!(
                    "action `{}` expects {} argument(s), but was called with {}",
                    name,
                    action_def.params.len(),
                    args.len()
                ),
            )));
        }
        for (arg, param) in args.iter().zip(action_def.params.iter()) {
            if !arg.fits_type(&param.ty) {
                return Err(MachineError::new(MachineErrorType::invalid_type(
                    param.ty.to_string(),
                    arg.type_name(),
                    "invalid function argument",
                )));
            }
        }

        self.setup_function(&Label::new(name, LabelType::Action))?;
        for a in args {
            self.ipush(a)?;
        }

        #[cfg(feature = "bench")]
        self.stopwatch.stop();

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
        name: Identifier,
        args: Args,
    ) -> Result<ExitReason, MachineError>
    where
        Args: IntoIterator,
        Args::Item: Into<Value>,
    {
        if !matches!(&self.ctx, CommandContext::Action(ActionContext{name: ctx_name,..}) if *ctx_name == name)
        {
            return Err(MachineErrorType::ContextMismatch.into());
        }
        self.setup_action(name, args)?;
        self.run()
    }

    /// Call the seal block on this command to produce an envelope. The
    /// seal block is given an implicit parameter `this` and should
    /// return an opaque envelope struct on the stack.
    pub fn call_seal(&mut self, this_data: Struct) -> Result<ExitReason, MachineError> {
        let name = this_data.name.clone();
        if !matches!(&self.ctx, CommandContext::Seal(SealContext{name: ctx_name,..}) if *ctx_name == name)
        {
            return Err(MachineErrorType::ContextMismatch.into());
        }
        self.setup_function(&Label::new(name, LabelType::CommandSeal))?;

        // Seal/Open pushes the argument and defines it itself, because
        // it calls through a function stub. So we just push `this_data`
        // onto the stack.
        self.ipush(this_data)?;
        self.run()
    }

    /// Call the open block on an envelope struct to produce a command struct.
    pub fn call_open(
        &mut self,
        name: Identifier,
        envelope: Struct,
    ) -> Result<ExitReason, MachineError> {
        if !matches!(&self.ctx, CommandContext::Open(OpenContext{name: ctx_name,..}) if *ctx_name == name)
        {
            return Err(MachineErrorType::ContextMismatch.into());
        }
        self.setup_function(&Label::new(name, LabelType::CommandOpen))?;
        self.ipush(envelope)?;
        self.run()
    }

    /// Destroy the `RunState` and return the value on top of the stack.
    pub fn consume_return(mut self) -> Result<Value, MachineError> {
        self.stack
            .pop_value()
            .map_err(|t| MachineError::from_position(t, self.pc, self.machine.codemap.as_ref()))
    }

    fn validate_fact_literal(&mut self, fact: &Fact) -> Result<(), MachineError> {
        #[cfg(feature = "bench")]
        self.stopwatch.start("validate_fact_literal");

        if !self
            .machine
            .fact_defs
            .get(&fact.name)
            .is_some_and(|schema| validate_fact_schema(fact, schema))
        {
            return Err(MachineError::from_position(
                MachineErrorType::InvalidSchema(fact.name.clone()),
                self.pc,
                self.machine.codemap.as_ref(),
            ));
        }

        #[cfg(feature = "bench")]
        self.stopwatch.stop();

        Ok(())
    }
}

/// An implementation of [`Stack`].
pub struct MachineStack(pub(crate) HVec<Value, STACK_SIZE>);

impl MachineStack {
    /// Creates an empty stack.
    pub const fn new() -> Self {
        Self(HVec::new())
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

    /// Turn a Stack into a Vec of Values.
    pub fn into_vec(self) -> Vec<Value> {
        self.0.into_iter().collect()
    }
}

impl Stack for MachineStack {
    fn push_value(&mut self, value: Value) -> Result<(), MachineErrorType> {
        self.0
            .push(value)
            .map_err(|_| MachineErrorType::StackOverflow)
    }

    fn pop_value(&mut self) -> Result<Value, MachineErrorType> {
        self.0.pop().ok_or(MachineErrorType::StackUnderflow)
    }

    fn peek_value(&mut self) -> Result<&mut Value, MachineErrorType> {
        self.0.last_mut().ok_or(MachineErrorType::StackUnderflow)
    }
}

impl Default for MachineStack {
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Display for RunState<'_, M>
where
    M: MachineIO<MachineStack>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# Name table:")?;
        for (k, v) in &self.machine.labels {
            writeln!(f, "  {}: {:?}", k, v)?;
        }
        write!(f, "# Current defs")?;
        if !self.call_state.is_empty() {
            write!(f, " ({} stacked)", self.call_state.len())?;
        }
        writeln!(f, ":")?;
        for (k, v) in self.scope.locals() {
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
