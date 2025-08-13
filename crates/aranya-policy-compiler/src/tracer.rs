mod analyzers;
mod error;

pub use analyzers::*;
use aranya_policy_module::{Instruction, Label, ModuleV0, Target};
pub use error::TraceError;
use error::TraceErrorType;

/// Failed results from one analyzer on one code path
#[derive(Debug, Clone)]
pub struct TraceFailure {
    /// The sequence of instructions that produced this failure. The last instruction is not
    /// necessarily the instruction responsible for the failure.
    pub instruction_path: Vec<usize>,
    /// This is the instruction responsible for the failure. This is usually the last
    /// instruction in `instruction_path`, but not always.
    pub responsible_instruction: usize,
    /// The message associated with the failure.
    pub message: String,
}

/// Builds a [`TraceAnalyzer`] by adding a series of [`Analyzer`] implementations with
/// [`add_analyzer`](TraceAnalyzerBuilder::add_analyzer) and calling
/// [`build`](TraceAnalyzerBuilder::build).
///
/// ```ignore
/// let module = ...; // a `Module`
/// let tracer = TraceAnalyzerBuilder::new(module)
///     .add_analyzer(FinishAnalyzer::new())
///     .add_analyzer(ValueAnalyzer::new(["this", "envelope"]))
///     .build()
/// let failures = tracer.trace(Label::new("Init", LabelType::CommandPolicy))?;
/// ```
pub struct TraceAnalyzerBuilder<'a> {
    m: &'a ModuleV0,
    tracers: Vec<Box<dyn Analyzer>>,
}

impl<'a> TraceAnalyzerBuilder<'a> {
    pub fn new(m: &'a ModuleV0) -> TraceAnalyzerBuilder<'a> {
        TraceAnalyzerBuilder { m, tracers: vec![] }
    }
}

impl<'a> TraceAnalyzerBuilder<'a> {
    /// Add an [`Analyzer`] implementation.
    pub fn add_analyzer<A>(mut self, mut tracer: A) -> TraceAnalyzerBuilder<'a>
    where
        A: Analyzer + 'static,
    {
        tracer.init(self.m);
        self.tracers.push(Box::new(tracer));
        self
    }

    /// Build a [`TraceAnalyzer`].
    pub fn build(self) -> TraceAnalyzer<'a> {
        TraceAnalyzer {
            ct: self.m,
            call_stack: vec![],
            instruction_path: vec![],
            branches: vec![],
            tracer_enable: vec![],
            analyzers: self.tracers,
        }
    }
}

/// Traces compiled code paths to prove properties with [`Analyzer`]s. See
/// [`TraceAnalyzerBuilder`] to construct a [`TraceAnalyzer`].
#[derive(Clone)]
pub struct TraceAnalyzer<'a> {
    /// The compiled code we're analyzing
    ct: &'a ModuleV0,
    /// Stores return addresses from `Call` instructions
    call_stack: Vec<usize>,
    /// The addresses of the instruction path so far in our trace
    instruction_path: Vec<usize>,
    /// Addresses we've encountered for branch instructions
    branches: Vec<usize>,
    /// Same length as the tracers list, and indexed the same way. If the entry is `false`,
    /// the tracer is not run.
    tracer_enable: Vec<bool>,
    /// An HList of tracer implementations
    analyzers: Vec<Box<dyn Analyzer>>,
}

/// Organizes intermediate results as the tracer recurses along code paths.
struct TraceIntermediate {
    failures: Vec<Vec<TraceFailure>>,
    successful_branch_paths: Vec<Vec<usize>>,
}

impl TraceAnalyzer<'_> {
    fn trace_err(&self, etype: TraceErrorType) -> TraceError {
        TraceError::new(etype, self.instruction_path.clone())
    }

    /// Begin a trace at a [`Label`]. Returns a list of [`TraceFailure`]s or a
    /// [`TraceError`] if tracing failed.
    ///
    /// A [`TraceFailure`] is a failure in the code being analyzed. A [`TraceError`] is an
    /// error in the tracing process itself. e.g., if a `Label` was given that didn't exist,
    /// that would be a [`TraceError`].
    pub fn trace(self, start: &Label) -> Result<Vec<TraceFailure>, TraceError> {
        match self.ct.labels.get(start) {
            Some(pc) => self.trace_pc(*pc),
            None => Err(self.trace_err(TraceErrorType::BadLabel(start.clone()))),
        }
    }

    /// Same as [`trace`](Self::trace), but starting at an address instead of a `Label`.
    pub fn trace_pc(mut self, start: usize) -> Result<Vec<TraceFailure>, TraceError> {
        self.tracer_enable = vec![true; self.analyzers.len()];
        let TraceIntermediate {
            mut failures,
            mut successful_branch_paths,
        } = self.trace_inner(start)?;
        successful_branch_paths.sort();
        successful_branch_paths.dedup();

        self.post_analyze(&mut failures, &successful_branch_paths);

        // Flatten failures into a single list
        let mut failures: Vec<TraceFailure> = failures.into_iter().flatten().collect();

        // Multiple paths may give us the same failures. Sort them by responsible
        // instruction and consider them identical if they have the same message.
        failures.sort_by(|a, b| a.responsible_instruction.cmp(&b.responsible_instruction));
        failures.dedup_by(|a, b| {
            a.message == b.message && a.responsible_instruction == b.responsible_instruction
        });

        Ok(failures)
    }

    fn trace_inner(&mut self, entry: usize) -> Result<TraceIntermediate, TraceError> {
        let mut pc = entry;
        // Failures are organized by which analyzer produced them, so we can hand them back
        // for post-analysis.
        let mut failures = vec![vec![]; self.analyzers.len()];
        // Keep track of all the branches from paths that didn't fail, for use by
        // post-analysis.
        let mut successful_branch_paths = vec![];

        while pc < self.ct.progmem.len() {
            self.instruction_path.push(pc);
            let i = self
                .ct
                .progmem
                .get(pc)
                .ok_or_else(|| self.trace_err(TraceErrorType::Bug))?;

            let ar = self.analyze_instruction(pc, i);
            for (index, res) in ar.into_iter().enumerate() {
                let astatus = res?;
                if matches!(astatus, AnalyzerStatus::Halted(_)) {
                    self.tracer_enable[index] = false;
                }
                match astatus {
                    AnalyzerStatus::Failed(s) | AnalyzerStatus::Halted(s) => {
                        failures[index].push(TraceFailure {
                            instruction_path: self.instruction_path.clone(),
                            responsible_instruction: pc,
                            message: s,
                        });
                    }
                    _ => (),
                }
            }

            match i {
                Instruction::Jump(t) => {
                    pc = t
                        .resolved()
                        .ok_or_else(|| self.trace_err(TraceErrorType::Bug))?;
                    continue;
                }
                Instruction::Branch(t) => {
                    self.branches.push(pc);
                    // Recurse on the target
                    let jump_pc = t
                        .resolved()
                        .ok_or_else(|| self.trace_err(TraceErrorType::Bug))?;
                    let mut jump_tracer = self.clone();
                    let TraceIntermediate {
                        failures: jump_failures,
                        successful_branch_paths: mut success_branches,
                    } = jump_tracer.trace_inner(jump_pc)?;
                    for (idx, mut jf) in jump_failures.into_iter().enumerate() {
                        failures[idx].append(&mut jf);
                        successful_branch_paths.append(&mut success_branches);
                    }
                }
                Instruction::Call(t) => {
                    let next_addr = *match t {
                        Target::Unresolved(l) => self
                            .ct
                            .labels
                            .get(l)
                            .ok_or_else(|| self.trace_err(TraceErrorType::Bug))?,
                        Target::Resolved(a) => a,
                    };
                    self.call_stack.push(pc);
                    pc = next_addr;
                    continue; // skip address increment when jumping
                }
                Instruction::Return => {
                    if self.call_stack.is_empty() {
                        // Exit on empty return
                        successful_branch_paths.push(self.branches.clone());
                        return Ok(TraceIntermediate {
                            failures,
                            successful_branch_paths,
                        });
                    }
                    pc = self.call_stack.pop().expect("impossible empty stack");
                }
                Instruction::Exit(_) => {
                    successful_branch_paths.push(self.branches.clone());
                    return Ok(TraceIntermediate {
                        failures,
                        successful_branch_paths,
                    });
                }
                _ => (),
            }

            pc = pc
                .checked_add(1)
                .ok_or_else(|| self.trace_err(TraceErrorType::Bug))?;
        }

        Err(self.trace_err(TraceErrorType::Bug))
    }

    fn analyze_instruction(
        &mut self,
        pc: usize,
        i: &Instruction,
    ) -> Vec<Result<AnalyzerStatus, TraceError>> {
        self.analyzers
            .iter_mut()
            .zip(self.tracer_enable.iter())
            .map(|(analyzer, enabled)| {
                if !enabled {
                    return Ok(AnalyzerStatus::Ok);
                }
                analyzer.analyze_instruction(pc, i, self.ct)
            })
            .collect()
    }

    fn post_analyze(
        &mut self,
        failures: &mut [Vec<TraceFailure>],
        successful_branch_paths: &[Vec<usize>],
    ) {
        for (analyzer, failures) in self.analyzers.iter_mut().zip(failures.iter_mut()) {
            analyzer.post_analyze(failures, successful_branch_paths);
        }
    }
}
