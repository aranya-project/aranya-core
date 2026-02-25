use std::{
    fmt,
    fs::OpenOptions,
    io::{self, BufRead as _, BufReader},
    path::{Path, PathBuf},
};

use aranya_crypto::{KeyStore, id::Id};
use aranya_policy_compiler::{CompileError, Compiler};
use aranya_policy_lang::lang::{ParseError, ParseErrorKind, parse_expression, parse_policy_str};
use aranya_policy_vm::{
    CommandContext, ExitReason, Identifier, Label, LabelType, Machine, MachineError, PolicyContext,
    UnsupportedVersion, Value, ast::ExprKind, ffi::FfiModule as _, ident,
};

use crate::{
    io::{PreambleIO, testing_ffi::TestingFfi},
    policy::CE,
};

#[derive(Debug, PartialEq, Eq)]
pub struct SyntaxError {
    line: usize,
    message: String,
}

impl SyntaxError {
    fn new(line: usize, message: impl ToString) -> Self {
        Self {
            line,
            message: message.to_string(),
        }
    }
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for SyntaxError {}

#[derive(Debug, thiserror::Error)]
pub enum RunFileError {
    #[error("I/O Error")]
    Io(#[from] io::Error),
    #[error("Syntax Error")]
    Syntax(#[from] SyntaxError),
    #[error("Policy Parse Error")]
    PolicyParse(#[from] ParseError),
    #[error("Policy Compile Error")]
    PolicyCompile(#[from] CompileError),
    #[error("Policy VM Error")]
    PolicyVm(#[from] MachineError),
    #[error("Policy VM Check")]
    PolicyVmCheck,
    #[error("Policy VM Panic")]
    PolicyVmPanic,
    #[error("Policy Version")]
    PolicyVersion,
}

impl From<UnsupportedVersion> for RunFileError {
    fn from(_value: UnsupportedVersion) -> Self {
        Self::PolicyVersion
    }
}

/// A thing that can be run. Either an action or a raw command struct.
#[derive(Debug)]
pub enum PolicyRunnable {
    Action(String),
    Command(String),
}

// Parsed version of a policy file.
#[derive(Debug)]
pub struct RunFile {
    /// The path to the run file. Used for printing markers.
    pub file_path: PathBuf,
    /// Policy code which defines values and performs other preparation for the `do` block.
    pub preamble: String,
    /// A list of actions and commands to be executed in the policy.
    pub do_things: Vec<PolicyRunnable>,
}

impl RunFile {
    /// Construct a `RunFile` by loading and parsing it from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RunFileError> {
        let f = OpenOptions::new().read(true).open(path.as_ref())?;
        Self::from_reader(f, path)
    }

    pub fn from_reader<R: io::Read>(
        reader: R,
        file_path: impl AsRef<Path>,
    ) -> Result<Self, RunFileError> {
        enum Mode {
            None,
            Preamble,
            Do,
        }

        let reader = BufReader::new(reader);
        let mut preamble = String::new();
        let mut do_things = Vec::new();
        let mut mode = Mode::None;
        let mut partial_expression = String::new();
        let mut parse_begin = 0;

        for (i, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim_end();
            let line_no = i
                .checked_add(1)
                .expect("overflow in calculating line number");
            match line {
                "preamble:" => mode = Mode::Preamble,
                "do:" => mode = Mode::Do,
                l => match mode {
                    Mode::None => {
                        return Err(SyntaxError::new(line_no, "Expected 'preamble' or 'do'").into());
                    }
                    Mode::Preamble => {
                        preamble.push('\n');
                        preamble.push_str(l);
                    }
                    Mode::Do => {
                        // Construct the full expression from this line concatenated with any
                        // previous unparsed lines.
                        if partial_expression.is_empty() {
                            // Beginning of parsing a new expression. Save this so we can locate
                            // the beginning line of an unparseable expression in the error handler
                            // below.
                            parse_begin = line_no;
                        }
                        let full_expression = partial_expression.clone() + l;
                        match parse_expression(&full_expression) {
                            Ok(expr) => {
                                // Successfully parsed an expression. Add it to the list of runnables.
                                match expr.kind {
                                    ExprKind::FunctionCall(_) => {
                                        do_things.push(PolicyRunnable::Action(full_expression));
                                    }
                                    ExprKind::NamedStruct(_) => {
                                        do_things.push(PolicyRunnable::Command(full_expression));
                                    }
                                    _ => {
                                        return Err(SyntaxError::new(line_no,
                                            format!("runnable must be an action call or command struct: {l}")
                                        ).into());
                                    }
                                }
                                partial_expression.clear();
                            }
                            Err(pe) if pe.kind == ParseErrorKind::Syntax => {
                                // Not valid syntax, add to `partial_expression` and continue on the next line
                                partial_expression.push_str(l);
                            }
                            Err(pe) => return Err(pe.into()), // Some other error; report to the user
                        }
                    }
                },
            }
        }

        if !partial_expression.is_empty() {
            // If we successfully parsed all expressions in the `do`
            // block, this should be empty. Remaining content in
            // `partial_expression` indicates an unparseable expression
            // at the end of the file.
            return Err(SyntaxError::new(
                parse_begin,
                format!("Could not parse expression: {partial_expression}"),
            )
            .into());
        }

        if do_things.is_empty() {
            eprintln!(
                "WARNING: 'do' block is absent or empty in {}",
                file_path.as_ref().display()
            );
        }

        Ok(Self {
            file_path: file_path.as_ref().to_owned(),
            preamble,
            do_things,
        })
    }

    /// Calculate preamble values from the run file.
    ///
    /// Run file preambles are executed within a function so that they
    /// can use the `testing` FFI calls. The function is called and
    /// values are extracted from the machine after the function
    /// returns.
    pub fn get_preamble_values<KS: KeyStore>(
        &self,
        crypto_engine: &mut CE,
        keystore: &mut KS,
    ) -> Result<Vec<(Identifier, Value)>, RunFileError> {
        let func_str = format!(
            "use testing\nfunction preamble() bool {{\n{}\n  return false\n}}",
            self.preamble
        );
        let ast = parse_policy_str(&func_str, aranya_policy_lang::ast::Version::V2)?;
        let module = Compiler::new(&ast)
            // It is important that only `TestingFfi` is specified here, as `PreambleIO` uses it
            // alone.
            .ffi_modules(&[TestingFfi::<KS>::SCHEMA])
            .compile()?;

        let machine = Machine::from_module(module).expect("cannot get unsupported version");
        let mut io = PreambleIO::new(crypto_engine, keystore);
        let mut rs = machine.create_run_state(
            &mut io,
            CommandContext::Policy(PolicyContext {
                name: ident!("preamble"),
                id: Id::default(),
                author: Id::default(),
                version: Id::default(),
            }),
        );
        rs.set_pc_by_label(&Label::new(ident!("preamble"), LabelType::Function))?;
        match rs.run() {
            Ok(ExitReason::Normal) => {}
            Ok(ExitReason::Check) => {
                return Err(RunFileError::PolicyVmCheck);
            }
            Ok(ExitReason::Panic) => return Err(RunFileError::PolicyVmPanic),
            Ok(ExitReason::Yield) => unreachable!("Cannot yield in functions"),
            Err(err) => {
                return Err(err.into());
            }
        }
        Ok(rs
            .scope()
            .locals()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use aranya_crypto::{
        Random as _, dangerous::spideroak_crypto::aead::AeadKey, default::DefaultEngine,
        keystore::memstore::MemStore,
    };

    use crate::SwitchableRng;

    use super::{RunFile, RunFileError};

    #[test]
    fn parse_correct() {
        let text = r#"
preamble:
    let x = 0
do:
    doit(x)
        "#
        .trim();

        assert!(RunFile::from_reader(text.as_bytes(), "test.run").is_ok());
    }

    #[test]
    fn parse_without_preamble() {
        let text = r#"
do:
    doit(x)
        "#
        .trim();

        assert!(RunFile::from_reader(text.as_bytes(), "test.run").is_ok());
    }

    #[test]
    fn parse_without_do() {
        let text = r#"
preamble:
    let x = 0
        "#
        .trim();

        assert!(RunFile::from_reader(text.as_bytes(), "test.run").is_ok());
    }

    #[test]
    fn parse_without_sections() {
        let text = r#"
    doit(x)
        "#
        .trim();

        assert!(matches!(
            RunFile::from_reader(text.as_bytes(), "test.run"),
            Err(RunFileError::Syntax(se)) if se.to_string() == "line 1: Expected 'preamble' or 'do'"
        ));
    }

    #[test]
    fn parse_empty() {
        let text = "";

        assert!(RunFile::from_reader(text.as_bytes(), "test.run").is_ok());
    }

    fn test_prereqs() -> (DefaultEngine<SwitchableRng>, MemStore) {
        let rng = SwitchableRng::new_default();
        let secret_key = AeadKey::random(&rng);
        let engine = DefaultEngine::new(&secret_key, rng);
        let keystore = MemStore::new();
        (engine, keystore)
    }

    #[test]
    fn preamble_policy_lang_parse_error() {
        let text = r#"
preamble:
    let x = 0 / "horse"
        "#
        .trim();

        let (mut ce, mut ks) = test_prereqs();

        let rf = RunFile::from_reader(text.as_bytes(), "test.run").expect("parses correctly");
        let r = rf.get_preamble_values(&mut ce, &mut ks);
        assert!(matches!(r, Err(RunFileError::PolicyParse(_))));
    }

    #[test]
    fn preamble_policy_lang_compile_error() {
        let text = r#"
preamble:
    let x = foo("horse")
        "#
        .trim();

        let (mut ce, mut ks) = test_prereqs();

        let rf = RunFile::from_reader(text.as_bytes(), "test.run").expect("parses correctly");
        let r = rf.get_preamble_values(&mut ce, &mut ks);
        assert!(matches!(r, Err(RunFileError::PolicyCompile(_))));
    }

    #[test]
    fn preamble_policy_lang_vm_error() {
        let text = r#"
preamble:
    let x = if false {: todo() } else {: "foo" }
    let y = x > 3
        "#
        .trim();

        let (mut ce, mut ks) = test_prereqs();

        let rf = RunFile::from_reader(text.as_bytes(), "test.run").expect("parses correctly");
        let r = rf.get_preamble_values(&mut ce, &mut ks);
        println!("{r:?}");
        assert!(matches!(r, Err(RunFileError::PolicyVm(_))));
    }

    #[test]
    fn preamble_policy_lang_vm_check() {
        let text = r#"
preamble:
    check false
        "#
        .trim();

        let (mut ce, mut ks) = test_prereqs();

        let rf = RunFile::from_reader(text.as_bytes(), "test.run").expect("parses correctly");
        let r = rf.get_preamble_values(&mut ce, &mut ks);
        assert!(matches!(r, Err(RunFileError::PolicyVmCheck)));
    }
}
