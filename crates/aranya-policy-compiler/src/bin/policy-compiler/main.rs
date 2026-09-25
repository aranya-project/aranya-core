use std::{fs::File, path::PathBuf, process::ExitCode};

use aranya_policy_compiler::{Compiler, validate::validate};
use aranya_policy_lang::lang::parse_policy_document;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "policy compiler", version)]
#[command(about = "Converts policy documents into compiled policy modules")]
struct Args {
    /// The file containing policy code.
    file: PathBuf,
    /// The output file. If omitted, the output file is the input, but with the extension
    /// '.pmod'.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Be verbose
    #[arg(short, long)]
    verbose: bool,
    /// Do not perform more rigorous validation passes
    #[arg(short, long)]
    no_validate: bool,
    /// Do not compile FFI calls
    #[arg(long)]
    stub_ffi: bool,
    /// Run the obligation analysis and print warnings (e.g. a `create`
    /// without a prior proof that the fact does not exist)
    #[arg(long)]
    check_obligations: bool,
}

pub fn main() -> ExitCode {
    let args = Args::parse();

    let out_path = args.out.unwrap_or_else(|| args.file.with_extension("pmod"));

    if args.verbose {
        println!(
            "Compiling {} to {}",
            args.file.display(),
            out_path.display()
        );
    }

    let policy_str = std::fs::read_to_string(&args.file).expect("could not read input file");
    let ast = match parse_policy_document(&policy_str) {
        Ok(a) => a,
        Err(e) => {
            println!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let compiler = Compiler::new(&ast)
        .stub_ffi(args.stub_ffi)
        .analyze_obligations(args.check_obligations);
    let (module, warnings) = match compiler.compile_with_diagnostics() {
        Ok(m) => m,
        Err(e) => {
            println!("{e}");
            return ExitCode::FAILURE;
        }
    };
    for warning in &warnings {
        eprintln!("{}", warning.render(&ast.text));
    }

    if !args.no_validate && !validate(&module) {
        return ExitCode::FAILURE;
    }

    if args.stub_ffi {
        println!("Not creating output file with --stub-ffi");
        return ExitCode::SUCCESS;
    }

    let mut out_f = File::create(out_path).expect("could not open output file");

    ciborium::into_writer(&module, &mut out_f).expect("could not write output file");
    ExitCode::SUCCESS
}
