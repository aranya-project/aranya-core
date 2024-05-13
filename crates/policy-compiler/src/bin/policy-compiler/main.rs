use std::{fs::File, path::PathBuf, process::ExitCode};

use clap::Parser;
use policy_compiler::Compiler;
use policy_lang::lang::parse_policy_document;

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
}

pub fn main() -> ExitCode {
    let args = Args::parse();

    let policy_str = std::fs::read_to_string(&args.file).expect("could not read input file");
    let ast = parse_policy_document(&policy_str).expect("could not parse policy document");
    let module = Compiler::new(&ast)
        .compile()
        .expect("could not compile policy");

    let out_path = args
        .out
        .unwrap_or_else(|| args.file.with_extension(".pmod"));
    let mut out_f = File::create(out_path).expect("could not open output file");

    ciborium::into_writer(&module, &mut out_f).expect("could not write output file");
    ExitCode::SUCCESS
}
