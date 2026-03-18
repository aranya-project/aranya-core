use std::path::PathBuf;

use anyhow::anyhow;
use aranya_policy_runner::PolicyRunner;
use clap::Parser;

/// The Aranya Policy Runner runs sequences of actions on policy files.
#[derive(Parser, Debug)]
struct Args {
    /// The policy file.
    policy: PathBuf,
    /// One or more run files.
    runs: Vec<PathBuf>,
    /// The working directory for all data stored.
    ///
    /// If unspecified, a temporary directory is used.
    #[arg(long, short)]
    working_directory: Option<PathBuf>,
    /// Send output to a file instead of stdout.
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// Use a deterministic RNG.
    ///
    /// This does not affect the randomly generated temporary working
    /// directory.
    #[arg(long)]
    deterministic_rng: bool,
    /// Add a marker to the output between run files.
    ///
    /// The marker includes the run file path.
    #[arg(long)]
    marker: bool,
    /// Suppress trace output and other diagnostics.
    ///
    /// This just turns off the default `tracing` subscriber. Fatal
    /// errors will still be printed.
    #[arg(long, short)]
    quiet: bool,
    /// Run the validator on the policy compilation.
    #[arg(long)]
    validator: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.runs.is_empty() {
        return Err(anyhow!("Please specify one or more run files"));
    }

    if !args.quiet {
        tracing_subscriber::fmt::init();
    }

    let runner = PolicyRunner::new_from_path(args.policy)?
        .with_working_directory(args.working_directory)
        .with_deterministic_rng(args.deterministic_rng)
        .with_marker(args.marker)
        .with_validator(args.validator)
        .with_runfile_paths(args.runs)?;
    let runner = if let Some(path) = args.output {
        runner.with_output_file(path)
    } else {
        runner
    };

    runner.run()?;

    Ok(())
}
