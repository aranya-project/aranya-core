use std::{fs::File, io, path::PathBuf};

use anyhow::anyhow;
use aranya_policy_runner::PolicyRunner;
use clap::Parser;
use tracing_subscriber::EnvFilter;

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
    /// Enable trace output and other diagnostics.
    ///
    /// Trace information will be printed to stderr. If --output is
    /// specified, trace output will be logged to the output file.
    #[arg(long, short)]
    trace: bool,
    /// Run the validator on the policy compilation.
    #[arg(long)]
    validator: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.runs.is_empty() {
        return Err(anyhow!("Please specify one or more run files"));
    }

    // if output is specified, open the file here.
    let output_file = args.output.as_ref().map(File::create).transpose()?;

    if args.trace {
        let env_filter = EnvFilter::from_default_env();
        if let Some(output_file) = &output_file {
            // Clone the handle for the tracing output.
            let tracing_file = output_file.try_clone()?;
            tracing_subscriber::fmt()
                .with_writer(tracing_file)
                .with_env_filter(env_filter)
                .init();
        } else {
            // Configure trace output to use stderr.
            tracing_subscriber::fmt()
                .with_writer(io::stderr)
                .with_env_filter(env_filter)
                .init();
        }
    }

    let runner = PolicyRunner::new_from_path(args.policy)?
        .with_working_directory(args.working_directory)
        .with_deterministic_rng(args.deterministic_rng)
        .with_marker(args.marker)
        .with_validator(args.validator)
        .with_runfile_paths(args.runs)?;
    let runner = if let Some(file) = output_file {
        // Use the output file.
        runner.with_output_file(file)
    } else {
        // Continue to use the default stdout.
        runner
    };

    runner.run()?;

    Ok(())
}
