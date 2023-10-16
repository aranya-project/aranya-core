use std::{
    fs::OpenOptions,
    io::{stdin, BufRead, BufReader, Read},
    process::ExitCode,
};

use clap::{Parser, ValueEnum};
use flow3_policy_lang::lang::*;
use pest::Parser as PestParser;

#[derive(Parser, Debug)]
#[command(name = "parser explorer", version)]
#[command(about = "Converts text into AST trees for exploration and debugging")]
struct Args {
    /// The policy version. If this is set the policy is treated as raw.
    /// Valid values are v3.
    #[arg(short, long)]
    raw_policy_version: Option<Version>,
    /// What to parse
    #[arg(value_enum, default_value_t = Mode::Document)]
    mode: Mode,
    /// The file to read from. If omitted, the document is read from stdin.
    #[arg(short, long)]
    file: Option<String>,
    /// Line-mode parses after every newline instead of at EOF
    #[arg(short, long)]
    line_mode: bool,
    /// Check-mode validates the policy and shows any error
    #[arg(short, long)]
    check_mode: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    Document,
    Expression,
}

fn parse_text_and_version(s: &str, args: &Args) -> Result<(String, Version), String> {
    match args.raw_policy_version {
        Some(version) => Ok((s.to_owned(), version)),
        None => {
            let (policy_text, version) = extract_policy(s).map_err(|e| e.to_string())?;

            Ok((policy_text, version))
        }
    }
}

fn parse_thing(s: &str, args: &Args) -> Result<String, String> {
    let (policy_text, version) = parse_text_and_version(s, args)?;
    match args.mode {
        Mode::Document => match args.check_mode {
            true => {
                PolicyParser::parse(Rule::file, &policy_text).map_err(|e| e.to_string())?;
                Ok(String::from("policy is valid"))
            }
            false => {
                let policy = parse_policy_str(&policy_text, version).map_err(|e| e.to_string())?;

                Ok(format!("{:#?}", policy))
            }
        },
        Mode::Expression => {
            let mut pairs = PolicyParser::parse(Rule::expression, s).map_err(|e| e.to_string())?;

            let token = pairs.next().ok_or_else(|| String::from("No tokens"))?;

            let ast = parse_expression(token, &get_pratt_parser()).map_err(|e| e.to_string())?;

            Ok(format!("{:#?}", ast))
        }
    }
}

fn output(v: Result<String, String>) -> ExitCode {
    match v {
        Ok(s) => {
            println!("{}", s);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("error: {}", e);
            ExitCode::from(1)
        }
    }
}

pub fn main() -> ExitCode {
    let args = Args::parse();

    println!("Parsing {:?}", args.mode);
    let mut file: Box<dyn Read> = if let Some(ref file_name) = args.file {
        let f = OpenOptions::new()
            .read(true)
            .open(file_name)
            .expect("Could not open");
        Box::new(f)
    } else {
        Box::new(stdin())
    };

    if args.line_mode {
        let mut bufread = BufReader::new(file);
        loop {
            let mut line = String::new();
            bufread.read_line(&mut line).expect("Could not read line");
            output(parse_thing(&line, &args));
        }
    } else {
        let mut buf = vec![];
        file.read_to_end(&mut buf).expect("Cannot read stdin");
        let s = String::from_utf8(buf).expect("invalid UTF-8");
        output(parse_thing(&s, &args))
    }
}
