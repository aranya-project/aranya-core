use std::{
    fs::OpenOptions,
    io::{stdin, BufRead, BufReader, Read},
    process::ExitCode,
};

use anyhow::Context;
use clap::{Parser, ValueEnum};
use pest::Parser as PestParser;
use policy_lang::lang::{
    extract_policy, get_pratt_parser, parse_expression, parse_policy_str, PolicyParser, Rule,
    Version,
};

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

fn parse_text_and_version(s: &str, args: &Args) -> anyhow::Result<(String, Version)> {
    match args.raw_policy_version {
        Some(version) => Ok((s.to_owned(), version)),
        None => {
            let (chunks, version) = extract_policy(s)?;
            let mut s = String::new();
            for c in chunks {
                s.push_str(&c.text);
            }

            Ok((s, version))
        }
    }
}

fn parse_thing(s: &str, args: &Args) -> anyhow::Result<String> {
    match args.mode {
        Mode::Document => {
            let (policy_text, version) = parse_text_and_version(s, args)?;
            let policy = parse_policy_str(&policy_text, version)?;
            match args.check_mode {
                true => Ok(String::from("policy is valid")),
                false => Ok(format!("{:#?}", policy)),
            }
        }
        Mode::Expression => {
            let mut pairs = PolicyParser::parse(Rule::expression, s)?;

            let token = pairs.next().context("No tokens")?;

            let ast = parse_expression(token, &get_pratt_parser())?;

            Ok(format!("{:#?}", ast))
        }
    }
}

fn output(res: anyhow::Result<String>) -> ExitCode {
    match res {
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

    if args.line_mode && args.mode == Mode::Document {
        println!("Line mode does not make sense for parsing documents");
        return ExitCode::from(1);
    }
    if args.check_mode && args.mode == Mode::Expression {
        println!("Check mode does not make sense for parsing expressions");
        return ExitCode::from(1);
    }

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
            let n = bufread.read_line(&mut line).expect("Could not read line");
            if n == 0 {
                // End of file
                break ExitCode::SUCCESS;
            }
            output(parse_thing(&line, &args));
        }
    } else {
        let mut buf = vec![];
        file.read_to_end(&mut buf).expect("Cannot read input");
        let s = String::from_utf8(buf).expect("invalid UTF-8");
        output(parse_thing(&s, &args))
    }
}
