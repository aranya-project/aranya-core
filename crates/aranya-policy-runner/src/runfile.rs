use std::{
    fs::OpenOptions,
    io::{BufRead as _, BufReader},
    path::{Path, PathBuf},
};

use anyhow::anyhow;
use aranya_policy_lang::lang::{ParseErrorKind, parse_expression};
use aranya_policy_vm::ast::ExprKind;

/// A thing that can be run. Either an action or a raw command struct.
#[derive(Debug)]
pub enum PolicyRunnable {
    Action(String),
    Command(String),
}

#[derive(Debug)]
pub struct RunFile {
    pub file_path: PathBuf,
    pub preamble: String,
    pub do_things: Vec<PolicyRunnable>,
}

enum Mode {
    None,
    Preamble,
    Do,
}

pub fn parse_runfile(path: impl AsRef<Path>) -> anyhow::Result<RunFile> {
    let f = BufReader::new(OpenOptions::new().read(true).open(path.as_ref())?);
    let mut preamble = String::new();
    let mut do_things = Vec::new();
    let mut mode = Mode::None;
    let mut partial_expression = String::new();

    for (i, line) in f.lines().enumerate() {
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
                    return Err(anyhow!("Line without 'preamble' or 'do'"));
                }
                Mode::Preamble => {
                    preamble.push('\n');
                    preamble.push_str(l);
                }
                Mode::Do => {
                    let full_expression = partial_expression.clone() + l;
                    match parse_expression(&full_expression) {
                        Ok(expr) => {
                            match expr.kind {
                                ExprKind::FunctionCall(_) => {
                                    do_things.push(PolicyRunnable::Action(full_expression));
                                }
                                ExprKind::NamedStruct(_) => {
                                    do_things.push(PolicyRunnable::Command(full_expression));
                                }
                                _ => {
                                    return Err(anyhow!(
                                        "runnable must be an action call or command struct @ line {line_no}: {l}"
                                    ));
                                }
                            }
                            partial_expression.clear();
                        }
                        Err(pe) if pe.kind == ParseErrorKind::Syntax => {
                            // Not valid syntax, wait for the next line
                            partial_expression.push_str(l);
                            continue;
                        }
                        Err(pe) => return Err(pe.into()),
                    };
                }
            },
        }
    }

    if !partial_expression.is_empty() {
        return Err(anyhow!("Could not parse expression: {partial_expression}"));
    }

    Ok(RunFile {
        file_path: path.as_ref().to_owned(),
        preamble,
        do_things,
    })
}
