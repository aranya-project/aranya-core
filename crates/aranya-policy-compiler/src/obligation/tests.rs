//! Tests for the obligation analysis. Each file covers one feature;
//! the helpers here compile a small policy and return its warnings.

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;

use super::ObligationWarning;
use crate::Compiler;

mod assumptions;
mod attacks_expressions;
mod attacks_helpers;
mod attacks_names;
mod attacks_paths;
mod attacks_polarity;
mod attacks_state;
mod bound_keys;
mod branches;
mod conditions;
mod coverage;
mod diagnostics;
mod expressions;
mod finish_functions;
mod init_commands;
mod mutations;
mod paths;
mod pure_functions;
mod update_values;

/// A fact with a two-part key, for queries with a bound key.
const MEMBER: &str = "fact Member[team int, device int]=>{rank int}";

#[track_caller]
fn warnings_for(text: &str) -> Vec<ObligationWarning> {
    let policy = parse_policy_str(text, Version::V2).expect("parse");
    let (_module, warnings) = Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .analyze_obligations(true)
        .compile_with_diagnostics()
        .expect("compile");
    warnings
}

/// Wrap a policy body in a command with the `Account` fact defined.
fn command(policy_block: &str) -> String {
    format!(
        r#"
        fact Account[user int]=>{{balance int}}

        command Foo {{
            fields {{ user int }}
            policy {{
                {policy_block}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

/// Wrap a policy body in an `init: true` command.
fn init_command(policy_block: &str) -> String {
    format!(
        r#"
        fact Account[user int]=>{{balance int}}
        fact Owner[]=>{{user int}}

        command Init {{
            attributes {{ init: true }}
            fields {{ user int }}
            policy {{
                {policy_block}
            }}
        }}
        "#
    )
}

/// A policy with `Account` and `Owner` facts, extra definitions, and
/// one command with the given policy block.
fn with_defs(defs: &str, policy_block: &str) -> String {
    format!(
        r#"
        fact Account[user int]=>{{balance int}}
        fact Owner[]=>{{user int}}

        {defs}

        command Foo {{
            fields {{ user int }}
            policy {{
                {policy_block}
            }}
            recall failed() {{ finish {{}} }}
        }}
        "#
    )
}

#[track_caller]
fn warnings_with_cap(text: &str, cap: usize) -> Vec<ObligationWarning> {
    let policy = parse_policy_str(text, Version::V2).expect("parse");
    let (_module, warnings) = Compiler::new(&policy)
        .debug(true)
        .allow_baseless(true)
        .analyze_obligations(true)
        .max_exit_paths(cap)
        .compile_with_diagnostics()
        .expect("compile");
    warnings
}
