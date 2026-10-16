//! The `policy-compiler` binary's exit status: obligation warnings fail
//! it only with `--deny-warnings`.
//!
//! Runs that should succeed pass `--no-validate`, because the binary
//! reads the validator's result backwards and fails every policy that
//! validates cleanly.

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

/// The start of each test policy: a fact to mutate, and a base command
/// for commands to extend.
const HEADER: &str = "---
policy-version: 2
---

```policy
fact Account[user int]=>{balance int}

base command B {
    fields { }
    get_key {
        return None
    }
}
";

/// Creates an `Account` without checking that it does not exist.
const UNCHECKED: &str = "
command Open with B {
    fields { user int }
    policy {
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
    }
}
";

/// Creates an `Account` after checking that it does not exist.
const CHECKED: &str = "
command Open with B {
    fields { user int }
    policy {
        check !exists Account[user: this.user] else test_fail()
        finish {
            create Account[user: this.user]=>{balance: 0}
        }
    }
}
";

/// Compiles `code`, written to `<name>.md` in the test directory, with
/// `args`. Returns the binary's output and the output file's path, which
/// is removed first so the caller can tell whether this run wrote it.
fn compile(name: &str, code: &str, args: &[&str]) -> (Output, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let input = dir.join(format!("{name}.md"));
    let out = dir.join(format!("{name}.pmod"));
    fs::write(&input, [HEADER, code, "```\n"].concat()).expect("write the policy");
    if out.exists() {
        fs::remove_file(&out).expect("remove the old output");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_policy-compiler"))
        .args(args)
        .arg("--out")
        .arg(&out)
        .arg(&input)
        .output()
        .expect("run policy-compiler");
    (output, out)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

const WARNING: &str =
    "warning: cannot prove `Account[user: this.user]` does not exist before `create`";

const DENIED: &str = "error: aborting due to 1 obligation warning (--deny-warnings)";

#[test]
fn no_analysis_without_check_obligations() {
    let (output, _) = compile("unanalyzed", UNCHECKED, &["--no-validate"]);
    assert!(output.status.success(), "{output:?}");
    assert!(!stderr(&output).contains(WARNING), "{output:?}");
}

#[test]
fn warnings_do_not_fail_by_default() {
    let (output, out) = compile(
        "default",
        UNCHECKED,
        &["--check-obligations", "--no-validate"],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(stderr(&output).contains(WARNING), "{output:?}");
    assert!(out.exists());
}

#[test]
fn deny_warnings_fails_without_writing_output() {
    let (output, out) = compile(
        "denied",
        UNCHECKED,
        &["--check-obligations", "--deny-warnings", "--no-validate"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(stderr(&output).contains(WARNING), "{output:?}");
    assert!(stderr(&output).contains(DENIED), "{output:?}");
    assert!(!out.exists());
}

#[test]
fn deny_warnings_is_reported_before_validation() {
    // Validation currently fails this policy without a message, so the
    // denial has to come first to be reported.
    let (output, _) = compile(
        "denied_validated",
        UNCHECKED,
        &["--check-obligations", "--deny-warnings"],
    );
    assert!(stderr(&output).contains(DENIED), "{output:?}");
}

#[test]
fn deny_warnings_counts_every_warning() {
    let second = UNCHECKED.replace("Open", "Reopen");
    let (output, _) = compile(
        "denied_twice",
        &[UNCHECKED, &second].concat(),
        &["--check-obligations", "--deny-warnings"],
    );
    assert!(
        stderr(&output).contains("error: aborting due to 2 obligation warnings (--deny-warnings)"),
        "{output:?}"
    );
}

#[test]
fn deny_warnings_passes_a_proven_policy() {
    let (output, out) = compile(
        "proven",
        CHECKED,
        &["--check-obligations", "--deny-warnings", "--no-validate"],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(!stderr(&output).contains("warning"), "{output:?}");
    assert!(out.exists());
}

#[test]
fn deny_warnings_requires_check_obligations() {
    // Without the analysis there are no warnings, so the flag alone would
    // pass every policy.
    let (output, _) = compile("deny_alone", UNCHECKED, &["--deny-warnings"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        stderr(&output).contains("--check-obligations"),
        "{output:?}"
    );
}
