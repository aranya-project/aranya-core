//! Fields read from struct values: a field of a struct literal is the
//! value it was given, whether the literal is passed to a finish
//! function, bound by `let`, nested in another, or composed from another
//! struct.

use rstest::rstest;

use super::{warnings_for, with_defs};

/// Structs, and a finish function creating the fact a struct names.
const DEFS: &str = r#"
    struct Info { k int, v int }
    struct Key { k int }
    struct Outer { inner struct Info }
    fact Item[k int]=>{v int}

    finish function make(i struct Info) {
        create Item[k: i.k]=>{v: i.v}
    }
"#;

#[rstest]
#[case::literal_argument("", "make(Info { k: this.user, v: 0 })")]
#[case::bound_argument("let info = Info { k: this.user, v: 0 }", "make(info)")]
#[case::read_in_the_command(
    "let info = Info { k: this.user, v: 0 }",
    "create Item[k: info.k]=>{v: 0}"
)]
#[case::nested(
    "let o = Outer { inner: Info { k: this.user, v: 0 } }",
    "create Item[k: o.inner.k]=>{v: 0}"
)]
#[case::nested_argument(
    "let o = Outer { inner: Info { k: this.user, v: 0 } }",
    "make(o.inner)"
)]
#[case::composed(
    "let key = Key { k: this.user }
     let info = Info { v: 0, ...key }",
    "make(info)"
)]
fn key_read_from_a_struct_field_passes(#[case] setup: &str, #[case] mutation: &str) {
    let warnings = warnings_for(&with_defs(
        DEFS,
        &format!(
            r#"
            check !exists Item[k: this.user] else recall failed()
            {setup}
            finish {{ {mutation} }}
            "#
        ),
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}

#[test]
fn stored_value_read_from_a_struct_field_passes() {
    let warnings = warnings_for(&with_defs(
        "struct Old { balance int }",
        r#"
        let a = query Account[user: this.user] or recall failed()
        let old = Old { balance: a.balance }
        finish {
            update Account[user: this.user]=>{balance: old.balance} to {balance: 1}
        }
        "#,
    ));
    assert_eq!(warnings, vec![], "expected no warnings");
}
