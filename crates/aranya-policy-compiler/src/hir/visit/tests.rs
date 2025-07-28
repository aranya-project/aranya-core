//! Comprehensive tests for the HIR visitor pattern.
//!
//! These tests ensure that all HIR node types are properly visited in the correct order.
//! Each test uses the `RecordingVisitor` to capture the exact sequence of node visits
//! and verifies it against snapshots using `insta`.
//!
//! The tests cover:
//! - All top-level definitions (actions, commands, effects, enums, facts, functions, structs)
//! - All statement types
//! - All expression types
//! - Complex combinations of features
//!
//! ## Test Structure
//!
//! Each test follows the same pattern:
//! 1. Define a policy string with the syntax to test
//! 2. Parse the policy using `parse_policy_str`
//! 3. Generate HIR using `hir::parse`
//! 4. Create a `RecordingVisitor` that captures all visited nodes
//! 5. Walk the HIR and capture all visited nodes
//! 6. Verify the captured nodes against a snapshot using `insta`
//!
//! ## Updating Tests
//!
//! When the HIR structure changes:
//! 1. Run `cargo test -p aranya-policy-compiler hir::visit::tests`
//! 2. Review the changes with `cargo insta review`
//! 3. Accept valid changes with `cargo insta accept`

use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;
use serde::Serialize;

use super::*;
use crate::hir::{self, hir::*};

/// Enum representing all visitable items in the HIR
#[derive(Clone, Debug, Serialize)]
enum Item {
    ActionDef(ActionDef),
    ActionArg(ActionArg),
    Block(Block),
    CmdDef(CmdDef),
    CmdField(CmdField),
    EffectDef(EffectDef),
    EffectField(EffectField),
    EnumDef(EnumDef),
    Expr(Expr),
    FactDef(FactDef),
    FactKey(FactKey),
    FactVal(FactVal),
    FactLiteral(FactLiteral),
    FinishFuncDef(FinishFuncDef),
    FinishFuncArg(FinishFuncArg),
    FuncDef(FuncDef),
    FuncArg(FuncArg),
    GlobalLetDef(GlobalLetDef),
    Ident(Ident),
    Stmt(Stmt),
    StructDef(StructDef),
    StructField(StructField),
    VType(VType),
}

/// A visitor that records all HIR nodes being visited for snapshot testing
struct RecordingVisitor {
    items: Vec<Item>,
}

impl RecordingVisitor {
    fn new() -> Self {
        Self { items: Vec::new() }
    }
}

impl<'hir> Visitor<'hir> for RecordingVisitor {
    type Result = ();

    fn visit_action_def(&mut self, def: &'hir ActionDef) {
        self.items.push(Item::ActionDef(def.clone()));
    }

    fn visit_action_arg(&mut self, arg: &'hir ActionArg) {
        self.items.push(Item::ActionArg(arg.clone()));
    }

    fn visit_block(&mut self, block: &'hir Block) {
        self.items.push(Item::Block(block.clone()));
    }

    fn visit_cmd_def(&mut self, def: &'hir CmdDef) {
        self.items.push(Item::CmdDef(def.clone()));
    }

    fn visit_cmd_field(&mut self, field: &'hir CmdField) {
        self.items.push(Item::CmdField(field.clone()));
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) {
        self.items.push(Item::EffectDef(def.clone()));
    }

    fn visit_effect_field(&mut self, field: &'hir EffectField) {
        self.items.push(Item::EffectField(field.clone()));
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) {
        self.items.push(Item::EnumDef(def.clone()));
    }

    fn visit_expr(&mut self, expr: &'hir Expr) {
        self.items.push(Item::Expr(expr.clone()));
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) {
        self.items.push(Item::FactDef(def.clone()));
    }

    fn visit_fact_key(&mut self, key: &'hir FactKey) {
        self.items.push(Item::FactKey(key.clone()));
    }

    fn visit_fact_value(&mut self, val: &'hir FactVal) {
        self.items.push(Item::FactVal(val.clone()));
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) {
        self.items.push(Item::FinishFuncDef(def.clone()));
    }

    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) {
        self.items.push(Item::FinishFuncArg(arg.clone()));
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) {
        self.items.push(Item::FuncDef(def.clone()));
    }

    fn visit_func_arg(&mut self, arg: &'hir FuncArg) {
        self.items.push(Item::FuncArg(arg.clone()));
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) {
        self.items.push(Item::GlobalLetDef(def.clone()));
    }

    fn visit_ident(&mut self, ident: &'hir Ident) {
        self.items.push(Item::Ident(ident.clone()));
    }

    fn visit_stmt(&mut self, stmt: &'hir Stmt) {
        self.items.push(Item::Stmt(stmt.clone()));
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) {
        self.items.push(Item::StructDef(def.clone()));
    }

    fn visit_struct_field(&mut self, field: &'hir StructField) {
        self.items.push(Item::StructField(field.clone()));
    }

    fn visit_vtype(&mut self, ty: &'hir VType) {
        self.items.push(Item::VType(ty.clone()));
    }

    fn visit_fact_literal(&mut self, fact: &'hir FactLiteral) {
        self.items.push(Item::FactLiteral(fact.clone()));
    }
}

/// Tests visiting an `action`.
#[test]
fn test_action() {
    let text = r#"
action foo(x int, y string) {
    let z = x + 1
}
"#;

    let policy = parse_policy_str(text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_action", &visitor.items);
}

#[test]
fn test_command() {
    let policy_text = r#"
command Foo {
    fields {
        a int,
        b string
    }
    seal { return None }
    open { return None }
    policy {
        finish {
            check true
        }
    }
    recall { return None }
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_command", &visitor.items);
}

#[test]
fn test_effect() {
    let policy_text = r#"
effect MyEffect {
    user_id string,
    timestamp int,
    active bool
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_effect", &visitor.items);
}

#[test]
fn test_enum() {
    let policy_text = r#"
enum Status {
    Active,
    Inactive
}

action use_enum() {
    let s = Status::Active
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_enum", &visitor.items);
}

#[test]
fn test_fact() {
    let policy_text = r#"
fact User[user_id string]=>{name string, age int}

action query_fact() {
    let u = query User[user_id: "123"]
    check exists User[user_id: "456"]
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    // Analysis:
    // - Actions are visited first, then facts
    // - query and exists create InternalFunction expressions
    // - FactLiteral contains identifier and field mappings

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_fact", &visitor.items);
}

#[test]
fn test_finish_function() {
    let policy_text = r#"
effect UserDeleted {
    user_id string
}

finish function cleanup(user_id string) {
    delete User[user_id: user_id]
    emit UserDeleted { user_id: user_id }
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_finish_function", &visitor.items);
}

#[test]
fn test_function() {
    let policy_text = r#"
function add(a int, b int) int {
    return a + b
}

function multiply(x int, y int) int {
    let result = x + y
    return result
}
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_function", &visitor.items);
}

#[test]
fn test_global_let() {
    let policy_text = r#"
let MAX_SIZE = 100
let DEFAULT_NAME = "anonymous"
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_global_let", &visitor.items);
}

#[test]
fn test_struct() {
    let policy_str = r#"
struct Point {
    x int,
    y int
}

struct Line {
    start struct Point,
    end struct Point,
    color optional string
}
"#;
    let policy = parse_policy_str(policy_str, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_struct", &visitor.items);
}

#[test]
fn test_expressions() {
    let policy_str = r#"
function test_expressions() int {
    // Test core expression types
    let a = 42              // Integer literal
    let b = a + 5           // Binary operation
    let c = -a              // Unary operation
    let d = Point { x: 1, y: 2 }  // Struct literal
    let e = d.x             // Field access
    let f = Some(10)        // Optional with value
    let g = unwrap f        // Unwrap operation

    return g
}

struct Point {
    x int,
    y int
}
"#;
    let policy = parse_policy_str(policy_str, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_expressions", &visitor.items);
}

#[test]
fn test_statements() {
    let policy_str = r#"
action test_statements() {
    // Test check statement
    check true

    // Test if statement
    if true {
        let x = 1
    } else {
        let x = 2
    }

    // Test match statement
    let status = 1
    match status {
        1 => {
            let result = "one"
        }
        2 => {
            let result = "two"
        }
        _ => {
            let result = "other"
        }
    }

    // Test create statement
    create User[user_id: "test"]=>{ name: "Test User" }

    // Test update statement
    update User[user_id: "test"]=>{ name: ? } to { name: "Updated User" }

    // Test delete statement
    delete User[user_id: "test"]

    // Test emit statement
    emit UserUpdated { user_id: "test" }

    // Test publish statement
    publish TestCommand { value: 42 }
}

fact User[user_id string]=>{ name string }

effect UserUpdated {
    user_id string
}

command TestCommand {
    fields {
        value int
    }
    seal {}
    open {}
    policy {}
    recall { return None }
}
"#;
    let policy = parse_policy_str(policy_str, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_statements", &visitor.items);
}

#[test]
fn test_struct_refs() {
    let policy_str = r#"
struct Point {
    x int,
    y int,
}

struct Size {
    width int,
    height int,
}

// Struct that references other structs
struct Rectangle {
    +Point,
    +Size,
}

// Struct with both fields and references
struct NamedRectangle {
    name string,
    +Point,
    +Size,
    color string,
}
"#;
    let policy = parse_policy_str(policy_str, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy, &[]);

    let mut visitor = RecordingVisitor::new();
    hir.walk(&mut visitor);

    insta::assert_json_snapshot!("test_struct_refs", &visitor.items);
}
