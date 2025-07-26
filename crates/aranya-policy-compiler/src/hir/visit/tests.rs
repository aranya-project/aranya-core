//! Comprehensive tests for the HIR visitor pattern.
//!
//! These tests ensure that all HIR node types are properly visited in the correct order.
//! Each test uses the `ExactVisitor` to verify the exact sequence of node visits matches
//! the expected traversal order.
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
//! 4. Create an `ExactVisitor` with expected nodes in the exact visitor traversal order
//! 5. Walk the HIR and verify all expected nodes are visited
//!
//! ## Node ID Assignment
//!
//! - IDs are assigned sequentially for each node type starting from 1
//! - Each identifier gets a unique IdentId, even if the string is the same
//! - The `make_id(n, 1)` helper creates IDs where n is the sequential ID for that node type

use std::collections::VecDeque;

use aranya_policy_ast::{ident, Version};
use aranya_policy_lang::lang::parse_policy_str;

use super::*;
use crate::hir::{self, dsl::make_id, hir::*};

/// Enum representing all visitable items in the HIR
#[derive(Clone, Debug)]
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

/// A visitor that verifies the exact HIR nodes being visited
struct ExactVisitor {
    expected: VecDeque<Item>,
}

impl ExactVisitor {
    fn new(expected: Vec<Item>) -> Self {
        Self {
            expected: expected.into(),
        }
    }

    fn assert_done(&self) {
        assert!(
            self.expected.is_empty(),
            "expected items not visited: {:?}",
            self.expected
        );
    }
}

impl<'hir> Visitor<'hir> for ExactVisitor {
    type Result = ();

    fn visit_action_def(&mut self, def: &'hir ActionDef) {
        match self.expected.pop_front() {
            Some(Item::ActionDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected ActionDef, got {:?}", other),
        }
    }

    fn visit_action_arg(&mut self, arg: &'hir ActionArg) {
        match self.expected.pop_front() {
            Some(Item::ActionArg(expected)) => assert_eq!(arg, &expected),
            other => panic!("Expected ActionArg, got {:?}", other),
        }
    }

    fn visit_block(&mut self, block: &'hir Block) {
        match self.expected.pop_front() {
            Some(Item::Block(expected)) => assert_eq!(block, &expected),
            other => panic!("Expected Block, got {:?}", other),
        }
    }

    fn visit_cmd_def(&mut self, def: &'hir CmdDef) {
        match self.expected.pop_front() {
            Some(Item::CmdDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected CmdDef, got {:?}", other),
        }
    }

    fn visit_cmd_field(&mut self, field: &'hir CmdField) {
        match self.expected.pop_front() {
            Some(Item::CmdField(expected)) => assert_eq!(field, &expected),
            other => panic!("Expected CmdField, got {:?}", other),
        }
    }

    fn visit_effect_def(&mut self, def: &'hir EffectDef) {
        match self.expected.pop_front() {
            Some(Item::EffectDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected EffectDef, got {:?}", other),
        }
    }

    fn visit_effect_field(&mut self, field: &'hir EffectField) {
        match self.expected.pop_front() {
            Some(Item::EffectField(expected)) => assert_eq!(field, &expected),
            other => panic!("Expected EffectField, got {:?}", other),
        }
    }

    fn visit_enum_def(&mut self, def: &'hir EnumDef) {
        match self.expected.pop_front() {
            Some(Item::EnumDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected EnumDef, got {:?}", other),
        }
    }

    fn visit_expr(&mut self, expr: &'hir Expr) {
        match self.expected.pop_front() {
            Some(Item::Expr(expected)) => assert_eq!(expr, &expected),
            other => panic!("Expected Expr, got {:?}", other),
        }
    }

    fn visit_fact_def(&mut self, def: &'hir FactDef) {
        match self.expected.pop_front() {
            Some(Item::FactDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected FactDef, got {:?}", other),
        }
    }

    fn visit_fact_key(&mut self, key: &'hir FactKey) {
        match self.expected.pop_front() {
            Some(Item::FactKey(expected)) => assert_eq!(key, &expected),
            other => panic!("Expected FactKey, got {:?}", other),
        }
    }

    fn visit_fact_value(&mut self, val: &'hir FactVal) {
        match self.expected.pop_front() {
            Some(Item::FactVal(expected)) => assert_eq!(val, &expected),
            other => panic!("Expected FactVal, got {:?}", other),
        }
    }

    fn visit_finish_func_def(&mut self, def: &'hir FinishFuncDef) {
        match self.expected.pop_front() {
            Some(Item::FinishFuncDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected FinishFuncDef, got {:?}", other),
        }
    }

    fn visit_finish_func_arg(&mut self, arg: &'hir FinishFuncArg) {
        match self.expected.pop_front() {
            Some(Item::FinishFuncArg(expected)) => assert_eq!(arg, &expected),
            other => panic!("Expected FinishFuncArg, got {:?}", other),
        }
    }

    fn visit_func_def(&mut self, def: &'hir FuncDef) {
        match self.expected.pop_front() {
            Some(Item::FuncDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected FuncDef, got {:?}", other),
        }
    }

    fn visit_func_arg(&mut self, arg: &'hir FuncArg) {
        match self.expected.pop_front() {
            Some(Item::FuncArg(expected)) => assert_eq!(arg, &expected),
            other => panic!("Expected FuncArg, got {:?}", other),
        }
    }

    fn visit_global_def(&mut self, def: &'hir GlobalLetDef) {
        match self.expected.pop_front() {
            Some(Item::GlobalLetDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected GlobalLetDef, got {:?}", other),
        }
    }

    fn visit_ident(&mut self, ident: &'hir Ident) {
        match self.expected.pop_front() {
            Some(Item::Ident(expected)) => assert_eq!(ident, &expected),
            other => panic!("Expected Ident, got {:?}", other),
        }
    }

    fn visit_stmt(&mut self, stmt: &'hir Stmt) {
        match self.expected.pop_front() {
            Some(Item::Stmt(expected)) => assert_eq!(stmt, &expected),
            other => panic!("Expected Stmt, got {:?}", other),
        }
    }

    fn visit_struct_def(&mut self, def: &'hir StructDef) {
        match self.expected.pop_front() {
            Some(Item::StructDef(expected)) => assert_eq!(def, &expected),
            other => panic!("Expected StructDef, got {:?}", other),
        }
    }

    fn visit_struct_field(&mut self, field: &'hir StructField) {
        match self.expected.pop_front() {
            Some(Item::StructField(expected)) => assert_eq!(field, &expected),
            other => panic!("Expected StructField, got {:?}", other),
        }
    }

    fn visit_vtype(&mut self, ty: &'hir VType) {
        match self.expected.pop_front() {
            Some(Item::VType(expected)) => assert_eq!(ty, &expected),
            other => panic!("Expected VType, got {:?}", other),
        }
    }

    fn visit_fact_literal(&mut self, fact: &'hir FactLiteral) {
        match self.expected.pop_front() {
            Some(Item::FactLiteral(expected)) => assert_eq!(fact, &expected),
            other => panic!("Expected FactLiteral, got {:?}", other),
        }
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
    let (hir, _) = hir::parse(&policy);

    let expected = vec![
        Item::ActionDef(ActionDef {
            // This is the first action definition.
            id: make_id(1, 1),
            // It uses the first two action arguments.
            args: vec![make_id(1, 1), make_id(2, 1)],
            block: make_id(1, 1),
        }),
        Item::ActionArg(ActionArg {
            // This is the first action argument.
            id: make_id(1, 1),
            // It uses the first identifier.
            ident: make_id(1, 1),
            // It uses the first type.
            ty: make_id(1, 1),
        }),
        Item::Ident(Ident {
            // This is the first identifier.
            id: make_id(1, 1),
            ident: ident!("x"),
        }),
        Item::VType(VType {
            // This is the first type.
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        Item::ActionArg(ActionArg {
            id: make_id(2, 1),
            ident: make_id(2, 1),
            ty: make_id(2, 1),
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("y"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::String,
        }),
        Item::Block(Block {
            id: make_id(1, 1),
            stmts: vec![make_id(1, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(3, 1),
                // NB: This is expr 3 not 1 because we construct
                // the HIR with a post-order DFS.
                expr: make_id(3, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("z"),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::Add(make_id(1, 1), make_id(2, 1)),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Identifier(make_id(4, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("x"),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Int,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    let expected = vec![
        // Commands are visited after actions, so we visit the CmdDef first
        Item::CmdDef(CmdDef {
            id: make_id(1, 1),
            fields: vec![make_id(1, 1), make_id(2, 1)],
            seal: make_id(1, 1),
            open: make_id(2, 1),
            policy: make_id(4, 1),
            recall: make_id(5, 1),
        }),
        // First field: a int
        Item::CmdField(CmdField {
            id: make_id(1, 1),
            kind: CmdFieldKind::Field {
                ident: make_id(1, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("a"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        // Second field: b string
        Item::CmdField(CmdField {
            id: make_id(2, 1),
            kind: CmdFieldKind::Field {
                ident: make_id(2, 1),
                ty: make_id(2, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("b"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::String,
        }),
        // Seal block
        Item::Block(Block {
            id: make_id(1, 1),
            stmts: vec![make_id(1, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(1, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Optional(None),
        }),
        // Open block
        Item::Block(Block {
            id: make_id(2, 1),
            stmts: vec![make_id(2, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(2, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Optional(None),
        }),
        // Policy block
        Item::Block(Block {
            id: make_id(4, 1),
            stmts: vec![make_id(4, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(4, 1),
            kind: StmtKind::Finish(make_id(3, 1)),
        }),
        Item::Block(Block {
            id: make_id(3, 1),
            stmts: vec![make_id(3, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(3, 1),
            kind: StmtKind::Check(CheckStmt {
                expr: make_id(3, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::Bool,
        }),
        // Recall block
        Item::Block(Block {
            id: make_id(5, 1),
            stmts: vec![make_id(5, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(5, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(4, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(4, 1),
            kind: ExprKind::Optional(None),
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Effects are visited after actions and commands in Hir::walk
    // - Each effect has an EffectDef with a list of field IDs
    // - Each field has an EffectField with either a Field or StructRef kind
    // - For Field kind, we visit the identifier and type

    let expected = vec![
        // Effect definition
        Item::EffectDef(EffectDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1), make_id(2, 1), make_id(3, 1)],
        }),
        // First field: user_id string
        Item::EffectField(EffectField {
            id: make_id(1, 1),
            kind: EffectFieldKind::Field {
                ident: make_id(1, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::String,
        }),
        // Second field: timestamp int
        Item::EffectField(EffectField {
            id: make_id(2, 1),
            kind: EffectFieldKind::Field {
                ident: make_id(2, 1),
                ty: make_id(2, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("timestamp"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::Int,
        }),
        // Third field: active bool
        Item::EffectField(EffectField {
            id: make_id(3, 1),
            kind: EffectFieldKind::Field {
                ident: make_id(3, 1),
                ty: make_id(3, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("active"),
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Bool,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Actions are visited first, then enums
    // - Enum references create EnumReference expressions
    // - EnumReference contains two identifiers: the enum name and the value

    let expected = vec![
        // Action is visited first (before enums)
        Item::ActionDef(ActionDef {
            id: make_id(1, 1),
            args: vec![],
            block: make_id(1, 1),
        }),
        Item::Block(Block {
            id: make_id(1, 1),
            stmts: vec![make_id(1, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(1, 1),
                expr: make_id(1, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("s"),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::EnumReference(EnumReference {
                ident: make_id(2, 1),
                value: make_id(3, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("Status"),
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("Active"),
        }),
        // Enum definition is visited after actions
        Item::EnumDef(EnumDef { id: make_id(1, 1) }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Actions are visited first, then facts
    // - query and exists create InternalFunction expressions
    // - FactLiteral contains identifier and field mappings

    let expected = vec![
        // Action is visited first
        Item::ActionDef(ActionDef {
            id: make_id(1, 1),
            args: vec![],
            block: make_id(1, 1),
        }),
        Item::Block(Block {
            id: make_id(1, 1),
            stmts: vec![make_id(1, 1), make_id(2, 1)],
        }),
        // First statement: let u = query User[id: "123"]
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(1, 1),
                expr: make_id(2, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("u"),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::InternalFunction(InternalFunction::Query(FactLiteral {
                ident: make_id(2, 1),
                keys: vec![(make_id(3, 1), FactField::Expr(make_id(1, 1)))],
                vals: vec![],
            })),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(2, 1),
            keys: vec![(make_id(3, 1), FactField::Expr(make_id(1, 1)))],
            vals: vec![],
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::String,
        }),
        // Second statement: check exists User[id: "456"]
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Check(CheckStmt {
                expr: make_id(4, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(4, 1),
            kind: ExprKind::InternalFunction(InternalFunction::Exists(FactLiteral {
                ident: make_id(4, 1),
                keys: vec![(make_id(5, 1), FactField::Expr(make_id(3, 1)))],
                vals: vec![],
            })),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(4, 1),
            keys: vec![(make_id(5, 1), FactField::Expr(make_id(3, 1)))],
            vals: vec![],
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::String,
        }),
        // Fact definition is visited after actions
        Item::FactDef(FactDef {
            id: make_id(1, 1),
            keys: vec![make_id(1, 1)],
            vals: vec![make_id(1, 1), make_id(2, 1)],
        }),
        Item::FactKey(FactKey {
            id: make_id(1, 1),
            ident: make_id(6, 1),
            ty: make_id(1, 1),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::String,
        }),
        Item::FactVal(FactVal {
            id: make_id(1, 1),
            ident: make_id(7, 1),
            ty: make_id(2, 1),
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("name"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::String,
        }),
        Item::FactVal(FactVal {
            id: make_id(2, 1),
            ident: make_id(8, 1),
            ty: make_id(3, 1),
        }),
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("age"),
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Int,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Effects are visited first, then finish functions
    // - Finish functions have args and statements but no return type
    // - Delete and emit are statements specific to finish functions

    let expected = vec![
        // Effect is visited first
        Item::EffectDef(EffectDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1)],
        }),
        Item::EffectField(EffectField {
            id: make_id(1, 1),
            kind: EffectFieldKind::Field {
                ident: make_id(1, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::String,
        }),
        // Finish function is visited after effects
        Item::FinishFuncDef(FinishFuncDef {
            id: make_id(1, 1),
            args: vec![make_id(1, 1)],
            stmts: vec![make_id(1, 1), make_id(2, 1)],
        }),
        Item::FinishFuncArg(FinishFuncArg {
            id: make_id(1, 1),
            ident: make_id(2, 1),
            ty: make_id(2, 1),
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::String,
        }),
        // First statement: delete User[user_id: user_id]
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Delete(Delete {
                fact: FactLiteral {
                    ident: make_id(3, 1),
                    keys: vec![(make_id(4, 1), FactField::Expr(make_id(1, 1)))],
                    vals: vec![],
                },
            }),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(3, 1),
            keys: vec![(make_id(4, 1), FactField::Expr(make_id(1, 1)))],
            vals: vec![],
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Identifier(make_id(5, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("user_id"),
        }),
        // Second statement: emit UserDeleted { user_id: user_id }
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Emit(Emit {
                expr: make_id(3, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::NamedStruct(NamedStruct {
                ident: make_id(6, 1),
                fields: vec![(make_id(7, 1), make_id(2, 1))],
            }),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("UserDeleted"),
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Identifier(make_id(8, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("user_id"),
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Functions are visited after finish functions
    // - Functions have args, return type, and statements
    // - Return statements reference expressions
    // - Note: * is not a valid operator in the policy language, use something else

    let expected = vec![
        // First function: add
        Item::FuncDef(FuncDef {
            id: make_id(1, 1),
            args: vec![make_id(1, 1), make_id(2, 1)],
            result: make_id(3, 1),
            stmts: vec![make_id(1, 1)],
        }),
        Item::FuncArg(FuncArg {
            id: make_id(1, 1),
            ident: make_id(1, 1),
            ty: make_id(1, 1),
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("a"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        Item::FuncArg(FuncArg {
            id: make_id(2, 1),
            ident: make_id(2, 1),
            ty: make_id(2, 1),
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("b"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::Int,
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Int,
        }),
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(3, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::Add(make_id(1, 1), make_id(2, 1)),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Identifier(make_id(3, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("a"),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Identifier(make_id(4, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("b"),
        }),
        // Second function: multiply (using addition instead)
        Item::FuncDef(FuncDef {
            id: make_id(2, 1),
            args: vec![make_id(3, 1), make_id(4, 1)],
            result: make_id(6, 1),
            stmts: vec![make_id(2, 1), make_id(3, 1)],
        }),
        Item::FuncArg(FuncArg {
            id: make_id(3, 1),
            ident: make_id(5, 1),
            ty: make_id(4, 1),
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("x"),
        }),
        Item::VType(VType {
            id: make_id(4, 1),
            kind: VTypeKind::Int,
        }),
        Item::FuncArg(FuncArg {
            id: make_id(4, 1),
            ident: make_id(6, 1),
            ty: make_id(5, 1),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("y"),
        }),
        Item::VType(VType {
            id: make_id(5, 1),
            kind: VTypeKind::Int,
        }),
        Item::VType(VType {
            id: make_id(6, 1),
            kind: VTypeKind::Int,
        }),
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(7, 1),
                expr: make_id(6, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("result"),
        }),
        Item::Expr(Expr {
            id: make_id(6, 1),
            kind: ExprKind::Add(make_id(4, 1), make_id(5, 1)),
        }),
        Item::Expr(Expr {
            id: make_id(4, 1),
            kind: ExprKind::Identifier(make_id(8, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("x"),
        }),
        Item::Expr(Expr {
            id: make_id(5, 1),
            kind: ExprKind::Identifier(make_id(9, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(9, 1),
            ident: ident!("y"),
        }),
        Item::Stmt(Stmt {
            id: make_id(3, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(7, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(7, 1),
            kind: ExprKind::Identifier(make_id(10, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(10, 1),
            ident: ident!("result"),
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
}

#[test]
fn test_global_let() {
    let policy_text = r#"
let MAX_SIZE = 100
let DEFAULT_NAME = "anonymous"
    "#;

    let policy = parse_policy_str(policy_text, Version::V2).unwrap();
    let (hir, _) = hir::parse(&policy);

    // Analysis:
    // - Global lets are visited after functions
    // - Each global let has an expression

    let expected = vec![
        // First global let: MAX_SIZE = 100
        Item::GlobalLetDef(GlobalLetDef {
            id: make_id(1, 1),
            expr: make_id(1, 1),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Int,
        }),
        // Second global let: DEFAULT_NAME = "anonymous"
        Item::GlobalLetDef(GlobalLetDef {
            id: make_id(2, 1),
            expr: make_id(2, 1),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::String,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Define expected visitor order based on debug output
    let expected = vec![
        // First struct: Point
        Item::StructDef(StructDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1), make_id(2, 1)],
        }),
        // Field x
        Item::StructField(StructField {
            id: make_id(1, 1),
            kind: StructFieldKind::Field {
                ident: make_id(1, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("x"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        // Field y
        Item::StructField(StructField {
            id: make_id(2, 1),
            kind: StructFieldKind::Field {
                ident: make_id(2, 1),
                ty: make_id(2, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("y"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::Int,
        }),
        // Second struct: Line
        Item::StructDef(StructDef {
            id: make_id(2, 1),
            items: vec![make_id(3, 1), make_id(4, 1), make_id(5, 1)],
        }),
        // Field start
        Item::StructField(StructField {
            id: make_id(3, 1),
            kind: StructFieldKind::Field {
                ident: make_id(3, 1),
                ty: make_id(3, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("start"),
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Struct(make_id(4, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("Point"),
        }),
        // Field end
        Item::StructField(StructField {
            id: make_id(4, 1),
            kind: StructFieldKind::Field {
                ident: make_id(5, 1),
                ty: make_id(4, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("end"),
        }),
        Item::VType(VType {
            id: make_id(4, 1),
            kind: VTypeKind::Struct(make_id(6, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("Point"),
        }),
        // Field color
        Item::StructField(StructField {
            id: make_id(5, 1),
            kind: StructFieldKind::Field {
                ident: make_id(7, 1),
                ty: make_id(6, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("color"),
        }),
        Item::VType(VType {
            id: make_id(6, 1),
            kind: VTypeKind::Optional(make_id(5, 1)),
        }),
        Item::VType(VType {
            id: make_id(5, 1),
            kind: VTypeKind::String,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    let expected = vec![
        // 0: FuncDef(FuncId(1v1))
        Item::FuncDef(FuncDef {
            id: make_id(1, 1),
            args: vec![],
            result: make_id(1, 1),
            stmts: vec![
                make_id(1, 1),
                make_id(2, 1),
                make_id(3, 1),
                make_id(4, 1),
                make_id(5, 1),
                make_id(6, 1),
                make_id(7, 1),
                make_id(8, 1),
            ],
        }),
        // 1: VType(VTypeId(1v1))
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        // 2: Stmt(StmtId(1v1)) - let a = 42
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(1, 1),
                expr: make_id(1, 1),
            }),
        }),
        // 3: Ident(IdentId(1v1))
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("a"),
        }),
        // 4: Expr(ExprId(1v1))
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Int,
        }),
        // 5: Stmt(StmtId(2v1)) - let b = a + 5
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(2, 1),
                expr: make_id(4, 1),
            }),
        }),
        // 6: Ident(IdentId(2v1))
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("b"),
        }),
        // 7: Expr(ExprId(4v1))
        Item::Expr(Expr {
            id: make_id(4, 1),
            kind: ExprKind::Add(make_id(2, 1), make_id(3, 1)),
        }),
        // 8: Expr(ExprId(2v1))
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Identifier(make_id(3, 1)),
        }),
        // 9: Ident(IdentId(3v1))
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("a"),
        }),
        // 10: Expr(ExprId(3v1))
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::Int,
        }),
        // 11: Stmt(StmtId(3v1)) - let c = -a
        Item::Stmt(Stmt {
            id: make_id(3, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(4, 1),
                expr: make_id(6, 1),
            }),
        }),
        // 12: Ident(IdentId(4v1))
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("c"),
        }),
        // 13: Expr(ExprId(6v1))
        Item::Expr(Expr {
            id: make_id(6, 1),
            kind: ExprKind::Negative(make_id(5, 1)),
        }),
        // 14: Expr(ExprId(5v1))
        Item::Expr(Expr {
            id: make_id(5, 1),
            kind: ExprKind::Identifier(make_id(5, 1)),
        }),
        // 15: Ident(IdentId(5v1))
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("a"),
        }),
        // 16: Stmt(StmtId(4v1)) - let d = Point { x: 1, y: 2 }
        Item::Stmt(Stmt {
            id: make_id(4, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(6, 1),
                expr: make_id(9, 1),
            }),
        }),
        // 17: Ident(IdentId(6v1))
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("d"),
        }),
        // 18: Expr(ExprId(9v1))
        Item::Expr(Expr {
            id: make_id(9, 1),
            kind: ExprKind::NamedStruct(NamedStruct {
                ident: make_id(7, 1),
                fields: vec![
                    (make_id(8, 1), make_id(7, 1)),
                    (make_id(9, 1), make_id(8, 1)),
                ],
            }),
        }),
        // 19: Ident(IdentId(7v1))
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("Point"),
        }),
        // 20: Ident(IdentId(8v1))
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("x"),
        }),
        // 21: Expr(ExprId(7v1))
        Item::Expr(Expr {
            id: make_id(7, 1),
            kind: ExprKind::Int,
        }),
        // 22: Ident(IdentId(9v1))
        Item::Ident(Ident {
            id: make_id(9, 1),
            ident: ident!("y"),
        }),
        // 23: Expr(ExprId(8v1))
        Item::Expr(Expr {
            id: make_id(8, 1),
            kind: ExprKind::Int,
        }),
        // 24: Stmt(StmtId(5v1)) - let e = d.x
        Item::Stmt(Stmt {
            id: make_id(5, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(10, 1),
                expr: make_id(11, 1),
            }),
        }),
        // 25: Ident(IdentId(10v1))
        Item::Ident(Ident {
            id: make_id(10, 1),
            ident: ident!("e"),
        }),
        // 26: Expr(ExprId(11v1))
        Item::Expr(Expr {
            id: make_id(11, 1),
            kind: ExprKind::Dot(make_id(10, 1), make_id(12, 1)),
        }),
        // 27: Expr(ExprId(10v1))
        Item::Expr(Expr {
            id: make_id(10, 1),
            kind: ExprKind::Identifier(make_id(11, 1)),
        }),
        // 28: Ident(IdentId(11v1))
        Item::Ident(Ident {
            id: make_id(11, 1),
            ident: ident!("d"),
        }),
        // 29: Ident(IdentId(12v1))
        Item::Ident(Ident {
            id: make_id(12, 1),
            ident: ident!("x"),
        }),
        // 30: Stmt(StmtId(6v1)) - let f = Some(10)
        Item::Stmt(Stmt {
            id: make_id(6, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(13, 1),
                expr: make_id(13, 1),
            }),
        }),
        // 31: Ident(IdentId(13v1))
        Item::Ident(Ident {
            id: make_id(13, 1),
            ident: ident!("f"),
        }),
        // 32: Expr(ExprId(13v1))
        Item::Expr(Expr {
            id: make_id(13, 1),
            kind: ExprKind::Optional(Some(make_id(12, 1))),
        }),
        // 33: Expr(ExprId(12v1))
        Item::Expr(Expr {
            id: make_id(12, 1),
            kind: ExprKind::Int,
        }),
        // 34: Stmt(StmtId(7v1)) - let g = unwrap f
        Item::Stmt(Stmt {
            id: make_id(7, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(14, 1),
                expr: make_id(15, 1),
            }),
        }),
        // 35: Ident(IdentId(14v1))
        Item::Ident(Ident {
            id: make_id(14, 1),
            ident: ident!("g"),
        }),
        // 36: Expr(ExprId(15v1))
        Item::Expr(Expr {
            id: make_id(15, 1),
            kind: ExprKind::Unwrap(make_id(14, 1)),
        }),
        // 37: Expr(ExprId(14v1))
        Item::Expr(Expr {
            id: make_id(14, 1),
            kind: ExprKind::Identifier(make_id(15, 1)),
        }),
        // 38: Ident(IdentId(15v1))
        Item::Ident(Ident {
            id: make_id(15, 1),
            ident: ident!("f"),
        }),
        // 39: Stmt(StmtId(8v1)) - return g
        Item::Stmt(Stmt {
            id: make_id(8, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(16, 1),
            }),
        }),
        // 40: Expr(ExprId(16v1))
        Item::Expr(Expr {
            id: make_id(16, 1),
            kind: ExprKind::Identifier(make_id(16, 1)),
        }),
        // 41: Ident(IdentId(16v1))
        Item::Ident(Ident {
            id: make_id(16, 1),
            ident: ident!("g"),
        }),
        // 42: StructDef(StructId(1v1))
        Item::StructDef(StructDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1), make_id(2, 1)],
        }),
        // 43: StructField(StructFieldId(1v1))
        Item::StructField(StructField {
            id: make_id(1, 1),
            kind: StructFieldKind::Field {
                ident: make_id(17, 1),
                ty: make_id(2, 1),
            },
        }),
        // 44: Ident(IdentId(17v1))
        Item::Ident(Ident {
            id: make_id(17, 1),
            ident: ident!("x"),
        }),
        // 45: VType(VTypeId(2v1))
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::Int,
        }),
        // 46: StructField(StructFieldId(2v1))
        Item::StructField(StructField {
            id: make_id(2, 1),
            kind: StructFieldKind::Field {
                ident: make_id(18, 1),
                ty: make_id(3, 1),
            },
        }),
        // 47: Ident(IdentId(18v1))
        Item::Ident(Ident {
            id: make_id(18, 1),
            ident: ident!("y"),
        }),
        // 48: VType(VTypeId(3v1))
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Int,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Debug to understand the visitor order
    struct StmtDebugVisitor {
        indent: usize,
    }
    impl StmtDebugVisitor {
        fn new() -> Self {
            Self { indent: 0 }
        }
        fn print(&self, msg: &str) {
            eprintln!("{}{}", " ".repeat(self.indent), msg);
        }
    }
    impl<'a> Visitor<'a> for StmtDebugVisitor {
        type Result = ();

        fn visit_action_def(&mut self, def: &ActionDef) {
            self.print(&format!("ActionDef: {:?}", def.id));
            self.indent += 2;
        }

        fn visit_stmt(&mut self, stmt: &Stmt) {
            self.print(&format!("Stmt: {:?}", stmt));
            self.indent += 2;
        }

        fn visit_expr(&mut self, expr: &Expr) {
            self.print(&format!("Expr: {:?}", expr));
        }

        fn visit_ident(&mut self, ident: &Ident) {
            self.print(&format!("Ident: {:?}", ident));
        }

        fn visit_fact_literal(&mut self, fact: &FactLiteral) {
            self.print(&format!("FactLiteral: {:?}", fact));
        }
    }

    let expected = vec![
        // ActionDef
        Item::ActionDef(ActionDef {
            id: make_id(1, 1),
            args: vec![],
            block: make_id(2, 1),
        }),
        Item::Block(Block {
            id: make_id(2, 1),
            stmts: vec![
                make_id(1, 1),
                make_id(4, 1),
                make_id(5, 1),
                make_id(9, 1),
                make_id(10, 1),
                make_id(11, 1),
                make_id(12, 1),
                make_id(13, 1),
                make_id(14, 1),
            ],
        }),
        // Check statement
        Item::Stmt(Stmt {
            id: make_id(1, 1),
            kind: StmtKind::Check(CheckStmt {
                expr: make_id(1, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(1, 1),
            kind: ExprKind::Bool,
        }),
        // If statement
        Item::Stmt(Stmt {
            id: make_id(4, 1),
            kind: StmtKind::If(IfStmt {
                branches: vec![IfBranch {
                    expr: make_id(2, 1),
                    stmts: vec![make_id(2, 1)],
                }],
                else_block: Some(make_id(1, 1)),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(2, 1),
            kind: ExprKind::Bool,
        }),
        // let x = 1 in if branch
        Item::Stmt(Stmt {
            id: make_id(2, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(1, 1),
                expr: make_id(3, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("x"),
        }),
        Item::Expr(Expr {
            id: make_id(3, 1),
            kind: ExprKind::Int,
        }),
        // Else block
        Item::Block(Block {
            id: make_id(1, 1),
            stmts: vec![make_id(3, 1)],
        }),
        // let x = 2 in else branch
        Item::Stmt(Stmt {
            id: make_id(3, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(2, 1),
                expr: make_id(4, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("x"),
        }),
        Item::Expr(Expr {
            id: make_id(4, 1),
            kind: ExprKind::Int,
        }),
        // let status = 1
        Item::Stmt(Stmt {
            id: make_id(5, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(3, 1),
                expr: make_id(5, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("status"),
        }),
        Item::Expr(Expr {
            id: make_id(5, 1),
            kind: ExprKind::Int,
        }),
        // Match statement
        Item::Stmt(Stmt {
            id: make_id(9, 1),
            kind: StmtKind::Match(MatchStmt {
                expr: make_id(6, 1),
                arms: vec![
                    MatchArm {
                        pattern: MatchPattern::Values(vec![make_id(7, 1)]),
                        stmts: vec![make_id(6, 1)],
                    },
                    MatchArm {
                        pattern: MatchPattern::Values(vec![make_id(9, 1)]),
                        stmts: vec![make_id(7, 1)],
                    },
                    MatchArm {
                        pattern: MatchPattern::Default,
                        stmts: vec![make_id(8, 1)],
                    },
                ],
            }),
        }),
        Item::Expr(Expr {
            id: make_id(6, 1),
            kind: ExprKind::Identifier(make_id(4, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("status"),
        }),
        Item::Expr(Expr {
            id: make_id(7, 1),
            kind: ExprKind::Int,
        }),
        // let result = "one"
        Item::Stmt(Stmt {
            id: make_id(6, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(5, 1),
                expr: make_id(8, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("result"),
        }),
        Item::Expr(Expr {
            id: make_id(8, 1),
            kind: ExprKind::String,
        }),
        Item::Expr(Expr {
            id: make_id(9, 1),
            kind: ExprKind::Int,
        }),
        // let result = "two"
        Item::Stmt(Stmt {
            id: make_id(7, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(6, 1),
                expr: make_id(10, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("result"),
        }),
        Item::Expr(Expr {
            id: make_id(10, 1),
            kind: ExprKind::String,
        }),
        // let result = "other"
        Item::Stmt(Stmt {
            id: make_id(8, 1),
            kind: StmtKind::Let(LetStmt {
                ident: make_id(7, 1),
                expr: make_id(11, 1),
            }),
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("result"),
        }),
        Item::Expr(Expr {
            id: make_id(11, 1),
            kind: ExprKind::String,
        }),
        // Create statement
        Item::Stmt(Stmt {
            id: make_id(10, 1),
            kind: StmtKind::Create(Create {
                fact: FactLiteral {
                    ident: make_id(8, 1),
                    keys: vec![(make_id(9, 1), FactField::Expr(make_id(12, 1)))],
                    vals: vec![(make_id(10, 1), FactField::Expr(make_id(13, 1)))],
                },
            }),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(8, 1),
            keys: vec![(make_id(9, 1), FactField::Expr(make_id(12, 1)))],
            vals: vec![(make_id(10, 1), FactField::Expr(make_id(13, 1)))],
        }),
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(9, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(12, 1),
            kind: ExprKind::String,
        }),
        Item::Ident(Ident {
            id: make_id(10, 1),
            ident: ident!("name"),
        }),
        Item::Expr(Expr {
            id: make_id(13, 1),
            kind: ExprKind::String,
        }),
        // Update statement
        Item::Stmt(Stmt {
            id: make_id(11, 1),
            kind: StmtKind::Update(Update {
                fact: FactLiteral {
                    ident: make_id(11, 1),
                    keys: vec![(make_id(12, 1), FactField::Expr(make_id(14, 1)))],
                    vals: vec![(make_id(13, 1), FactField::Bind)],
                },
                to: vec![(make_id(14, 1), FactField::Expr(make_id(15, 1)))],
            }),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(11, 1),
            keys: vec![(make_id(12, 1), FactField::Expr(make_id(14, 1)))],
            vals: vec![(make_id(13, 1), FactField::Bind)],
        }),
        Item::Ident(Ident {
            id: make_id(11, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(12, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(14, 1),
            kind: ExprKind::String,
        }),
        Item::Ident(Ident {
            id: make_id(13, 1),
            ident: ident!("name"),
        }),
        Item::Ident(Ident {
            id: make_id(14, 1),
            ident: ident!("name"),
        }),
        Item::Expr(Expr {
            id: make_id(15, 1),
            kind: ExprKind::String,
        }),
        // Delete statement
        Item::Stmt(Stmt {
            id: make_id(12, 1),
            kind: StmtKind::Delete(Delete {
                fact: FactLiteral {
                    ident: make_id(15, 1),
                    keys: vec![(make_id(16, 1), FactField::Expr(make_id(16, 1)))],
                    vals: vec![],
                },
            }),
        }),
        Item::FactLiteral(FactLiteral {
            ident: make_id(15, 1),
            keys: vec![(make_id(16, 1), FactField::Expr(make_id(16, 1)))],
            vals: vec![],
        }),
        Item::Ident(Ident {
            id: make_id(15, 1),
            ident: ident!("User"),
        }),
        Item::Ident(Ident {
            id: make_id(16, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(16, 1),
            kind: ExprKind::String,
        }),
        // Emit statement
        Item::Stmt(Stmt {
            id: make_id(13, 1),
            kind: StmtKind::Emit(Emit {
                expr: make_id(18, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(18, 1),
            kind: ExprKind::NamedStruct(NamedStruct {
                ident: make_id(17, 1),
                fields: vec![(make_id(18, 1), make_id(17, 1))],
            }),
        }),
        Item::Ident(Ident {
            id: make_id(17, 1),
            ident: ident!("UserUpdated"),
        }),
        Item::Ident(Ident {
            id: make_id(18, 1),
            ident: ident!("user_id"),
        }),
        Item::Expr(Expr {
            id: make_id(17, 1),
            kind: ExprKind::String,
        }),
        // Publish statement
        Item::Stmt(Stmt {
            id: make_id(14, 1),
            kind: StmtKind::Publish(Publish {
                exor: make_id(20, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(20, 1),
            kind: ExprKind::NamedStruct(NamedStruct {
                ident: make_id(19, 1),
                fields: vec![(make_id(20, 1), make_id(19, 1))],
            }),
        }),
        Item::Ident(Ident {
            id: make_id(19, 1),
            ident: ident!("TestCommand"),
        }),
        Item::Ident(Ident {
            id: make_id(20, 1),
            ident: ident!("value"),
        }),
        Item::Expr(Expr {
            id: make_id(19, 1),
            kind: ExprKind::Int,
        }),
        // Command definition
        Item::CmdDef(CmdDef {
            id: make_id(1, 1),
            fields: vec![make_id(1, 1)],
            seal: make_id(3, 1),
            open: make_id(4, 1),
            policy: make_id(5, 1),
            recall: make_id(6, 1),
        }),
        Item::CmdField(CmdField {
            id: make_id(1, 1),
            kind: CmdFieldKind::Field {
                ident: make_id(21, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(21, 1),
            ident: ident!("value"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        Item::Block(Block {
            id: make_id(3, 1),
            stmts: vec![],
        }),
        Item::Block(Block {
            id: make_id(4, 1),
            stmts: vec![],
        }),
        Item::Block(Block {
            id: make_id(5, 1),
            stmts: vec![],
        }),
        Item::Block(Block {
            id: make_id(6, 1),
            stmts: vec![make_id(15, 1)],
        }),
        Item::Stmt(Stmt {
            id: make_id(15, 1),
            kind: StmtKind::Return(ReturnStmt {
                expr: make_id(21, 1),
            }),
        }),
        Item::Expr(Expr {
            id: make_id(21, 1),
            kind: ExprKind::Optional(None),
        }),
        // Effect definition
        Item::EffectDef(EffectDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1)],
        }),
        Item::EffectField(EffectField {
            id: make_id(1, 1),
            kind: EffectFieldKind::Field {
                ident: make_id(22, 1),
                ty: make_id(2, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(22, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::String,
        }),
        // Fact definition
        Item::FactDef(FactDef {
            id: make_id(1, 1),
            keys: vec![make_id(1, 1)],
            vals: vec![make_id(1, 1)],
        }),
        Item::FactKey(FactKey {
            id: make_id(1, 1),
            ident: make_id(23, 1),
            ty: make_id(3, 1),
        }),
        Item::Ident(Ident {
            id: make_id(23, 1),
            ident: ident!("user_id"),
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::String,
        }),
        Item::FactVal(FactVal {
            id: make_id(1, 1),
            ident: make_id(24, 1),
            ty: make_id(4, 1),
        }),
        Item::Ident(Ident {
            id: make_id(24, 1),
            ident: ident!("name"),
        }),
        Item::VType(VType {
            id: make_id(4, 1),
            kind: VTypeKind::String,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
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
    let (hir, _) = hir::parse(&policy);

    // Analysis of visitor order:
    // - Structs are visited in order of definition
    // - Within each struct, items are visited in order
    // - StructRef items only contain the identifier reference

    let expected = vec![
        // First struct: Point
        Item::StructDef(StructDef {
            id: make_id(1, 1),
            items: vec![make_id(1, 1), make_id(2, 1)],
        }),
        Item::StructField(StructField {
            id: make_id(1, 1),
            kind: StructFieldKind::Field {
                ident: make_id(1, 1),
                ty: make_id(1, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(1, 1),
            ident: ident!("x"),
        }),
        Item::VType(VType {
            id: make_id(1, 1),
            kind: VTypeKind::Int,
        }),
        Item::StructField(StructField {
            id: make_id(2, 1),
            kind: StructFieldKind::Field {
                ident: make_id(2, 1),
                ty: make_id(2, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(2, 1),
            ident: ident!("y"),
        }),
        Item::VType(VType {
            id: make_id(2, 1),
            kind: VTypeKind::Int,
        }),
        // Second struct: Size
        Item::StructDef(StructDef {
            id: make_id(2, 1),
            items: vec![make_id(3, 1), make_id(4, 1)],
        }),
        Item::StructField(StructField {
            id: make_id(3, 1),
            kind: StructFieldKind::Field {
                ident: make_id(3, 1),
                ty: make_id(3, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(3, 1),
            ident: ident!("width"),
        }),
        Item::VType(VType {
            id: make_id(3, 1),
            kind: VTypeKind::Int,
        }),
        Item::StructField(StructField {
            id: make_id(4, 1),
            kind: StructFieldKind::Field {
                ident: make_id(4, 1),
                ty: make_id(4, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(4, 1),
            ident: ident!("height"),
        }),
        Item::VType(VType {
            id: make_id(4, 1),
            kind: VTypeKind::Int,
        }),
        // Third struct: Rectangle (with struct refs)
        Item::StructDef(StructDef {
            id: make_id(3, 1),
            items: vec![make_id(5, 1), make_id(6, 1)],
        }),
        Item::StructField(StructField {
            id: make_id(5, 1),
            kind: StructFieldKind::StructRef(make_id(5, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(5, 1),
            ident: ident!("Point"),
        }),
        Item::StructField(StructField {
            id: make_id(6, 1),
            kind: StructFieldKind::StructRef(make_id(6, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(6, 1),
            ident: ident!("Size"),
        }),
        // Fourth struct: NamedRectangle (mixed fields and refs)
        Item::StructDef(StructDef {
            id: make_id(4, 1),
            items: vec![make_id(7, 1), make_id(8, 1), make_id(9, 1), make_id(10, 1)],
        }),
        Item::StructField(StructField {
            id: make_id(7, 1),
            kind: StructFieldKind::Field {
                ident: make_id(7, 1),
                ty: make_id(5, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(7, 1),
            ident: ident!("name"),
        }),
        Item::VType(VType {
            id: make_id(5, 1),
            kind: VTypeKind::String,
        }),
        Item::StructField(StructField {
            id: make_id(8, 1),
            kind: StructFieldKind::StructRef(make_id(8, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(8, 1),
            ident: ident!("Point"),
        }),
        Item::StructField(StructField {
            id: make_id(9, 1),
            kind: StructFieldKind::StructRef(make_id(9, 1)),
        }),
        Item::Ident(Ident {
            id: make_id(9, 1),
            ident: ident!("Size"),
        }),
        Item::StructField(StructField {
            id: make_id(10, 1),
            kind: StructFieldKind::Field {
                ident: make_id(10, 1),
                ty: make_id(6, 1),
            },
        }),
        Item::Ident(Ident {
            id: make_id(10, 1),
            ident: ident!("color"),
        }),
        Item::VType(VType {
            id: make_id(6, 1),
            kind: VTypeKind::String,
        }),
    ];

    let mut visitor = ExactVisitor::new(expected);
    hir.walk(&mut visitor);
    visitor.assert_done();
}
