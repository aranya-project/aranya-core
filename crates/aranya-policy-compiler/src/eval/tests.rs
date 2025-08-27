use aranya_policy_ast::Version;
use aranya_policy_lang::lang::parse_policy_str;

use crate::{
    ctx::{Ctx, InnerCtx, Session},
    diag::DiagCtx,
    eval::{Const, ConstEval, Consts, Error as ConstError, Value},
    hir::{ExprId, HirView, LowerAst},
    symtab::SymbolResolution,
    typecheck::TypesPass,
};

/// Build a context and run the required passes, then invoke `f`.
fn with_const_eval<T>(
    policy_text: &str,
    f: impl for<'cx> FnOnce(Ctx<'cx>, &'cx Consts, HirView<'cx>) -> T,
) -> T {
    let policy = parse_policy_str(policy_text, Version::V2).expect("parse");
    let codemap = aranya_policy_module::CodeMap::new(&policy.text, policy.ranges.clone());
    let sess = Session {
        dcx: DiagCtx::new(&policy.text, "test.policy"),
    };
    let ast = crate::ast::Ast {
        ast: &policy,
        schemas: &[],
        codemap: &codemap,
    };
    let inner = InnerCtx::new(&sess, ast);
    let cx = Ctx { inner: &inner };

    // Trigger dependency chain
    let _ = cx.get::<LowerAst>().expect("lower ok");
    let _ = cx.get::<SymbolResolution>().expect("symbols ok");
    let _ = cx.get::<TypesPass>().expect("types ok");
    let consts = cx.get::<ConstEval>().expect("const eval ok");
    let hir = cx.hir().expect("hir view");
    f(cx, consts, hir)
}

fn last_return_expr(hir: HirView<'_>) -> ExprId {
    let (_, func) = hir.hir().funcs.iter().next().expect("one function");
    let body = hir.lookup(func.body);
    let last_stmt = *body.stmts.last().expect("return stmt");
    match &hir.lookup(last_stmt).kind {
        crate::hir::StmtKind::Return(r) => r.expr,
        other => panic!("expected Return, got {other:?}"),
    }
}

fn const_get<'cx>(
    cx: Ctx<'cx>,
    consts: &'cx Consts,
    expr: ExprId,
) -> Option<Result<Const<&'cx Value>, ConstError>> {
    let cons = consts.exprs.get(&expr).copied()?;
    match cons {
        Ok(Const::Lit(v)) => Some(Ok(Const::Lit(cx.get_const(v)))),
        Ok(Const::Expr(v)) => Some(Ok(Const::Expr(cx.get_const(v)))),
        Err(err) => Some(Err(err)),
    }
}

fn const_get_lit<'cx>(
    cx: Ctx<'cx>,
    consts: &'cx Consts,
    expr: ExprId,
) -> Option<Result<&'cx Value, ConstError>> {
    const_get(cx, consts, expr).and_then(|res| match res {
        Ok(Const::Lit(v)) => Some(Ok(v)),
        Ok(Const::Expr(_)) => None,
        Err(err) => Some(Err(err)),
    })
}

#[test]
fn test_literals_int_bool_string() {
    with_const_eval("function f() int { return 42 }", |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Int(n) => assert_eq!(*n, 42),
            _ => panic!(),
        }
    });

    with_const_eval("function f() bool { return true }", |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Bool(b) => assert!(*b),
            _ => panic!(),
        }
    });

    with_const_eval(
        "function f() string { return \"abc\" }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
            match v {
                Value::String(t) => assert_eq!(cx.get_text(*t).as_str(), "abc"),
                _ => panic!(),
            }
        },
    );
}

#[test]
fn test_optional_some_none() {
    with_const_eval(
        "function f() optional int { return Some(5) }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let v = const_get(cx, consts, expr_id).unwrap().unwrap();
            match v {
                Const::Expr(val) | Const::Lit(val) => match val {
                    Value::Optional(Some(_)) => {}
                    _ => panic!(),
                },
            }
        },
    );

    with_const_eval(
        "function f() optional int { return None }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let v = const_get(cx, consts, expr_id).unwrap().unwrap();
            match v {
                Const::Expr(val) | Const::Lit(val) => match val {
                    Value::Optional(None) => {}
                    _ => panic!(),
                },
            }
        },
    );
}

#[test]
fn test_unary_and_binary_ops_and_overflow() {
    with_const_eval(
        "function f() int { return -(-1) + 2 }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let v = const_get(cx, consts, expr_id).unwrap().unwrap();
            match v {
                Const::Lit(Value::Int(n)) | Const::Expr(Value::Int(n)) => assert_eq!(*n, 3),
                _ => panic!(),
            }
        },
    );

    // overflow: -i64::MIN
    // Use max + 1 which parses and overflows during eval
    with_const_eval(
        "function f() int { return 9223372036854775807 + 1 }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let err = const_get(cx, consts, expr_id).unwrap().err().unwrap();
            assert!(matches!(err, ConstError::IntOverflow));
        },
    );
}

#[test]
fn test_ternary_and_is_predicate() {
    with_const_eval(
        "function f() int { return if true { :1 } else { :2 } }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let got = const_get(cx, consts, expr_id).unwrap().unwrap();
            match got {
                Const::Expr(_) | Const::Lit(_) => {}
            }
        },
    );

    with_const_eval(
        "function f() bool { return (Some(1)) is Some }",
        |cx, consts, hir| {
            let expr_id = last_return_expr(hir);
            let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
            match v {
                Value::Bool(b) => assert!(*b),
                _ => panic!(),
            }
        },
    );
}

#[test]
fn test_match_values_and_default() {
    let src = r#"function f() int { let x = 2 return match x { 1 => { :10 } 2 => { :20 } _ => { :30 } } }"#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Const::Expr(val) | Const::Lit(val) => match val {
                Value::Int(n) => assert_eq!(*n, 20),
                _ => panic!(),
            },
        }
    });
}

#[test]
fn test_struct_field_access_constant() {
    let src = r#"
        struct Foo { x int, y int }
        function f() int {
            let a = Foo { x: 1, y: 2 }
            return a.x
        }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Int(n) => assert_eq!(*n, 1),
            _ => panic!(),
        }
    });
}

#[test]
#[ignore = "Function-call const eval path still unstable; enable after pass fixes"]
fn test_function_call_constness_allowed_body() {
    let src = r#"
        function g(a int, b int) int { let c = a + b return c }
        function f() int { return g(1, 2) }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Int(n) => assert_eq!(*n, 3),
            _ => panic!(),
        }
    });
}

#[test]
#[ignore = "Disallowing side-effect/control-flow in callees in const eval not enforced yet"]
fn test_function_call_constness_disallowed_body() {
    // Use a disallowed construct in callee to force NotConst
    let src = r#"
        function g() int { if true {} return 0 }
        function f() int { return g() }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        assert!(const_get(cx, consts, expr_id).is_none());
    });
}

#[test]
#[ignore = "Serialize/never intrinsics constness pending stabilization"]
fn test_intrinsics_and_foreign_call() {
    // serialize should not be a constant
    let src = r#"
        struct S { x int }
        function f() bytes { return serialize(S { x: 1 }) }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        assert!(const_get(cx, consts, expr_id).is_none());
    });
}

#[test]
#[ignore = "Struct cast/substruct const eval path pending fixes in type/symbol resolution"]
fn test_struct_dot_cast_substruct() {
    let src = r#"
        struct Foo { x int, y int }
        struct Bar { y int, x int }
        function f() int {
            let a = Foo { x: 1, y: 2 }
            let b = a as Bar
            return b.x
        }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Int(n) => assert_eq!(*n, 1),
            _ => panic!(),
        }
    });

    let src = r#"
        struct Foo { x int, y int, z int }
        struct Small { x int, z int }
        function f() int {
            let a = Foo { x: 7, y: 9, z: 3 }
            let s = a substruct Small
            return s.z
        }
    "#;
    with_const_eval(src, |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let v = const_get_lit(cx, consts, expr_id).unwrap().unwrap();
        match v {
            Value::Int(n) => assert_eq!(*n, 3),
            _ => panic!(),
        }
    });
}

#[test]
fn test_view_api_get_vs_get_lit() {
    with_const_eval("function f() int { return 1 + 2 }", |cx, consts, hir| {
        let expr_id = last_return_expr(hir);
        let g = const_get(cx, consts, expr_id).unwrap().unwrap();
        match g {
            Const::Expr(_) => {}
            _ => panic!(),
        }
        assert!(const_get_lit(cx, consts, expr_id).is_none());
    });
}
