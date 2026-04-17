use crate::{
    EnumReference, ExprKind, Expression, Ident, NamedStruct, ResultTypeKind, Span, TypeKind, VType,
    ident,
};

// ExprKind macros to reduce boilerplate

macro_rules! ident_at {
    ($name:expr, $start:expr, $end:expr) => {
        Ident {
            inner: ident!($name),
            span: Span::new($start, $end),
        }
    };
}

macro_rules! expr {
    ($kind:expr, $start:expr, $end:expr) => {
        Expression {
            inner: $kind,
            span: Span::new($start, $end),
        }
    };
}

macro_rules! enum_ref {
    ($enum_name:expr, $variant:expr, $e_start:expr, $e_end:expr, $v_start:expr, $v_end:expr) => {
        ExprKind::EnumReference(EnumReference {
            identifier: ident_at!($enum_name, $e_start, $e_end),
            value: ident_at!($variant, $v_start, $v_end),
        })
    };
}

macro_rules! named_struct {
    ($name:expr, $s_start:expr, $s_end:expr, $field:expr, $f_start:expr, $f_end:expr, $val_kind:expr, $v_start:expr, $v_end:expr) => {
        ExprKind::NamedStruct(NamedStruct {
            identifier: ident_at!($name, $s_start, $s_end),
            fields: vec![(
                ident_at!($field, $f_start, $f_end),
                expr!($val_kind, $v_start, $v_end),
            )],
            sources: vec![],
        })
    };
}

macro_rules! some_expr {
    ($kind:expr, $start:expr, $end:expr) => {
        ExprKind::Optional(Some(Box::new(expr!($kind, $start, $end))))
    };
}

macro_rules! ok_expr {
    ($kind:expr, $start:expr, $end:expr) => {
        ExprKind::Ok(Box::new(expr!($kind, $start, $end)))
    };
}

macro_rules! err_expr {
    ($kind:expr, $start:expr, $end:expr) => {
        ExprKind::Err(Box::new(expr!($kind, $start, $end)))
    };
}

/// Unified result macro - create Ok or Err expressions
macro_rules! result {
    (Ok: $kind:expr, $start:expr, $end:expr) => {
        ok_expr!($kind, $start, $end)
    };
    (Err: $kind:expr, $start:expr, $end:expr) => {
        err_expr!($kind, $start, $end)
    };
}

macro_rules! result_type {
    ($ok_t:expr, $start1:expr, $end1:expr, $err_t:expr, $start2:expr, $end2:expr) => {
        TypeKind::Result(Box::new(ResultTypeKind {
            ok: VType {
                inner: $ok_t,
                span: Span::new($start1, $end1),
            },
            err: VType {
                inner: $err_t,
                span: Span::new($start2, $end2),
            },
        }))
    };
}

#[test]
fn test_result_type_matches() {
    let result1 = result_type!(TypeKind::Int, 5, 10, TypeKind::String, 15, 20);
    let result2 = result_type!(TypeKind::Int, 6, 11, TypeKind::String, 16, 21);

    // Same types should match
    assert!(result1.matches(&result2));

    // Different ok types should not match
    let result3 = result_type!(TypeKind::Bool, 10, 20, TypeKind::String, 30, 40);
    assert!(!result1.matches(&result3));

    // Different err types should not match
    let result4 = result_type!(TypeKind::Int, 50, 60, TypeKind::Bool, 70, 80);
    assert!(!result1.matches(&result4));
}

#[test]
fn test_expr_matches_named_struct() {
    // Two identical NamedStruct expressions with different spans should match
    let struct1 = named_struct!("MyStruct", 0, 8, "field", 9, 14, ExprKind::Int(42), 16, 18);
    let struct2 = named_struct!(
        "MyStruct",
        100,
        108,
        "field",
        109,
        114,
        ExprKind::Int(42),
        116,
        118
    );

    assert!(
        struct1.matches(&struct2),
        "NamedStruct expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_enum_reference() {
    let enum1 = enum_ref!("Color", "Red", 0, 5, 7, 10);
    let enum2 = enum_ref!("Color", "Red", 50, 55, 57, 60);

    assert!(
        enum1.matches(&enum2),
        "EnumReference expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_struct() {
    // Ok(MyStruct { field: 42 }) with different spans
    let ok1 = ok_expr!(
        named_struct!(
            "MyStruct",
            3,
            11,
            "field",
            14,
            19,
            ExprKind::Int(42),
            21,
            23
        ),
        3,
        24
    );
    let ok2 = ok_expr!(
        named_struct!(
            "MyStruct",
            200,
            208,
            "field",
            211,
            216,
            ExprKind::Int(42),
            218,
            220
        ),
        200,
        221
    );

    assert!(
        ok1.matches(&ok2),
        "Ok(NamedStruct) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_enum_ok() {
    // Ok(Color::Red) with different spans
    let ok1 = result!(Ok: enum_ref!("Color", "Red", 3, 8, 10, 13), 3, 13);
    let ok2 = result!(Ok: enum_ref!("Color", "Red", 100, 105, 107, 110), 100, 110);

    assert!(
        ok1.matches(&ok2),
        "Ok(EnumReference) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_enum_err() {
    // Err(ErrorCode::NotFound) with different spans
    let err1 = result!(Err: enum_ref!("ErrorCode", "NotFound", 4, 13, 15, 23), 4, 23);
    let err2 = result!(Err: enum_ref!("ErrorCode", "NotFound", 200, 209, 211, 219), 200, 219);

    assert!(
        err1.matches(&err2),
        "Err(EnumReference) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_different_enum_variants() {
    // Ok(Color::Red) vs Ok(Color::Blue) should NOT match
    let ok_red = ok_expr!(enum_ref!("Color", "Red", 3, 8, 10, 13), 3, 13);
    let ok_blue = ok_expr!(enum_ref!("Color", "Blue", 3, 8, 10, 14), 3, 14);

    assert!(
        !ok_red.matches(&ok_blue),
        "Ok(EnumReference) with different variants should not match"
    );
}

#[test]
fn test_expr_matches_optional() {
    // Some(Color::Green) with different spans
    let some1 = some_expr!(enum_ref!("Color", "Green", 5, 10, 12, 17), 5, 17);
    let some2 = some_expr!(enum_ref!("Color", "Green", 300, 305, 307, 312), 300, 312);

    assert!(
        some1.matches(&some2),
        "Optional(Some(EnumReference)) expressions with same content but different spans should match"
    );
}
