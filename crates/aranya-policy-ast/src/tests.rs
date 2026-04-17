use crate::{
    EnumReference, ExprKind, Expression, Ident, NamedStruct, ResultTypeKind, TypeKind, VType,
    WithSpanExt as _, ident,
};

// Helper functions to reduce boilerplate

fn enum_ref(identifier: Ident, value: Ident) -> ExprKind {
    ExprKind::EnumReference(EnumReference { identifier, value })
}

fn named_struct(name: Ident, fields: impl IntoIterator<Item = (Ident, Expression)>) -> ExprKind {
    ExprKind::NamedStruct(NamedStruct {
        identifier: name,
        fields: fields.into_iter().collect(),
        sources: Vec::new(),
    })
}

fn some_expr(expr: Expression) -> ExprKind {
    ExprKind::Optional(Some(Box::new(expr)))
}

fn ok_expr(expr: Expression) -> ExprKind {
    ExprKind::Ok(Box::new(expr))
}

fn err_expr(expr: Expression) -> ExprKind {
    ExprKind::Err(Box::new(expr))
}

pub fn result_type(ok: VType, err: VType) -> TypeKind {
    TypeKind::Result(Box::new(ResultTypeKind { ok, err }))
}

#[test]
fn test_result_type_matches() {
    let result1 = result_type(TypeKind::Int.at(5..10), TypeKind::String.at(15..20));
    let result2 = result_type(TypeKind::Int.at(6..11), TypeKind::String.at(16..21));

    // Same types should match
    assert!(result1.matches(&result2));

    // Different ok types should not match
    let result3 = result_type(TypeKind::Bool.at(10..20), TypeKind::String.at(30..40));
    assert!(!result1.matches(&result3));

    // Different err types should not match
    let result4 = result_type(TypeKind::Int.at(50..60), TypeKind::Bool.at(70..80));
    assert!(!result1.matches(&result4));
}

#[test]
fn test_expr_matches_named_struct() {
    // Two identical NamedStruct expressions with different spans should match
    let struct1 = named_struct(
        ident!("MyStruct").at(0..8),
        [(ident!("field").at(9..14), ExprKind::Int(42).at(16..18))],
    );
    let struct2 = named_struct(
        ident!("MyStruct").at(100..108),
        [(ident!("field").at(109..114), ExprKind::Int(42).at(116..118))],
    );

    assert!(
        struct1.matches(&struct2),
        "NamedStruct expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_enum_reference() {
    let enum1 = enum_ref(ident!("Color").at(0..5), ident!("Red").at(7..10));
    let enum2 = enum_ref(ident!("Color").at(50..55), ident!("Red").at(57..60));

    assert!(
        enum1.matches(&enum2),
        "EnumReference expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_struct() {
    // Ok(MyStruct { field: 42 }) with different spans
    let ok1 = ok_expr(
        named_struct(
            ident!("MyStruct").at(3..11),
            [(ident!("field").at(14..19), ExprKind::Int(42).at(21..23))],
        )
        .at(3..24),
    );
    let ok2 = ok_expr(
        named_struct(
            ident!("MyStruct").at(200..208),
            [(ident!("field").at(211..216), ExprKind::Int(42).at(218..220))],
        )
        .at(200..221),
    );

    assert!(
        ok1.matches(&ok2),
        "Ok(NamedStruct) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_enum_ok() {
    // Ok(Color::Red) with different spans
    let ok1 = ok_expr(enum_ref(ident!("Color").at(3..8), ident!("Red").at(10..13)).at(3..13));
    let ok2 =
        ok_expr(enum_ref(ident!("Color").at(100..105), ident!("Red").at(107..110)).at(100..110));

    assert!(
        ok1.matches(&ok2),
        "Ok(EnumReference) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_enum_err() {
    // Err(ErrorCode::NotFound) with different spans
    let err1 =
        err_expr(enum_ref(ident!("ErrorCode").at(4..13), ident!("NotFound").at(15..23)).at(4..23));
    let err2 = err_expr(
        enum_ref(
            ident!("ErrorCode").at(200..209),
            ident!("NotFound").at(211..219),
        )
        .at(200..219),
    );

    assert!(
        err1.matches(&err2),
        "Err(EnumReference) expressions with same content but different spans should match"
    );
}

#[test]
fn test_expr_matches_result_with_different_enum_variants() {
    // Ok(Color::Red) vs Ok(Color::Blue) should NOT match
    let ok_red = ok_expr(enum_ref(ident!("Color").at(3..8), ident!("Red").at(10..13)).at(3..13));
    let ok_blue = ok_expr(enum_ref(ident!("Color").at(3..8), ident!("Blue").at(10..14)).at(3..14));

    assert!(
        !ok_red.matches(&ok_blue),
        "Ok(EnumReference) with different variants should not match"
    );
}

#[test]
fn test_expr_matches_optional() {
    // Some(Color::Green) with different spans
    let some1 =
        some_expr(enum_ref(ident!("Color").at(5..10), ident!("Green").at(12..17)).at(5..17));
    let some2 = some_expr(
        enum_ref(ident!("Color").at(300..305), ident!("Green").at(307..312)).at(300..312),
    );

    assert!(
        some1.matches(&some2),
        "Optional(Some(EnumReference)) expressions with same content but different spans should match"
    );
}
