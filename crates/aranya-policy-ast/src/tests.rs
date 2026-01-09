#![cfg(test)]

use crate::{ResultTypeKind, Span, TypeKind, VType};

#[test]
fn test_result_type_matches() {
    let result1 = TypeKind::Result(Box::new(ResultTypeKind {
        ok: VType {
            kind: TypeKind::Int,
            span: Span::empty(),
        },
        err: VType {
            kind: TypeKind::String,
            span: Span::empty(),
        },
    }));

    let result2 = TypeKind::Result(Box::new(ResultTypeKind {
        ok: VType {
            kind: TypeKind::Int,
            span: Span::empty(),
        },
        err: VType {
            kind: TypeKind::String,
            span: Span::empty(),
        },
    }));

    // Same types should match
    assert!(result1.matches(&result2));

    // Different ok types should not match
    let result3 = TypeKind::Result(Box::new(ResultTypeKind {
        ok: VType {
            kind: TypeKind::Bool,
            span: Span::empty(),
        },
        err: VType {
            kind: TypeKind::String,
            span: Span::empty(),
        },
    }));
    assert!(!result1.matches(&result3));

    // Different err types should not match
    let result4 = TypeKind::Result(Box::new(ResultTypeKind {
        ok: VType {
            kind: TypeKind::Int,
            span: Span::empty(),
        },
        err: VType {
            kind: TypeKind::Bool,
            span: Span::empty(),
        },
    }));
    assert!(!result1.matches(&result4));
}
