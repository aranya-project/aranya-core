use aranya_policy_ast::{
    Identifier, Param, WithSpan,
    thir::{ExprKind, Expression, NamedStruct},
};
use sha2::{Digest as _, Sha256};

/// Hashes data from an AST representation and updates a [`Digest`](sha2::Digest) with the type, identifier.
///
/// ```ignore
/// update_hash_parts!(self.signature_hasher => Enum &enum_def.identifier, &enum_def.variants);
/// ```
macro_rules! update_hash_parts {
    ($hasher:expr => $kind:ident $name:expr, $($tail:tt)* ) => {
        $hasher.update([0x01]); // ASCII Start of Heading
        $hasher.update(stringify!($kind).as_bytes());
        $hasher.update([0x1F]); // ASCII Unit Separator
        $name.ast_hash(&mut $hasher);
        $hasher.update([0x02]); // ASCII Start of Text
        update_hash_parts!($hasher => $($tail)*);
    };
    ($hasher:expr => $item:expr, $($tail:tt)*) => {
        // TODO(chip): When `inter_intersperse` becomes stable, use that instead
        $item.ast_hash(&mut $hasher);
        $hasher.update([0x1E]); // ASCII Group Separator
        update_hash_parts!($hasher => $($tail)*)
    };
    ($hasher:expr => $item:expr) => {
        $item.ast_hash(&mut $hasher);
        $hasher.update([0x04]); // ASCII End of Text
    };
}

pub(crate) trait AstHash {
    fn ast_hash(&self, hasher: &mut Sha256);
}

impl<T: AstHash + ?Sized> AstHash for &T {
    fn ast_hash(&self, hasher: &mut Sha256) {
        (*self).ast_hash(hasher);
    }
}

impl AstHash for str {
    fn ast_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.as_bytes());
    }
}

impl AstHash for Identifier {
    fn ast_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.as_str().as_bytes());
    }
}

impl<T: AstHash> AstHash for WithSpan<T> {
    fn ast_hash(&self, hasher: &mut Sha256) {
        self.inner.ast_hash(hasher);
    }
}

impl<T: AstHash> AstHash for &[T] {
    fn ast_hash(&self, hasher: &mut Sha256) {
        let last_item = self.len().saturating_sub(1); // If there are zero parts, this will still do nothing.
        for (i, f) in self.iter().enumerate() {
            f.ast_hash(hasher);
            if i < last_item {
                hasher.update([0x1F]); // ASCII Unit Separator
            }
        }
    }
}

impl<T: AstHash> AstHash for Vec<T> {
    fn ast_hash(&self, hasher: &mut Sha256) {
        self.as_slice().ast_hash(hasher);
    }
}

impl<T: AstHash> AstHash for Option<T> {
    fn ast_hash(&self, hasher: &mut Sha256) {
        if let Some(v) = self {
            v.ast_hash(hasher);
        } else {
            hasher.update([0]);
        }
    }
}

impl AstHash for Param {
    fn ast_hash(&self, hasher: &mut Sha256) {
        self.name.ast_hash(hasher);
        hasher.update([0x1F]);
        self.ty.to_string().as_str().ast_hash(hasher);
    }
}

impl AstHash for NamedStruct {
    fn ast_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.identifier.as_str().as_bytes());
        self.fields.ast_hash(hasher);
        self.sources.ast_hash(hasher);
    }
}

impl AstHash for ExprKind {
    fn ast_hash(&self, hasher: &mut Sha256) {
        match self {
            ExprKind::Unit => "Unit".ast_hash(hasher),
            ExprKind::Int(v) => format!("Int\x1F{v}").ast_hash(hasher),
            ExprKind::String(text) => format!("String\x1F{text}").ast_hash(hasher),
            ExprKind::Bool(v) => format!("Bool\x1F{v}").ast_hash(hasher),
            ExprKind::Optional(expression) => {
                hasher.update(b"Option\x1F");
                if let Some(e) = expression {
                    e.ast_hash(hasher);
                }
            }
            ExprKind::NamedStruct(named_struct) => {
                "NamedStruct".ast_hash(hasher);
                named_struct.ast_hash(hasher)
            }
            ExprKind::InternalFunction(internal_function) => {
                "InternalFunction".ast_hash(hasher);
                internal_function.ast_hash(hasher);
            }
            ExprKind::FunctionCall(function_call) => function_call.ast_hash(hasher),
            ExprKind::ForeignFunctionCall(foreign_function_call) => {
                foreign_function_call.ast_hash(hasher)
            }
            ExprKind::Return(expression) => {
                "Return".ast_hash(hasher);
                expression.ast_hash(hasher)
            }
            ExprKind::Recall(recall_call) => {
                "Recall".ast_hash(hasher);
                recall_call.ast_hash(hasher)
            }
            ExprKind::Identifier(ident) => {
                "Identifier".ast_hash(hasher);
                ident.ast_hash(hasher);
            }
            ExprKind::EnumReference(enum_reference) => {
                "EnumReference".ast_hash(hasher);
                enum_reference.ast_hash(hasher);
            }
            ExprKind::And(a, b) => {
                "And".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::Or(a, b) => {
                "Or".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::Coalesce(a, b) => {
                "Coalesce".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::Equal(a, b) => {
                "Equal".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::NotEqual(a, b) => {
                "NotEqual".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::GreaterThan(a, b) => {
                "GreaterThan".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::LessThan(a, b) => {
                "LessThan".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::GreaterThanOrEqual(a, b) => {
                "GreaterThanOrEqual".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::LessThanOrEqual(a, b) => {
                "LessThanOrEqual".ast_hash(hasher);
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::Dot(a, b) => {
                "Dot".ast_hash(hasher); // Added for consistency
                a.ast_hash(hasher);
                b.ast_hash(hasher);
            }
            ExprKind::Not(e) => {
                "Not".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
            ExprKind::Unwrap(e) => {
                "Unwrap".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
            ExprKind::CheckUnwrap(e) => {
                "CheckUnwrap".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
            ExprKind::Is(e, is_some) => {
                "Is".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
                is_some.ast_hash(hasher);
            }
            ExprKind::Block(statements, e) => {
                "Block".ast_hash(hasher); // Added for consistency
                for s in statements {
                    s.ast_hash(hasher);
                }
                e.ast_hash(hasher);
            }
            ExprKind::Substruct(e, ident) => {
                "Substruct".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
                ident.ast_hash(hasher);
            }
            ExprKind::Cast(e, ident) => {
                "Cast".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
                ident.ast_hash(hasher);
            }
            ExprKind::Match(e) => {
                "Match".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
            ExprKind::Ok(e) => {
                "Ok".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
            ExprKind::Err(e) => {
                "Err".ast_hash(hasher); // Added for consistency
                e.ast_hash(hasher);
            }
        }
    }
}

impl AstHash for Expression {
    fn ast_hash(&self, hasher: &mut Sha256) {
        self.kind.ast_hash(hasher);
    }
}

impl<T1: AstHash, T2: AstHash> AstHash for (T1, T2) {
    fn ast_hash(&self, hasher: &mut Sha256) {
        self.0.ast_hash(hasher);
        self.1.ast_hash(hasher);
    }
}
