use aranya_policy_ast::{
    ActionDefinition, CheckStatement, CommandDefinition, CreateStatement, DeleteStatement,
    EffectDefinition, EffectFieldDefinition, EnumDefinition, EnumReference, ExprKind,
    FactCountType, FactDefinition, FactField, FactLiteral, FieldDefinition,
    FinishFunctionDefinition, ForeignFunctionCall, FunctionCall, FunctionDefinition,
    GlobalLetStatement, Identifier, IfStatement, InternalFunction, LetStatement, MapStatement,
    MatchArm, MatchExpression, MatchExpressionArm, MatchPattern, MatchStatement, NamedStruct,
    Param, Persistence, Policy, RecallBlockDefinition, ReturnStatement, StmtKind, StructDefinition,
    StructItem, Text, TypeKind, UpdateStatement, Version, WithSpan,
};
use sha2::digest::Update;

/// Hashes data from an AST representation and updates a [`Digest`](sha2::Digest) with the type, identifier.
///
/// ```ignore
/// update_hash_parts!(self.signature_hasher => Enum &enum_def.identifier, &enum_def.variants);
/// ```
macro_rules! update_hash_parts {
    // A type with no name uses _, which elides the name from the output
    ($hasher:expr => $ident:ident _, $($tail:tt)* ) => {
        $hasher.update(&[0x01]); // ASCII Start of Heading
        $hasher.update(stringify!($kind).as_bytes());
        $hasher.update(&[0x02]); // ASCII Start of Text
        update_hash_parts!($hasher => $($tail)*);
    };
    // A type with a name encodes it before the SOT marker
    ($hasher:expr => $kind:ident $name:expr, $($tail:tt)* ) => {
        $hasher.update(&[0x01]); // ASCII Start of Heading
        $hasher.update(stringify!($kind).as_bytes());
        $hasher.update(&[0x1F]); // ASCII Unit Separator
        $name.ast_hash($hasher);
        $hasher.update(&[0x02]); // ASCII Start of Text
        update_hash_parts!($hasher => $($tail)*);
    };
    // A type with no data other than the name
    ($hasher:expr => $kind:ident $name:expr) => {
        $hasher.update(&[0x01]); // ASCII Start of Heading
        $hasher.update(stringify!($kind).as_bytes());
        $hasher.update(&[0x1F]); // ASCII Unit Separator
        $name.ast_hash($hasher);
        $hasher.update(&[0x04]); // ASCII End of Text
    };
    // Recursive case for interior items
    ($hasher:expr => $item:expr, $($tail:tt)*) => {
        // TODO(chip): When `inter_intersperse` becomes stable, use that instead
        $item.ast_hash($hasher);
        $hasher.update(&[0x1E]); // ASCII Group Separator
        update_hash_parts!($hasher => $($tail)*)
    };
    // Terminal case for interior items
    ($hasher:expr => $item:expr) => {
        $item.ast_hash($hasher);
        $hasher.update(&[0x04]); // ASCII End of Text
    };
}

/// Trait for computing the hash of an AST component
pub(crate) trait AstHash {
    fn ast_hash(&self, hasher: &mut impl Update);
}

impl<T: AstHash + ?Sized> AstHash for &T {
    fn ast_hash(&self, hasher: &mut impl Update) {
        (*self).ast_hash(hasher);
    }
}

impl<T: AstHash> AstHash for &[T] {
    fn ast_hash(&self, hasher: &mut impl Update) {
        let last_item = self.len().saturating_sub(1); // If there are zero parts, this will still do nothing.
        for (i, f) in self.iter().enumerate() {
            f.ast_hash(hasher);
            if i < last_item {
                hasher.update(&[0x1F]); // ASCII Unit Separator
            }
        }
    }
}

impl<T: AstHash> AstHash for Vec<T> {
    fn ast_hash(&self, hasher: &mut impl Update) {
        self.as_slice().ast_hash(hasher);
    }
}

impl<T1: AstHash, T2: AstHash> AstHash for (T1, T2) {
    fn ast_hash(&self, hasher: &mut impl Update) {
        self.0.ast_hash(hasher);
        hasher.update(&[0x1F]);
        self.1.ast_hash(hasher);
    }
}

impl<T: AstHash> AstHash for Option<T> {
    fn ast_hash(&self, hasher: &mut impl Update) {
        if let Some(v) = self {
            v.ast_hash(hasher);
        } else {
            hasher.update(&[0]);
        }
    }
}

impl<T: AstHash> AstHash for Box<T> {
    fn ast_hash(&self, hasher: &mut impl Update) {
        (**self).ast_hash(hasher);
    }
}

impl AstHash for i64 {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(&self.to_le_bytes());
    }
}

impl AstHash for usize {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(&self.to_le_bytes());
    }
}

impl AstHash for bool {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(if *self { &[1] } else { &[0] });
    }
}

impl AstHash for str {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(self.as_bytes());
    }
}

impl AstHash for Text {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(self.as_str().as_bytes());
    }
}

impl AstHash for Identifier {
    fn ast_hash(&self, hasher: &mut impl Update) {
        hasher.update(self.as_str().as_bytes());
    }
}

impl<T: AstHash> AstHash for WithSpan<T> {
    fn ast_hash(&self, hasher: &mut impl Update) {
        self.inner.ast_hash(hasher);
    }
}

impl AstHash for Param {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => Param &self.name, self.ty);
    }
}

impl AstHash for NamedStruct {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => NamedStruct self.identifier, self.fields, self.sources);
    }
}

impl AstHash for FactField {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Expression(e) => e.ast_hash(hasher),
            Self::Bind(_) => hasher.update(b"?"),
        }
    }
}

impl AstHash for FactLiteral {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FactLiteral self.identifier, self.key_fields, self.value_fields);
    }
}

impl AstHash for FunctionCall {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FunctionCall self.identifier, self.arguments);
    }
}

impl AstHash for ForeignFunctionCall {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => ForeignFunctionCall self.module, self.identifier, self.arguments);
    }
}

impl AstHash for EnumReference {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => EnumReference self.identifier, self.value);
    }
}

impl AstHash for InternalFunction {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Query(fact) => {
                update_hash_parts!(hasher => Query _, fact);
            }
            Self::Exists(fact) => {
                update_hash_parts!(hasher => Exists _, fact);
            }
            Self::FactCount(ty, lit, fact) => {
                update_hash_parts!(hasher => FactCount _, ty, lit, fact);
            }
            Self::If(cond, then, else_) => {
                update_hash_parts!(hasher => If _, cond, then, else_);
            }
            Self::Todo(_span) => {
                hasher.update(b"Todo");
            }
            Self::TestFail(msg, _span) => {
                update_hash_parts!(hasher => TestFail _, msg);
            }
        }
    }
}

impl AstHash for FactCountType {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::UpTo(_) => hasher.update(b"UpTo"),
            Self::AtLeast(_) => hasher.update(b"AtLeast"),
            Self::AtMost(_) => hasher.update(b"AtMost"),
            Self::Exactly(_) => hasher.update(b"Exactly"),
        }
    }
}

impl AstHash for ExprKind {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Unit => hasher.update(b"Unit"),
            Self::Int(v) => {
                update_hash_parts!(hasher => Int _, v);
            }
            Self::String(text) => {
                update_hash_parts!(hasher => String _, text);
            }
            Self::Bool(v) => {
                update_hash_parts!(hasher => Bool _, v);
            }
            Self::Optional(expression) => {
                update_hash_parts!(hasher => Option _, expression);
            }
            Self::NamedStruct(named_struct) => {
                named_struct.ast_hash(hasher);
            }
            Self::InternalFunction(internal_function) => {
                update_hash_parts!(hasher => InternalFunction _, internal_function);
            }
            Self::FunctionCall(function_call) => {
                function_call.ast_hash(hasher);
            }
            Self::ForeignFunctionCall(foreign_function_call) => {
                foreign_function_call.ast_hash(hasher);
            }
            Self::Return(expression) => {
                update_hash_parts!(hasher => Return _, expression);
            }
            Self::Recall(recall_call) => {
                recall_call.ast_hash(hasher);
            }
            Self::Identifier(ident) => {
                update_hash_parts!(hasher => Identifier _, ident);
            }
            Self::EnumReference(enum_reference) => {
                enum_reference.ast_hash(hasher);
            }
            Self::And(a, b) => {
                update_hash_parts!(hasher => And _, a, b);
            }
            Self::Or(a, b) => {
                update_hash_parts!(hasher => Or _, a, b);
            }
            Self::Coalesce(a, b) => {
                update_hash_parts!(hasher => Coalesce _, a, b);
            }
            Self::Equal(a, b) => {
                update_hash_parts!(hasher => Equal _, a, b);
            }
            Self::NotEqual(a, b) => {
                update_hash_parts!(hasher => NotEqual _, a, b);
            }
            Self::GreaterThan(a, b) => {
                update_hash_parts!(hasher => GreaterThan _, a, b);
            }
            Self::LessThan(a, b) => {
                update_hash_parts!(hasher => LessThan _, a, b);
            }
            Self::GreaterThanOrEqual(a, b) => {
                update_hash_parts!(hasher => GreaterThanOrEqual _, a, b);
            }
            Self::LessThanOrEqual(a, b) => {
                update_hash_parts!(hasher => LessThanOrEqual _, a, b);
            }
            Self::Dot(a, b) => {
                update_hash_parts!(hasher => Dot _, a, b);
            }
            Self::Not(e) => {
                update_hash_parts!(hasher => Not _, e);
            }
            Self::Is(e, is_some) => {
                update_hash_parts!(hasher => Is _, e, is_some);
            }
            Self::Block(statements, e) => {
                update_hash_parts!(hasher => Block _, statements, e);
            }
            Self::Substruct(e, ident) => {
                update_hash_parts!(hasher => Substruct _, e, ident);
            }
            Self::Cast(e, ident) => {
                update_hash_parts!(hasher => Cast _, e, ident);
            }
            Self::Match(e) => {
                update_hash_parts!(hasher => Match _, e);
            }
            Self::Ok(e) => {
                update_hash_parts!(hasher => Ok _, e);
            }
            Self::Err(e) => {
                update_hash_parts!(hasher => Err _, e);
            }
        }
    }
}

// Added implementations for statement types
impl AstHash for LetStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => LetStatement _, self.identifier, self.expression);
    }
}

impl AstHash for CheckStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => CheckStatement _, self.expression, self.else_expression);
    }
}

impl AstHash for MatchStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => MatchStatement _, self.expression, self.arms);
    }
}

impl AstHash for IfStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => IfStatement _, self.branches, self.fallback);
    }
}

impl AstHash for MapStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => MapStatement _, self.fact, self.identifier, self.statements);
    }
}

impl AstHash for CreateStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => CreateStatement _, self.fact);
    }
}

impl AstHash for UpdateStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => UpdateStatement _, self.fact, self.to);
    }
}

impl AstHash for DeleteStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => DeleteStatement _, self.fact);
    }
}

impl AstHash for ReturnStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => ReturnStatement _, self.expression);
    }
}

impl AstHash for MatchPattern {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Default(_) => {
                hasher.update(b"Default");
            }
            Self::Values(values) => {
                update_hash_parts!(hasher => Values _, values);
            }
        }
    }
}

impl AstHash for MatchArm {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => MatchArm _, self.pattern, self.statements);
    }
}

impl AstHash for MatchExpression {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => MatchExpression _, self.scrutinee, self.arms);
    }
}

impl AstHash for MatchExpressionArm {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => MatchExpressionArm _, self.pattern, self.expression);
    }
}

impl AstHash for StmtKind {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Let(let_stmt) => let_stmt.ast_hash(hasher),
            Self::Check(check_stmt) => check_stmt.ast_hash(hasher),
            Self::Match(match_stmt) => match_stmt.ast_hash(hasher),
            Self::If(if_stmt) => if_stmt.ast_hash(hasher),
            Self::Finish(statements) => statements.ast_hash(hasher),
            Self::Map(map_stmt) => map_stmt.ast_hash(hasher),
            Self::Return(return_stmt) => return_stmt.ast_hash(hasher),
            Self::ActionCall(func_call) => {
                update_hash_parts!(hasher => ActionCall func_call.identifier, func_call.arguments);
            }
            Self::Publish(expr) => {
                update_hash_parts!(hasher => Publish _, expr);
            }
            Self::Create(create_stmt) => create_stmt.ast_hash(hasher),
            Self::Update(update_stmt) => update_stmt.ast_hash(hasher),
            Self::Delete(delete_stmt) => delete_stmt.ast_hash(hasher),
            Self::Emit(expr) => {
                update_hash_parts!(hasher => Emit _, expr);
            }
            Self::FunctionCall(func_call) => {
                update_hash_parts!(hasher => FunctionCall func_call.identifier, func_call.arguments);
            }
            Self::DebugAssert(expr) => {
                update_hash_parts!(hasher => DebugAssert _, expr);
            }
            Self::Recall(recall_call) => recall_call.ast_hash(hasher),
        }
    }
}

impl AstHash for TypeKind {
    fn ast_hash(&self, hasher: &mut impl Update) {
        self.to_string().ast_hash(hasher);
    }
}

impl AstHash for FieldDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FieldDefinition self.identifier, self.field_type);
    }
}

impl AstHash for FactDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FactDefinition self.identifier, self.immutable, self.key, self.value);
    }
}

impl AstHash for Persistence {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Persistent => hasher.update(b"persistent"),
            Self::Ephemeral(_) => hasher.update(b"ephemeral"),
        }
    }
}

impl AstHash for ActionDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => ActionDefinition self.identifier, self.persistence, self.arguments, self.return_type, self.statements);
    }
}

impl AstHash for EffectFieldDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => EffectFieldDefinition self.identifier, self.field_type, self.dynamic);
    }
}

impl AstHash for EffectDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => EffectDefinition self.identifier, self.items);
    }
}

impl<T: AstHash> AstHash for StructItem<T> {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            Self::Field(v) => v.ast_hash(hasher),
            Self::StructRef(ident) => {
                update_hash_parts!(hasher => StructRef ident);
            }
        }
    }
}

impl AstHash for StructDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => StructDefinition self.identifier, self.items);
    }
}

impl AstHash for EnumDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => EnumDefinition self.identifier, self.variants);
    }
}

impl AstHash for RecallBlockDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => RecallBlockDefinition self.identifier, self.arguments, self.statements);
    }
}

impl AstHash for CommandDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => CommandDefinition self.identifier, self.persistence, self.attributes, self.fields, self.seal, self.open, self.policy, self.recalls);
    }
}

impl AstHash for FunctionDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FunctionDefinition self.identifier, self.arguments, self.return_type, self.statements);
    }
}

impl AstHash for FinishFunctionDefinition {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => FinishFunctionDefinition self.identifier, self.arguments, self.statements);
    }
}

impl AstHash for GlobalLetStatement {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => GlobalLetStatement self.identifier, self.expression);
    }
}

impl AstHash for Version {
    fn ast_hash(&self, hasher: &mut impl Update) {
        match self {
            #[allow(deprecated)]
            Self::V1 => hasher.update(&[0x01]),
            Self::V2 => hasher.update(&[0x02]),
        }
    }
}

impl AstHash for Policy {
    fn ast_hash(&self, hasher: &mut impl Update) {
        update_hash_parts!(hasher => Policy _,
            self.version,
            self.ffi_imports,
            self.facts,
            self.actions,
            self.effects,
            self.structs,
            self.enums,
            self.commands,
            self.functions,
            self.finish_functions,
            self.global_lets
        );
    }
}
