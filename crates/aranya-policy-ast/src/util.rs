use crate::{ExprKind, Expression, FactDefinition, FieldDefinition, Identifier, TypeKind};

impl FactDefinition {
    /// Get a key field by name
    pub fn get_key_field(&self, name: &Identifier) -> Option<&FieldDefinition> {
        self.key.iter().find(|fd| fd.identifier == *name)
    }

    /// Get a value field by name
    pub fn get_value_field(&self, name: &Identifier) -> Option<&FieldDefinition> {
        self.value.iter().find(|fd| fd.identifier == *name)
    }
}

impl FieldDefinition {
    /// Is this a hashable type?
    pub fn is_hashable(&self) -> bool {
        matches!(
            &self.field_type.kind,
            TypeKind::Int | TypeKind::Bool | TypeKind::String | TypeKind::Id | TypeKind::Enum(_)
        )
    }
}

impl Expression {
    /// Is this a literal expression?
    pub fn is_literal(&self) -> bool {
        match &self.kind {
            ExprKind::Int(_)
            | ExprKind::String(_)
            | ExprKind::Bool(_)
            | ExprKind::EnumReference(_) => true,
            ExprKind::Optional(o) => match o {
                Some(e) => e.is_literal(),
                None => true,
            },
            ExprKind::NamedStruct(s) => s.fields.iter().all(|(_, e)| e.is_literal()),
            _ => false,
        }
    }
}
