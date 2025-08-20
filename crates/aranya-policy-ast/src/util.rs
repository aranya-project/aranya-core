use crate::{Expression, FactDefinition, FieldDefinition, Identifier, VType};

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
            self.field_type,
            VType::Int | VType::Bool | VType::String | VType::Id | VType::Enum(_)
        )
    }
}

impl Expression {
    /// Is this a literal expression?
    pub fn is_literal(&self) -> bool {
        match self {
            Self::Int(_) | Self::String(_) | Self::Bool(_) | Self::EnumReference(_) => true,
            Self::Optional(o) => o.as_ref().is_none_or(|e| e.is_literal()),
            Self::NamedStruct(s) => s.fields.iter().all(|(_, e)| e.is_literal()),
            _ => false,
        }
    }
}
