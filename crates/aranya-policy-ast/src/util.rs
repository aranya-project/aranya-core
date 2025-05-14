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
    /// Is this a hashable type (int, bool, string, or id)?
    pub fn is_hashable(&self) -> bool {
        matches!(
            self.field_type,
            VType::Int | VType::Bool | VType::String | VType::Id
        )
    }
}

impl Expression {
    /// Is this a literal expression?
    pub fn is_literal(&self) -> bool {
        match self {
            Expression::Int(_)
            | Expression::String(_)
            | Expression::Bool(_)
            | Expression::EnumReference(_) => true,
            Expression::Optional(o) => match o {
                Some(e) => e.is_literal(),
                None => true,
            },
            Expression::NamedStruct(s) => s.fields.iter().all(|(_, e)| e.is_literal()),
            _ => false,
        }
    }
}
