//! Things which are referred to by name in policy code and thus in errors.

use core::fmt;

use aranya_policy_ast::{Ident, Span, WithSpanExt as _, ident};

#[derive(Clone, Debug)]
pub enum Reference {
    Callable(Callable),
    Param(Callable, Ident),
    Flavor(Ident),
    Base(Ident),
    Command(Ident),
    CommandAttribute(Ident, Ident),
    Struct(Ident),
    Effect(Ident),
    StructField(Ident, Ident),
    Enum(Ident),
    EnumVariant(Ident, Ident),
    Variable(Ident),
    Fact(Ident),
    FactKey(Ident, Ident),
    FactValue(Ident, Ident),
    Module(Ident),
    FfiFunction(Ident, Ident),
    Global(Ident),
}

#[derive(Clone, Debug)]
pub(crate) enum Callable {
    Action(Ident),
    Function(Ident),
    FinishFunction(Ident),
    GetKey(Span),
    Policy(Span),
    Recall(Ident),
}

impl Reference {
    /// Get the name of the reference.
    ///
    /// This is the most specific part of the reference, such as the function name of an ffi call or
    /// the field name in a struct, regardless of the extra context contained.
    pub(crate) fn name(&self) -> Ident {
        match self {
            Self::Callable(callable) => callable.name(),
            Self::Param(_, name) => name.clone(),
            Self::Flavor(name)
            | Self::Base(name)
            | Self::Command(name)
            | Self::CommandAttribute(_, name)
            | Self::Struct(name)
            | Self::Effect(name)
            | Self::StructField(_, name)
            | Self::Enum(name)
            | Self::EnumVariant(_, name)
            | Self::Variable(name)
            | Self::Fact(name)
            | Self::FactKey(_, name)
            | Self::FactValue(_, name)
            | Self::Module(name)
            | Self::FfiFunction(_, name)
            | Self::Global(name) => name.clone(),
        }
    }

    /// Get the span of the most specific part of the reference.
    ///
    /// See [`Self::name`].
    pub(super) fn span(&self) -> Span {
        self.name().span
    }
}

impl Callable {
    fn name(&self) -> Ident {
        match self {
            Self::Action(name)
            | Self::Function(name)
            | Self::FinishFunction(name)
            | Self::Recall(name) => name.clone(),
            // A little funky but these names aren't currently used anyways.
            Self::GetKey(span) => ident!("get_key").at(*span),
            Self::Policy(span) => ident!("policy").at(*span),
        }
    }

    /// Create a [`Reference::Param`] of this callable.
    pub(crate) fn param(self, name: Ident) -> Reference {
        Reference::Param(self, name)
    }
}

impl From<Callable> for Reference {
    fn from(value: Callable) -> Self {
        Self::Callable(value)
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Callable(callable) => write!(f, "{callable}"),
            Self::Param(callable, param) => {
                write!(f, "param `{param}` of {callable}")
            }
            Self::Flavor(name) => write!(f, "flavor `{name}`"),
            Self::Base(name) => write!(f, "base command `{name}`"),
            Self::Command(name) => write!(f, "command `{name}`"),
            Self::CommandAttribute(cmd, name) => write!(f, "attribute `{name}` of command `{cmd}`"),
            Self::Struct(name) => write!(f, "struct `{name}`"),
            Self::Effect(name) => write!(f, "effect `{name}`"),
            Self::StructField(strukt, field) => {
                write!(f, "field `{field}` of struct `{strukt}`")
            }
            Self::Enum(name) => write!(f, "enum `{name}`"),
            Self::EnumVariant(enumeration, variant) => {
                write!(f, "variant `{variant}` of enum `{enumeration}`")
            }
            Self::Variable(name) => write!(f, "variable `{name}`"),
            Self::Fact(name) => write!(f, "fact `{name}`"),
            Self::FactKey(fact, key) => write!(f, "key field `{key}` of fact `{fact}`"),
            Self::FactValue(fact, value) => write!(f, "value field `{value}` fact `{fact}`"),
            Self::Module(name) => write!(f, "module `{name}`"),
            Self::FfiFunction(module, function) => {
                write!(f, "function `{function}` in module `{module}`")
            }
            Self::Global(name) => {
                write!(f, "global value `{name}`")
            }
        }
    }
}

impl fmt::Display for Callable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Action(name) => write!(f, "action `{name}`"),
            Self::Function(name) => write!(f, "function `{name}`"),
            Self::FinishFunction(name) => write!(f, "finish function `{name}`"),
            Self::GetKey(_) => write!(f, "get_key block"),
            Self::Policy(_) => write!(f, "policy block"),
            Self::Recall(name) => write!(f, "recall block `{name}`"),
        }
    }
}
