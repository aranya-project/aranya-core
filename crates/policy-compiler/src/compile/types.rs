use std::{
    borrow::Cow,
    collections::{hash_map, HashMap},
    fmt::Display,
};

use ast::{Expression, VType};
use buggy::bug;
use policy_ast as ast;

use crate::{compile::CompileState, CompileErrorType};

/// Describes the nature of a type error
#[derive(Debug, PartialEq)]
pub struct TypeError(Cow<'static, str>);

impl TypeError {
    fn new(msg: &'static str) -> TypeError {
        TypeError(Cow::from(msg))
    }

    fn new_owned(msg: String) -> TypeError {
        TypeError(Cow::from(msg))
    }
}

impl Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Type Error: {}", self.0)
    }
}

impl From<TypeError> for CompileErrorType {
    fn from(value: TypeError) -> Self {
        CompileErrorType::InvalidType(value.0.into_owned())
    }
}

/// Holds a stack of identifier-type mappings. Lookups traverse down the stack. The "current
/// scope" is the one on the top of the stack.
#[derive(Debug)]
pub struct IdentifierTypeStack {
    stack: Vec<HashMap<String, Typeish>>,
}

impl IdentifierTypeStack {
    /// Create a new `IdentifierTypeStack`
    pub fn new() -> Self {
        Self {
            stack: vec![HashMap::new()],
        }
    }

    /// Add an identifier-type mapping to the current scope
    pub fn add<S>(&mut self, name: S, value: Typeish) -> Result<(), CompileErrorType>
    where
        S: Into<String>,
    {
        let Some(map) = self.stack.last_mut() else {
            bug!("identifier stack empty");
        };
        match map.entry(name.into()) {
            hash_map::Entry::Occupied(o) => Err(CompileErrorType::AlreadyDefined(o.key().into())),
            hash_map::Entry::Vacant(e) => {
                e.insert(value);
                Ok(())
            }
        }
    }

    /// Retrieve a type for an identifier. Searches lower stack items if a mapping is not
    /// found in the current scope.
    pub fn get(&self, name: &str) -> Result<Typeish, CompileErrorType> {
        for scope in self.stack.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Ok(v.clone());
            }
        }
        Err(CompileErrorType::NotDefined(name.to_string()))
    }

    /// Push a new, empty scope on top of the type stack.
    pub fn push_scope(&mut self) {
        self.stack.push(HashMap::new())
    }

    /// Pop the current scope off of the type stack. It is a fatal error to pop an empty
    /// stack, as this indicates a mistake in the compiler.
    pub fn pop_scope(&mut self) {
        self.stack.pop().expect("empty type stack");
    }
}

/// This is a calculated type, which may be indeterminate if we don't have all the
/// information we need to calculate it.
///
/// [`PartialEq`] and [`Eq`] are intentionally not derived, as naive equality doesn't make
/// sense here. Use [`is_equal()`](Typeish::is_equal),
/// [`is_indeterminate()`](Typeish::is_indeterminate), and
/// [`is_maybe()`](Typeish::is_indeterminate).
//
// TODO(chip): This _should_
// eventually go away as every expression should be well-defined by the language. But we're
// not there yet.
#[derive(Debug, Clone)]
pub enum Typeish {
    Type(VType),
    Indeterminate,
}

impl Typeish {
    /// If `self` is `Type(x)`, map `x` to `y` via `f()`
    fn map_vtype<F>(self, f: F) -> Typeish
    where
        F: Fn(VType) -> VType,
    {
        match self {
            Self::Type(t) => Self::Type(f(t)),
            x => x,
        }
    }

    /// If `self` is `Type(x)`, map `x` to `y` as a Result via `f()`
    fn map_result<F>(self, f: F) -> Result<Typeish, TypeError>
    where
        F: Fn(VType) -> Result<Typeish, TypeError>,
    {
        match self {
            Self::Type(t) => f(t),
            x => Ok(x),
        }
    }

    /// Two Typeish's are equal if they're both definite types and are the same type
    pub fn is_equal(&self, ot: &Typeish) -> bool {
        match (self, ot) {
            (Self::Type(x), Self::Type(y)) => x == y,
            _ => false,
        }
    }

    /// True if the type is indeterminate
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate)
    }

    /// Is this an instance of this type or an Indeterminate value? Indeterminate types
    /// always match.
    pub fn is_maybe(&self, ot: &VType) -> bool {
        match self {
            Self::Type(t) => t == ot,
            _ => true,
        }
    }
}

impl Display for Typeish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Typeish::Type(t) => write!(f, "{t}"),
            Typeish::Indeterminate => write!(f, "indeterminate"),
        }
    }
}

impl CompileState<'_> {
    /// Construct a struct's type, or error if the struct is not defined.
    fn struct_type(&self, s: &ast::NamedStruct) -> Result<Typeish, TypeError> {
        if self.m.struct_defs.contains_key(&s.identifier) {
            Ok(Typeish::Type(VType::Struct(s.identifier.clone())))
        } else {
            Err(TypeError::new_owned(format!(
                "Struct `{}` not defined",
                s.identifier
            )))
        }
    }

    /// Construct the type of a query based on its fact argument, or error if the fact is
    /// not defined.
    fn query_fact_type(&self, f: &ast::FactLiteral) -> Result<Typeish, TypeError> {
        if self.m.fact_defs.contains_key(&f.identifier) {
            Ok(Typeish::Type(VType::Struct(f.identifier.clone())))
        } else {
            Err(TypeError::new_owned(format!(
                "Fact `{}` not defined",
                f.identifier
            )))
        }
    }

    /// If two types are defined, and are the same, the result is that type. If they are
    /// different, it is a type error. If either type is indeterminate, the type is
    /// indeterminate.
    fn unify_pair(&self, left: &Expression, right: &Expression) -> Result<Typeish, TypeError> {
        let left_type = self.calculate_expression_type(left)?;
        let right_type = self.calculate_expression_type(right)?;
        if left_type.is_equal(&right_type) {
            Ok(left_type)
        } else if left_type.is_indeterminate() || right_type.is_indeterminate() {
            Ok(Typeish::Indeterminate)
        } else {
            Err(TypeError::new_owned(format!(
                "types do not match: {left_type} and {right_type}"
            )))
        }
    }

    /// Attempt to determine the type of an expression
    pub fn calculate_expression_type(&self, expression: &Expression) -> Result<Typeish, TypeError> {
        match expression {
            Expression::Int(_) => Ok(Typeish::Type(VType::Int)),
            Expression::String(_) => Ok(Typeish::Type(VType::String)),
            Expression::Bool(_) => Ok(Typeish::Type(VType::Bool)),
            Expression::Optional(t) => match t {
                Some(t) => {
                    let inner_type = self.calculate_expression_type(t)?;
                    Ok(inner_type.map_vtype(|v| VType::Optional(Box::new(v))))
                }
                None => Ok(Typeish::Indeterminate),
            },
            Expression::NamedStruct(s) => self.struct_type(s),
            Expression::InternalFunction(f) => match f {
                ast::InternalFunction::Query(f) => Ok(self
                    .query_fact_type(f)?
                    .map_vtype(|t| VType::Optional(Box::new(t)))),
                ast::InternalFunction::Exists(_) => Ok(Typeish::Type(VType::Bool)),
                ast::InternalFunction::If(c, t, f) => {
                    let condition_type = self.calculate_expression_type(c)?;
                    if !condition_type.is_maybe(&VType::Bool) {
                        return Err(TypeError::new("if condition must be a boolean expression"));
                    }
                    // The type of `if` is whatever the subexpressions
                    // are, as long as they are the same type
                    self.unify_pair(t, f)
                }
                ast::InternalFunction::Serialize(_) => {
                    // TODO(chip): Use information about which command
                    // we're in to throw an error when this is used on a
                    // struct that is not the current command struct
                    Ok(Typeish::Type(VType::Bytes))
                }
                ast::InternalFunction::Deserialize(_) => {
                    // TODO(chip): Use information about which command
                    // we're in to determine this concretely
                    Ok(Typeish::Indeterminate)
                }
                policy_ast::InternalFunction::CountUpTo(_, _) => Ok(Typeish::Type(VType::Int)),
            },
            Expression::FunctionCall(f) => {
                if let Some(func_def) = self.function_signatures.get(f.identifier.as_str()) {
                    match &func_def.color {
                        super::FunctionColor::Pure(t) => Ok(Typeish::Type(t.clone())),
                        super::FunctionColor::Finish => Err(TypeError::new("Finish functions are not allowed outside of finish blocks or finish functions")),
                    }
                } else {
                    Err(TypeError::new_owned(format!(
                        "Function `{}` not defined",
                        f.identifier
                    )))
                }
            }
            Expression::ForeignFunctionCall(f) => {
                let module = self
                    .ffi_modules
                    .iter()
                    .find(|m| m.name == f.module)
                    .ok_or_else(|| {
                        TypeError::new_owned(format!("Module `{}` not found", f.module))
                    })?;
                let ffi_def = module.functions.iter().find(|mf| mf.name == f.identifier);
                if let Some(ffi_def) = ffi_def {
                    Ok(Typeish::Type(VType::from(&ffi_def.return_type)))
                } else {
                    Err(TypeError::new_owned(format!(
                        "Foreign function `{}::{}` not defined",
                        module.name, f.identifier
                    )))
                }
            }
            Expression::Identifier(i) => {
                let t = self
                    .identifier_types
                    .get(i)
                    .map_err(|_| TypeError::new_owned(format!("Unknown identifier `{}`", i)))?;
                Ok(t)
            }
            Expression::Add(left, right) | Expression::Subtract(left, right) => {
                let inner_type = self.unify_pair(left, right)?;
                inner_type.map_result(|t| {
                    if t != VType::Int {
                        Err(TypeError::new("Cannot do math on non-int types"))
                    } else {
                        Ok(Typeish::Type(t))
                    }
                })
            }
            Expression::And(left, right) | Expression::Or(left, right) => {
                let inner_type = self.unify_pair(left, right)?;
                inner_type.map_result(|t| {
                    if t != VType::Bool {
                        Err(TypeError::new(
                            "Cannot use boolean operator on non-bool types",
                        ))
                    } else {
                        Ok(Typeish::Type(t))
                    }
                })
            }
            Expression::Dot(e, field) => {
                let inner_type = self.calculate_expression_type(e)?;
                inner_type.map_result(|t| {
                    let VType::Struct(name) = &t else {
                        return Err(TypeError::new("Expression left of `.` is not a struct"));
                    };
                    let Some(struct_def) = self.m.struct_defs.get(name) else {
                        return Err(TypeError::new_owned(format!(
                            "Struct `{}` not defined",
                            name
                        )));
                    };
                    match struct_def.iter().find(|f| &f.identifier == field) {
                        Some(field_def) => Ok(Typeish::Type(field_def.field_type.clone())),
                        None => Err(TypeError::new_owned(format!(
                            "Struct `{}` has no member `{}`",
                            name, field
                        ))),
                    }
                })
            }
            Expression::Equal(left, right) | Expression::NotEqual(left, right) => {
                // We don't actually care what types the subexpressions
                // are as long as they can be tested for equality.
                let _ = self.unify_pair(left, right)?;
                Ok(Typeish::Type(VType::Bool))
            }
            Expression::GreaterThan(left, right)
            | Expression::LessThan(left, right)
            | Expression::GreaterThanOrEqual(left, right)
            | Expression::LessThanOrEqual(left, right) => {
                let inner_type = self.unify_pair(left, right)?;
                inner_type.map_result(|t| {
                    if t != VType::Int {
                        Err(TypeError::new("Cannot compare non-int expressions"))
                    } else {
                        Ok(Typeish::Type(VType::Bool))
                    }
                })
            }
            Expression::Negative(e) => {
                let inner_type = self.calculate_expression_type(e)?;
                inner_type.map_result(|t| {
                    if t != VType::Int {
                        Err(TypeError::new("Cannot negate non-int expression"))
                    } else {
                        Ok(Typeish::Type(t))
                    }
                })
            }
            Expression::Not(e) => {
                let inner_type = self.calculate_expression_type(e)?;
                inner_type.map_result(|t| {
                    if t != VType::Bool {
                        Err(TypeError::new("Cannot invert non-boolean expression"))
                    } else {
                        Ok(Typeish::Type(t))
                    }
                })
            }
            Expression::Unwrap(e) | Expression::CheckUnwrap(e) => {
                let inner_type = self.calculate_expression_type(e)?;
                inner_type.map_result(|t| {
                    if let VType::Optional(t) = t {
                        Ok(Typeish::Type(*t))
                    } else {
                        Err(TypeError::new("Cannot unwrap non-option expression"))
                    }
                })
            }
            Expression::Is(a, _) => {
                let inner_type = self.calculate_expression_type(a)?;
                inner_type.map_result(|t| {
                    if let VType::Optional(_) = t {
                        Ok(Typeish::Type(VType::Bool))
                    } else {
                        Err(TypeError::new(
                            "`is` must operate on an optional expression`",
                        ))
                    }
                })
            }
            Expression::EnumReference(e) => Ok(Typeish::Type(VType::Enum(e.identifier.clone()))),
        }
    }
}
