use crate::{
    lang::ast::VType,
    machine::{data::CommandContext, error::MachineError, stack::Stack},
};

/// A foreign function.
#[derive(Clone, Debug)]
pub struct Func<'a> {
    /// The function's name.
    pub name: &'a str,
    /// The function's arguments.
    pub args: &'a [Arg<'a>],
    /// The function's "color."
    pub color: Color,
}

/// An argument to a foreign function.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg<'a> {
    /// The argument's name.
    pub name: &'a str,
    /// The field's type.
    pub vtype: VType,
}

/// Describes the context in which the function can be called.
#[derive(Clone, Debug)]
pub enum Color {
    /// Function is valid outside of finish blocks, and returns
    /// a value.
    Pure(VType),
    /// Function is valid inside finish blocks, and does not
    /// return a value.
    Finish,
}

/// Foreign Function Interface to allow the policy VM to call external functions.
pub trait FfiModule<S>
where
    S: Stack,
{
    type Error: Into<MachineError>;

    /// Returns a list of function definitions. Used by the
    /// compiler to emit the stack instructions needed for
    /// a call.
    fn function_table(&self) -> &'static [Func<'static>];

    /// Invokes a function in the module.
    /// `procedure` is the index in [`function_table`][Self::function_table].
    fn call(
        &self,
        procedure: usize,
        stack: &mut S,
        ctx: Option<CommandContext>,
    ) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::error::MachineErrorType;

    /// Tests that static function tables can be used. See
    /// issue/290.
    #[test]
    fn test_const() {
        struct E;
        impl From<E> for MachineError {
            fn from(_err: E) -> Self {
                MachineError::new(MachineErrorType::Unknown)
            }
        }

        struct T;
        impl T {
            const TABLE: &[Func<'static>] = &[
                Func {
                    name: "a",
                    args: &[],
                    color: Color::Finish,
                },
                Func {
                    name: "b",
                    args: &[
                        Arg {
                            name: "one",
                            vtype: VType::Int,
                        },
                        Arg {
                            name: "two",
                            vtype: VType::ID,
                        },
                    ],
                    color: Color::Finish,
                },
            ];
        }
        impl<S: Stack> FfiModule<S> for T {
            type Error = E;

            fn function_table(&self) -> &'static [Func<'static>] {
                Self::TABLE
            }

            fn call(
                &self,
                proc: usize,
                _stack: &mut S,
                _ctx: Option<CommandContext>,
            ) -> Result<(), Self::Error> {
                let f = Self::TABLE.get(proc).ok_or(E)?;
                match f.name {
                    "a" | "b" => Ok(()),
                    _ => Err(E),
                }
            }
        }
    }
}
