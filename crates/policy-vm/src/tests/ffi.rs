use crypto::Engine;

use crate::{
    ffi::{self, FfiModule, ModuleSchema},
    CommandContext, MachineError, MachineErrorType, Stack, Value,
};

pub struct PrintFfi {}

impl FfiModule for PrintFfi {
    type Error = MachineError;

    const SCHEMA: ModuleSchema<'static> = ModuleSchema {
        name: "print",
        functions: &[ffi::Func {
            name: "print",
            args: &[ffi::Arg {
                name: "s",
                vtype: ffi::Type::String,
            }],
            return_type: ffi::Type::String,
        }],
    };

    fn call<E: Engine>(
        &mut self,
        procedure: usize,
        stack: &mut impl Stack,
        _ctx: &CommandContext<'_>,
        _eng: &mut E,
    ) -> Result<(), Self::Error> {
        match procedure {
            0 => {
                // pop args off the stack
                let s: String = stack.pop()?;

                // Push something (the uppercased value) back onto the stack so the caller can verify this function was called.
                stack
                    .push(Value::String(s.to_uppercase()))
                    .expect("can't push");

                Ok(())
            }
            _ => Err(MachineError::new(MachineErrorType::FfiProcedureNotDefined(
                Self::SCHEMA.name.to_string(),
                procedure,
            ))),
        }
    }
}
