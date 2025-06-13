use aranya_crypto::Engine;
use aranya_policy_vm::{
    ffi::{self, FfiModule, ModuleSchema},
    ident, CommandContext, MachineError, MachineErrorType, Stack, Text, Value,
};

pub struct PrintFfi {}

impl FfiModule for PrintFfi {
    type Error = MachineError;

    const SCHEMA: ModuleSchema<'static> = ModuleSchema {
        name: ident!("print"),
        functions: &[ffi::Func {
            name: ident!("print"),
            args: &[ffi::Arg {
                name: ident!("s"),
                vtype: ffi::Type::String,
            }],
            return_type: ffi::Type::String,
        }],
        structs: &[],
        enums: &[],
    };

    fn call<E: Engine>(
        &self,
        procedure: usize,
        stack: &mut impl Stack,
        _ctx: &CommandContext,
        _eng: &mut E,
    ) -> Result<(), Self::Error> {
        match procedure {
            0 => {
                // pop args off the stack
                let s: Text = stack.pop()?;

                // Push something (the uppercased value) back onto the stack so the caller can verify this function was called.
                stack
                    .push(Value::String(
                        s.as_str().to_uppercase().try_into().expect("no nul"),
                    ))
                    .expect("can't push");

                Ok(())
            }
            _ => Err(MachineError::new(MachineErrorType::FfiProcedureNotDefined(
                Self::SCHEMA.name.clone(),
                procedure,
            ))),
        }
    }
}
