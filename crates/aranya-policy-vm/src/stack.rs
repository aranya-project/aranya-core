use aranya_policy_module::{TryAsMut, TryFromValue, Value, ValueConversionError};

use crate::error::MachineErrorType;

/// A stack data structure.
pub trait Stack {
    /// Push a value (as a [Value]) onto the stack.
    fn push_value(&mut self, value: Value) -> Result<(), MachineErrorType>;

    /// Pop a value (as a [Value]) from the stack.
    fn pop_value(&mut self) -> Result<Value, MachineErrorType>;

    /// Peek a value (as a mutable reference to a [Value]) on the top
    /// of the stack.
    fn peek_value(&mut self) -> Result<&mut Value, MachineErrorType>;

    /// Push a value onto the stack.
    fn push<V>(&mut self, value: V) -> Result<(), MachineErrorType>
    where
        V: Into<Value>,
    {
        self.push_value(value.into())
    }

    /// Pop a value off of the stack.
    fn pop<V>(&mut self) -> Result<V, MachineErrorType>
    where
        V: TryFromValue,
    {
        let raw = self.pop_value()?;
        Ok(TryFromValue::try_from_value(raw)?)
    }

    /// Get a reference to the value at the top of the stack
    fn peek<V>(&mut self) -> Result<&mut V, MachineErrorType>
    where
        V: ?Sized,
        Value: TryAsMut<V, Error = ValueConversionError>,
    {
        let raw = self.peek_value()?;
        Ok(raw.try_as_mut()?)
    }
}
