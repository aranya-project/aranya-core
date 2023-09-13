use crate::machine::{MachineErrorType, TryAsMut, Value};

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
        V: TryFrom<Value, Error = MachineErrorType>,
    {
        self.pop_value().and_then(|v| v.try_into())
    }

    /// Get a reference to the value at the top of the stack
    fn peek<V>(&mut self) -> Result<&mut V, MachineErrorType>
    where
        V: ?Sized,
        Value: TryAsMut<V, Error = MachineErrorType>,
    {
        self.peek_value().and_then(|v| v.try_as_mut())
    }
}
