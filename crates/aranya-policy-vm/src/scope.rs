use alloc::{collections::BTreeMap, string::ToString as _, vec, vec::Vec};

use aranya_policy_ast::Identifier;
use aranya_policy_module::ConstValue;

use crate::{MachineErrorType, Value};

/// Manages value assignment.
#[derive(Debug)]
pub struct ScopeManager<'a> {
    globals: &'a BTreeMap<Identifier, ConstValue>,
    locals: Vec<Vec<BTreeMap<Identifier, Value>>>,
}

impl<'a> ScopeManager<'a> {
    /// Create a new scope manager with the given global assignments.
    ///
    /// Globals are always reachable.
    pub fn new(globals: &'a BTreeMap<Identifier, ConstValue>) -> Self {
        Self {
            globals,
            locals: vec![vec![BTreeMap::new()]],
        }
    }

    /// Enter a new function scope.
    ///
    /// Previously defined locals will be unvailable until exiting the function.
    pub fn enter_function(&mut self) {
        self.locals.push(vec![BTreeMap::new()]);
    }

    /// Exit the current function scope.
    pub fn exit_function(&mut self) -> Result<(), MachineErrorType> {
        self.locals.pop().ok_or(MachineErrorType::BadState(
            "exit_function: empty function-scope stack",
        ))?;
        Ok(())
    }
    /// Enter a new block scope.
    ///
    /// Previously defined locals within the same function scope will be available.
    pub fn enter_block(&mut self) -> Result<(), MachineErrorType> {
        let locals = self.locals.last_mut().ok_or(MachineErrorType::BadState(
            "enter_block: empty function-scope stack",
        ))?;
        locals.push(BTreeMap::new());
        Ok(())
    }

    /// Exit the current block scope.
    pub fn exit_block(&mut self) -> Result<(), MachineErrorType> {
        let last = self.locals.last_mut().ok_or(MachineErrorType::BadState(
            "exit_block: empty function-scope stack",
        ))?;
        last.pop()
            .ok_or(MachineErrorType::BadState("exit_block: no block"))?;
        Ok(())
    }

    /// Look up an assignment by name.
    ///
    /// This will search all locals within the current function scope, and globals.
    pub fn get(&self, ident: &Identifier) -> Result<Value, MachineErrorType> {
        let key = ident.as_ref();
        if let Some(locals) = self.locals.last() {
            for scope in locals.iter().rev() {
                if let Some(v) = scope.get(key) {
                    return Ok(v.clone());
                }
            }
        }
        if let Some(v) = self.globals.get(key) {
            return Ok(v.clone().into());
        }
        Err(MachineErrorType::NotDefined(ident.to_string()))
    }

    /// Assign a name to a value within the current local scope.
    pub fn set(&mut self, ident: Identifier, value: Value) -> Result<(), MachineErrorType> {
        if self.globals.contains_key(ident.as_ref()) {
            return Err(MachineErrorType::AlreadyDefined(ident));
        }

        let locals = self
            .locals
            .last_mut()
            .ok_or(MachineErrorType::BadState("set: no local block"))?;
        for m in locals.iter() {
            if m.contains_key(ident.as_ref()) {
                return Err(MachineErrorType::AlreadyDefined(ident));
            }
        }

        let block = locals
            .last_mut()
            .ok_or(MachineErrorType::BadState("set: no locals"))?;
        block.insert(ident, value);

        Ok(())
    }

    /// Resets the scope manager to its initial value.
    pub fn clear(&mut self) {
        self.locals.clear();
        self.locals.push(vec![BTreeMap::new()]);
    }

    /// Returns an iterator of currently reachable local assignments.
    pub fn locals(&self) -> impl Iterator<Item = (&Identifier, &Value)> {
        self.locals.last().into_iter().flatten().rev().flatten()
    }
}

#[cfg(test)]
mod test {
    use aranya_policy_ast::ident;

    use super::*;

    #[test]
    fn test_scope() {
        let globals = BTreeMap::from([(ident!("g"), ConstValue::Int(42))]);
        let mut scope = ScopeManager::new(&globals);

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert_eq!(
            scope.set(ident!("g"), Value::NONE),
            Err(MachineErrorType::AlreadyDefined(ident!("g")))
        );

        scope.set(ident!("a1"), Value::Int(1)).unwrap();
        scope.set(ident!("a2"), Value::Int(2)).unwrap();

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert_eq!(scope.get(&ident!("a1")), Ok(Value::Int(1)));
        assert_eq!(scope.get(&ident!("a2")), Ok(Value::Int(2)));

        scope.enter_block().unwrap();
        scope.set(ident!("a3"), Value::Int(3)).unwrap();

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert_eq!(scope.get(&ident!("a1")), Ok(Value::Int(1)));
        assert_eq!(scope.get(&ident!("a2")), Ok(Value::Int(2)));
        assert_eq!(scope.get(&ident!("a3")), Ok(Value::Int(3)));

        assert!(scope.set(ident!("g"), Value::NONE).is_err());
        assert!(scope.set(ident!("a1"), Value::NONE).is_err());
        assert!(scope.set(ident!("a2"), Value::NONE).is_err());
        assert!(scope.set(ident!("a3"), Value::NONE).is_err());

        scope.enter_function();
        scope.set(ident!("b4"), Value::Int(4)).unwrap();

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert!(scope.get(&ident!("a1")).is_err());
        assert!(scope.get(&ident!("a2")).is_err());
        assert!(scope.get(&ident!("a3")).is_err());
        assert_eq!(scope.get(&ident!("b4")), Ok(Value::Int(4)));

        scope.enter_block().unwrap();
        scope.exit_function().unwrap();

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert_eq!(scope.get(&ident!("a1")), Ok(Value::Int(1)));
        assert_eq!(scope.get(&ident!("a2")), Ok(Value::Int(2)));
        assert_eq!(scope.get(&ident!("a3")), Ok(Value::Int(3)));
        assert!(scope.get(&ident!("b4")).is_err());

        scope.exit_function().unwrap();

        assert_eq!(scope.get(&ident!("g")), Ok(Value::Int(42)));
        assert!(scope.get(&ident!("a1")).is_err());
        assert!(scope.get(&ident!("a2")).is_err());
        assert!(scope.get(&ident!("a3")).is_err());
        assert!(scope.get(&ident!("b4")).is_err());
    }
}
