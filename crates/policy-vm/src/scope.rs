extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};

use policy_module::Value;

use crate::MachineErrorType;

/// Manages value assignment.
#[derive(Debug)]
pub struct ScopeManager<'a> {
    globals: &'a BTreeMap<String, Value>,
    locals: Vec<Vec<BTreeMap<String, Value>>>,
}

impl<'a> ScopeManager<'a> {
    /// Create a new scope manager with the given global assignments.
    ///
    /// Globals are always reachable.
    pub fn new(globals: &'a BTreeMap<String, Value>) -> Self {
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

    /// Enter a new block scope.
    ///
    /// Previously defined locals within the same function scope will be available.
    pub fn enter_block(&mut self) -> Result<(), MachineErrorType> {
        let locals = self.locals.last_mut().ok_or(MachineErrorType::BadState)?;
        locals.push(BTreeMap::new());
        Ok(())
    }

    /// Exit the current function scope.
    pub fn exit_function(&mut self) -> Result<(), MachineErrorType> {
        self.locals.pop().ok_or(MachineErrorType::BadState)?;
        Ok(())
    }

    /// Exit the current block scope.
    pub fn exit_block(&mut self) -> Result<(), MachineErrorType> {
        let last = self.locals.last_mut().ok_or(MachineErrorType::BadState)?;
        last.pop().ok_or(MachineErrorType::BadState)?;
        Ok(())
    }

    /// Look up an assignment by name.
    ///
    /// This will search all locals within the current function scope, and globals.
    pub fn get(&self, ident: impl Into<String> + AsRef<str>) -> Result<Value, MachineErrorType> {
        let key = ident.as_ref();
        if let Some(locals) = self.locals.last() {
            for scope in locals.iter().rev() {
                if let Some(v) = scope.get(key) {
                    return Ok(v.clone());
                }
            }
        }
        if let Some(v) = self.globals.get(key) {
            return Ok(v.clone());
        }
        Err(MachineErrorType::NotDefined(ident.into()))
    }

    /// Assign a name to a value within the current local scope.
    pub fn set(
        &mut self,
        ident: impl Into<String> + AsRef<str>,
        value: Value,
    ) -> Result<(), MachineErrorType> {
        if self.globals.contains_key(ident.as_ref()) {
            return Err(MachineErrorType::AlreadyDefined(ident.into()));
        }

        let locals = self.locals.last_mut().ok_or(MachineErrorType::BadState)?;
        for m in locals.iter() {
            if m.contains_key(ident.as_ref()) {
                return Err(MachineErrorType::AlreadyDefined(ident.into()));
            }
        }

        let block = locals.last_mut().ok_or(MachineErrorType::BadState)?;
        block.insert(ident.into(), value);

        Ok(())
    }

    /// Resets the scope manager to its initial value.
    pub fn clear(&mut self) {
        self.locals.clear();
        self.locals.push(vec![BTreeMap::new()]);
    }

    /// Returns an iterator of currently reachable local assignments.
    pub fn locals(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.locals
            .last()
            .into_iter()
            .flatten()
            .rev()
            .flatten()
            .map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_scope() {
        let globals = BTreeMap::from([(String::from("g"), Value::Int(42))]);
        let mut scope = ScopeManager::new(&globals);

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert_eq!(
            scope.set("g", Value::None),
            Err(MachineErrorType::AlreadyDefined("g".into()))
        );

        scope.set("a1", Value::Int(1)).unwrap();
        scope.set("a2", Value::Int(2)).unwrap();

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert_eq!(scope.get("a1"), Ok(Value::Int(1)));
        assert_eq!(scope.get("a2"), Ok(Value::Int(2)));

        scope.enter_block().unwrap();
        scope.set("a3", Value::Int(3)).unwrap();

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert_eq!(scope.get("a1"), Ok(Value::Int(1)));
        assert_eq!(scope.get("a2"), Ok(Value::Int(2)));
        assert_eq!(scope.get("a3"), Ok(Value::Int(3)));

        assert!(scope.set("g", Value::None).is_err());
        assert!(scope.set("a1", Value::None).is_err());
        assert!(scope.set("a2", Value::None).is_err());
        assert!(scope.set("a3", Value::None).is_err());

        scope.enter_function();
        scope.set("b4", Value::Int(4)).unwrap();

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert!(scope.get("a1").is_err());
        assert!(scope.get("a2").is_err());
        assert!(scope.get("a3").is_err());
        assert_eq!(scope.get("b4"), Ok(Value::Int(4)));

        scope.enter_block().unwrap();
        scope.exit_function().unwrap();

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert_eq!(scope.get("a1"), Ok(Value::Int(1)));
        assert_eq!(scope.get("a2"), Ok(Value::Int(2)));
        assert_eq!(scope.get("a3"), Ok(Value::Int(3)));
        assert!(scope.get("b4").is_err());

        scope.exit_function().unwrap();

        assert_eq!(scope.get("g"), Ok(Value::Int(42)));
        assert!(scope.get("a1").is_err());
        assert!(scope.get("a2").is_err());
        assert!(scope.get("a3").is_err());
        assert!(scope.get("b4").is_err());
    }
}
