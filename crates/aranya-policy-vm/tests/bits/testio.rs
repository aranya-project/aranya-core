use std::{
    cell::RefCell,
    collections::{BTreeMap, btree_map},
    fmt,
    ops::DerefMut,
};

use aranya_crypto::{
    Id, Rng,
    default::{DefaultCipherSuite, DefaultEngine},
};
use aranya_policy_ast::Identifier;
use aranya_policy_vm::{
    CommandContext, FactKey, FactKeyList, FactValue, FactValueList, KVPair, MachineError,
    MachineErrorType, MachineIO, MachineIOError, Stack,
    ffi::{FfiModule, ModuleSchema},
};

use super::printffi::*;

pub struct TestIO {
    pub facts: BTreeMap<(Identifier, FactKeyList), FactValueList>,
    pub effect_stack: Vec<(Identifier, Vec<KVPair>)>,
    pub engine: RefCell<DefaultEngine<Rng, DefaultCipherSuite>>,
    pub print_ffi: PrintFfi,
}

impl fmt::Debug for TestIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let module_names = ["print"];
        f.debug_struct("TestIO")
            .field("facts", &self.facts)
            .field("effect_stack", &self.effect_stack)
            .field("modules", &module_names)
            .finish()
    }
}

impl TestIO {
    pub fn new() -> Self {
        let (engine, _) = DefaultEngine::from_entropy(Rng);
        TestIO {
            facts: BTreeMap::new(),
            effect_stack: vec![],
            engine: RefCell::new(engine),
            print_ffi: PrintFfi {},
        }
    }

    /// List of schemas for the FFI modules provided by this MachineIO implementation.
    pub const FFI_SCHEMAS: &'static [ModuleSchema<'static>] = &[PrintFfi::SCHEMA];
}

/// Calculates whether the k/v pairs in a exist in b
fn prefix_key_match(fact: &[FactKey], query: &[FactKey]) -> bool {
    fact.starts_with(query)
}

impl<S> MachineIO<S> for TestIO
where
    S: Stack,
{
    type QueryIterator =
        Box<dyn Iterator<Item = Result<(FactKeyList, FactValueList), MachineIOError>>>;

    fn fact_insert(
        &mut self,
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
        value: impl IntoIterator<Item = FactValue>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        let value: Vec<_> = value.into_iter().collect();
        println!("fact insert {}[{:?}]=>{{{:?}}}", name, key, value);
        match self.facts.entry((name, key)) {
            btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            btree_map::Entry::Occupied(_) => Err(MachineIOError::FactExists),
        }
    }

    fn fact_delete(
        &mut self,
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<(), MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("fact delete {}[{:?}]", name, key);
        match self.facts.entry((name, key)) {
            btree_map::Entry::Vacant(_) => Err(MachineIOError::FactNotFound),
            btree_map::Entry::Occupied(entry) => {
                entry.remove();
                Ok(())
            }
        }
    }

    fn fact_query(
        &self,
        name: Identifier,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("query {}[{:?}]", name, key);
        let iter = self
            .facts
            .clone()
            .into_iter()
            .filter(move |f| f.0.0 == name && prefix_key_match(&f.0.1, &key))
            .map(|((_, k), v)| Ok::<(FactKeyList, FactValueList), MachineIOError>((k, v)));

        Ok(Box::new(iter))
    }

    fn effect(
        &mut self,
        name: Identifier,
        fields: impl IntoIterator<Item = KVPair>,
        _command: Id,
        _recalled: bool,
    ) {
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort_by(|a, b| a.key().cmp(b.key()));
        println!("effect {} {{{:?}}}", name, fields);
        self.effect_stack.push((name, fields));
    }

    fn call(
        &self,
        module: usize,
        procedure: usize,
        stack: &mut S,
        ctx: &CommandContext,
    ) -> Result<(), MachineError> {
        match module {
            0 => {
                let mut engine = self.engine.borrow_mut();
                self.print_ffi
                    .call(procedure, stack, ctx, engine.deref_mut())
            }
            _ => Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
                module,
            ))),
        }
    }
}
