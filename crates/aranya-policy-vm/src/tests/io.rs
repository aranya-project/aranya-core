extern crate alloc;
use alloc::collections::{btree_map, BTreeMap};
use core::fmt;

use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Id, Rng,
};

use super::ffi::*;
use crate::{
    ffi::FfiModule, CommandContext, FactKey, FactKeyList, FactValue, FactValueList, KVPair,
    MachineError, MachineErrorType, MachineIO, MachineIOError, Stack,
};

pub struct TestIO {
    pub facts: BTreeMap<(String, FactKeyList), FactValueList>,
    pub publish_stack: Vec<(String, Vec<KVPair>)>,
    pub effect_stack: Vec<(String, Vec<KVPair>)>,
    pub engine: DefaultEngine<Rng, DefaultCipherSuite>,
    pub print_ffi: PrintFfi,
}

impl fmt::Debug for TestIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let module_names = ["print"];
        f.debug_struct("TestIO")
            .field("facts", &self.facts)
            .field("publish_stack", &self.publish_stack)
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
            publish_stack: vec![],
            effect_stack: vec![],
            engine,
            print_ffi: PrintFfi {},
        }
    }
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
        name: String,
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
        name: String,
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
        name: String,
        key: impl IntoIterator<Item = FactKey>,
    ) -> Result<Self::QueryIterator, MachineIOError> {
        let key: Vec<_> = key.into_iter().collect();
        println!("query {}[{:?}]", name, key);
        let iter = self
            .facts
            .clone()
            .into_iter()
            .filter(move |f| f.0 .0 == name && prefix_key_match(&f.0 .1, &key))
            .map(|((_, k), v)| Ok::<(FactKeyList, FactValueList), MachineIOError>((k, v)));

        Ok(Box::new(iter))
    }

    fn publish(&mut self, name: String, fields: impl IntoIterator<Item = KVPair>) {
        let mut fields: Vec<_> = fields.into_iter().collect();
        fields.sort_by(|a, b| a.key().cmp(b.key()));
        println!("publish {} {{{:?}}}", name, fields);
        self.publish_stack.push((name, fields));
    }

    fn effect(
        &mut self,
        name: String,
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
        &mut self,
        module: usize,
        procedure: usize,
        stack: &mut S,
        ctx: &CommandContext<'_>,
    ) -> Result<(), MachineError> {
        match module {
            0 => self.print_ffi.call(procedure, stack, ctx, &mut self.engine),
            _ => Err(MachineError::new(MachineErrorType::FfiModuleNotDefined(
                module,
            ))),
        }
    }
}
