//! Contains [`TopoSort`] which can be used to sort values topologically.
//!
//! It's used to find the order for compiling type definitions, and to
//! detect recursive calls.
//!
//! A [`CycleError`] will be returned when values cannot be sorted topologically.
use std::{collections::HashMap, fmt::Display};

use aranya_policy_ast::Ident;
use petgraph::{
    algo::TarjanScc,
    graphmap::{DiGraphMap, NodeTrait},
};

use crate::compile::{error::CyclicTypeDefinitions, types::UserType};

/// Indicates that a cycle was found while sorting values.
#[derive(Debug)]
pub struct CycleError(Vec<Vec<String>>);

impl CycleError {
    // This is messy. It'd be better to create a TopoSort<&Ident> but it's tricky to create references that live long enough
    // for structs defined in FFI modules.
    pub(super) fn into_compile_error(
        self,
        ctx: &HashMap<Ident, UserType<'_>>,
    ) -> CyclicTypeDefinitions {
        let note = self.to_string();
        let idents = self
            .0
            .into_iter()
            .map(|strings| {
                strings
                    .into_iter()
                    .filter_map(|s| ctx.get_key_value(s.as_str()))
                    .map(|(ident, _)| ident.clone())
                    .collect()
            })
            .collect();

        CyclicTypeDefinitions(note, idents)
    }
}

impl Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This outputs a comma separated list of the nodes in each cycle/SCC.
        // A direct path is not shown.
        let cycles: Vec<_> = self
            .0
            .iter()
            .map(|cycle| format!("[{}]", cycle.as_slice().join(", ")))
            .collect();
        write!(
            f,
            "Found cyclic dependencies when compiling structs:\n- {}",
            cycles.join("\n- ")
        )
    }
}

/// A directed graph that can be topologically sorted.
pub(in crate::compile) struct TopoSort<T>(DiGraphMap<T, ()>);

impl<T: NodeTrait + Display> TopoSort<T> {
    /// Creates a new empty graph.
    pub(crate) fn new() -> Self {
        Self(DiGraphMap::new())
    }

    /// Inserts a node with its dependencies.
    ///
    /// If the node already exists, its dependencies are replaced.
    pub(crate) fn insert(&mut self, node: T, deps: impl IntoIterator<Item = T>) {
        self.0.extend(deps.into_iter().map(|dep| (node, dep)));
        self.0.add_node(node);
    }

    /// Consumes the graph and returns nodes in topological order.
    pub(crate) fn sort(self) -> Result<Vec<T>, CycleError> {
        let (topo, cycles) = self.partition();

        if !cycles.is_empty() {
            let cycles = cycles
                .into_iter()
                .map(|cycle| cycle.iter().map(ToString::to_string).collect())
                .collect();
            return Err(CycleError(cycles));
        }

        Ok(topo)
    }

    /// Returns every cycle in the graph, without sorting.
    pub(crate) fn cycles(&self) -> Vec<Vec<T>> {
        self.partition().1
    }

    /// Splits the nodes into those that are in topological order, and the cycles.
    // Uses strongly connected components (SSC) to determine cycles in a directed graph.
    fn partition(&self) -> (Vec<T>, Vec<Vec<T>>) {
        let mut cycles = Vec::new();
        let mut topo = Vec::new();

        TarjanScc::new().run(&self.0, |group| match group {
            // A strongly connected component (SSC) of a single vertex and it's not a self-loop.
            &[lone] if !self.0.contains_edge(lone, lone) => topo.push(lone),
            // This is either:
            //     1. A single vertex SCC that has a self-loop.
            //     2. A SCC with 2+ vertices.
            cycle => cycles.push(cycle.to_vec()),
        });

        (topo, cycles)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_cycle() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", []);
        topo.insert("Bar", ["Foo", "Fum"]);
        topo.insert("Foo", []);

        assert_eq!(topo.sort().unwrap(), vec!["Fum", "Foo", "Bar"]);
    }

    #[test]
    fn test_no_edges() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", []);

        assert_eq!(topo.sort().unwrap(), vec!["Fum"]);
    }

    #[test]
    fn test_cycle() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", ["Bar"]);
        topo.insert("Bar", ["Foo"]);
        topo.insert("Foo", ["Fum"]);

        assert_eq!(
            topo.sort().unwrap_err().to_string(),
            "Found cyclic dependencies when compiling structs:\n- [Foo, Bar, Fum]"
        );
    }

    #[test]
    fn test_cycles() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", ["Bar"]);
        topo.insert("Bar", ["Fum", "Foo"]);
        topo.insert("Foo", []);
        topo.insert("Fi", ["Foo"]);

        assert_eq!(topo.cycles(), vec![vec!["Bar", "Fum"]]);
    }

    #[test]
    fn test_self_cycle() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", ["Fum"]);
        topo.insert("Bar", ["Fum"]);

        assert_eq!(topo.cycles(), vec![vec!["Fum"]]);
    }

    #[test]
    fn test_no_cycles() {
        let mut topo = TopoSort::new();

        topo.insert("Bar", ["Foo", "Fum"]);
        topo.insert("Foo", ["Fum"]);
        topo.insert("Fum", []);

        assert!(topo.cycles().is_empty());
    }

    #[test]
    fn test_multi_cycle() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", ["Bar"]);
        topo.insert("Bar", ["Fum"]);
        topo.insert("Fi", ["Foo"]);
        topo.insert("Foo", ["Fi"]);

        assert_eq!(
            topo.sort().unwrap_err().to_string(),
            "Found cyclic dependencies when compiling structs:\n- [Bar, Fum]\n- [Foo, Fi]"
        );
    }
}
