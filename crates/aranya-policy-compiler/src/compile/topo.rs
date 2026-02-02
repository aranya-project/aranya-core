//! Contains [`TopoSort`] which can be used to sort values topologically.
//!
//! It is used in the compiler to find the order for compiling type definitions.
//!
//! A [`CycleError`] will be returned when values cannot be sorted topologically.
use std::fmt::Display;

use petgraph::{
    algo::TarjanScc,
    graphmap::{DiGraphMap, NodeTrait},
};

use crate::CompileErrorType;

/// Indicates that a cycle was found while sorting values.
#[derive(Debug)]
pub struct CycleError(Vec<Vec<String>>);

impl Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // This outputs a comma separated list of the nodes in each cycle/SCC.
        // A direct path is not shown.
        let cycles: Vec<_> = self
            .0
            .iter()
            .map(|cycle| {
                let mut buf = "[]".to_owned();
                buf.insert_str(1, &cycle.as_slice().join(", "));
                buf
            })
            .collect();
        write!(
            f,
            "Found cyclic dependencies when compiling structs:\n- {}",
            cycles.join("\n- ")
        )
    }
}

impl From<CycleError> for CompileErrorType {
    fn from(value: CycleError) -> Self {
        Self::Unknown(value.to_string())
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
    // Uses strongly connected components (SSC) to determine cycles in a directed graph.
    pub(crate) fn sort(self) -> Result<Vec<T>, CycleError> {
        let mut cycles = Vec::new();
        let mut topo = Vec::new();

        TarjanScc::new().run(&self.0, |group| match group {
            // A strongly connected component (SSC) of a single vertex and it's not a self-loop.
            &[lone] if !self.0.contains_edge(lone, lone) => topo.push(lone),
            // This is either:
            //     1. A single vertex SCC that has a self-loop.
            //     2. A SCC with 2+ vertices.
            cycle => {
                let cycle: Vec<_> = cycle.iter().map(ToString::to_string).collect();
                cycles.push(cycle);
            }
        });

        if !cycles.is_empty() {
            return Err(CycleError(cycles));
        }

        Ok(topo)
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
