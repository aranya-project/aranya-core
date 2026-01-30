//! Contains [`TopoSort`] which can be used to sort values topologically.
use std::fmt::Display;

use crate::CompileErrorType;

#[derive(Debug)]
pub(in crate::compile) struct CycleError(Vec<Vec<String>>);

impl Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub(in crate::compile) struct TopoSort<T>(petgraph::graphmap::DiGraphMap<T, ()>);

impl<T: petgraph::graphmap::NodeTrait + Display> TopoSort<T> {
    /// Creates a new empty graph.
    pub(crate) fn new() -> Self {
        Self(petgraph::graphmap::DiGraphMap::new())
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
        let mut cycles = Vec::new();
        let mut topo = Vec::new();

        petgraph::algo::TarjanScc::new().run(&self.0, |group| match group {
            &[lone] if !self.0.contains_edge(lone, lone) => topo.push(lone),
            cycle => {
                let mut cycle: Vec<_> = cycle.iter().map(ToString::to_string).collect();
                cycle.sort();
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
    fn test_cycle() {
        let mut topo = TopoSort::new();

        topo.insert("Fum", ["Bar"]);
        topo.insert("Bar", ["Foo"]);
        topo.insert("Foo", ["Fum"]);

        assert_eq!(
            topo.sort().unwrap_err().to_string(),
            "Found cyclic dependencies when compiling structs:\n- [Bar, Foo, Fum]"
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
            "Found cyclic dependencies when compiling structs:\n- [Bar, Fum]\n- [Fi, Foo]"
        );
    }
}
