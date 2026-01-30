//! Contains [`TopoSort`] which can be used to sort values topologically.
use std::{fmt::Display, hash::Hash};

use indexmap::{IndexMap, IndexSet};

use crate::CompileErrorType;

#[derive(Debug)]
pub(in crate::compile) struct CycleError(Vec<String>);

impl Display for CycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Found cyclic dependencies when compiling structs: {}",
            self.0.join(" -> ")
        )
    }
}

impl From<CycleError> for CompileErrorType {
    fn from(value: CycleError) -> Self {
        Self::Unknown(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Unvisited,
    Visiting,
    Visited,
}

/// A directed graph that can be topologically sorted.
// NB. IndexMap is mainly used to produce a deterministic ordering so tests pass.
pub(in crate::compile) struct TopoSort<T>(IndexMap<T, Vec<T>>);

impl<T: Hash + Eq> TopoSort<T> {
    /// Creates a new empty graph.
    pub(crate) fn new() -> Self {
        Self(IndexMap::new())
    }

    /// Inserts a node with its dependencies.
    ///
    /// If the node already exists, its dependencies are replaced.
    pub(crate) fn insert(&mut self, node: T, deps: impl IntoIterator<Item = T>) {
        self.0.insert(node, deps.into_iter().collect());
    }
}

impl<T: Clone + Eq + Hash + Display> TopoSort<T> {
    /// Consumes the graph and returns nodes in topological order.
    pub(crate) fn sort(self) -> Result<Vec<T>, CycleError> {
        let graph = &self.0;

        // Collect all nodes in insertion order
        let all_nodes: IndexSet<&T> = graph
            .iter()
            .flat_map(|(node, deps)| std::iter::once(node).chain(deps.iter()))
            .collect();

        let mut state: IndexMap<&T, State> =
            all_nodes.iter().map(|&n| (n, State::Unvisited)).collect();
        let mut result = Vec::with_capacity(all_nodes.len());
        // Keep track of the current path so we can print the cycle in case of an error.
        let mut path = Vec::new();

        for node in all_nodes {
            if state[node] == State::Unvisited {
                visit(node, graph, &mut state, &mut result, &mut path)?;
            }
        }

        Ok(result)
    }
}

// DFS with cycle detection
fn visit<'a, T>(
    node: &'a T,
    graph: &'a IndexMap<T, Vec<T>>,
    state: &mut IndexMap<&'a T, State>,
    result: &mut Vec<T>,
    path: &mut Vec<&'a T>,
) -> Result<(), CycleError>
where
    T: Clone + Eq + Hash + Display,
{
    state.insert(node, State::Visiting);
    path.push(node);

    if let Some(dependencies) = graph.get(node) {
        for dep in dependencies {
            match state
                .get(dep)
                .expect("should have initialized the state in `TopoSort::sort`")
            {
                State::Unvisited => visit(dep, graph, state, result, path)?,
                // Encountered a node that we're still processing so this must be a back edge.
                State::Visiting => {
                    let cycle = extract_cycle(path, dep);
                    return Err(CycleError(cycle));
                }
                State::Visited => {}
            }
        }
    }

    // All the dependencies have been visited so we can mark this node as "visited" and remove it from the path.
    state.insert(node, State::Visited);
    path.pop();
    result.push(node.clone());
    Ok(())
}

fn extract_cycle<T: Display + Eq>(path: &[&T], cycle_start: &T) -> Vec<String> {
    let start_pos = path
        .iter()
        .position(|&n| n == cycle_start)
        .expect("`cycle_start` should be in the path");
    let mut cycle: Vec<String> = path[start_pos..].iter().map(|n| n.to_string()).collect();
    // Add the `cycle_start` to the end so we can show the cycle like: 'Foo -> ... -> Foo'.
    cycle.push(cycle_start.to_string());
    cycle
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
            "Found cyclic dependencies when compiling structs: Fum -> Bar -> Foo -> Fum"
        )
    }
}
