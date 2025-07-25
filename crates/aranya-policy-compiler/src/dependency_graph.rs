use std::{error, fmt, hash::Hash, iter, vec};

use buggy::{Bug, BugExt};
use indexmap::IndexMap;

/// A node index in the dependency graph
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct NodeIdx(usize);

/// Type of dependency between nodes
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum DependencyKind {
    /// Type dependency (e.g., struct field type)
    Type,
    /// Function call dependency
    FunctionCall,
    /// Action call dependency
    ActionCall,
    /// Fact reference dependency
    FactReference,
    /// Struct composition dependency
    StructComposition,
    /// Enum reference dependency
    EnumReference,
    /// Substruct operation dependency
    SubstructTarget,
    /// A global identifier.
    Global,
}

/// A directed edge in the dependency graph (using indices for efficiency)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Edge {
    /// The target node index
    target_idx: usize,
    /// The kind of dependency
    kind: DependencyKind,
}

/// Node data in the dependency graph (minimal, index-based)
#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeData {
    /// Outgoing edges (dependencies) as indices
    edges: Vec<Edge>,
}

/// A purpose-built dependency graph optimized for topological sorting
#[derive(Clone)]
pub(crate) struct DependencyGraph<K> {
    /// Nodes indexed by key, preserving insertion order
    nodes: IndexMap<K, NodeData>,
}

impl<K> DependencyGraph<K>
where
    K: Hash + Eq + fmt::Debug,
{
    /// Create a new empty dependency graph
    pub fn new() -> Self {
        Self {
            nodes: IndexMap::new(),
        }
    }

    /// Returns the key corresponding with `idx`.
    ///
    /// It returns `None` if `idx` is invalid.
    pub fn get(&self, idx: NodeIdx) -> Option<&K> {
        self.nodes.get_index(idx.0).map(|(k, _)| k)
    }

    /// Returns the keys corresponding with `indices`.
    ///
    /// It returns `Err(InvalidNodeIndex)` if any of the indices
    /// are invalid.
    pub fn get_disjoint(
        &self,
        indices: impl IntoIterator<Item = NodeIdx>,
    ) -> impl Iterator<Item = Result<&K, InvalidNodeIdx>> {
        indices.into_iter().map(|idx| {
            self.nodes
                .get_index(idx.0)
                .map(|(k, _)| k)
                .ok_or(InvalidNodeIdx(idx))
        })
    }

    /// Adds a node to the graph.
    pub fn add_node(&mut self, id: K) -> usize {
        match self.nodes.get_index_of(&id) {
            Some(idx) => idx,
            None => {
                self.nodes.insert(id, NodeData { edges: Vec::new() });
                self.nodes.len() - 1
            }
        }
    }

    /// Add a dependency edge from `from` to `to` with the given kind
    pub fn add_dependency(&mut self, from: K, to: K, kind: DependencyKind) {
        // Ensure both nodes exist
        let from_idx = self.add_node(from);
        let to_idx = self.add_node(to);

        // Add the edge using indices
        self.nodes
            .get_index_mut(from_idx)
            .expect("from_idx must exist")
            .1
            .edges
            .push(Edge {
                target_idx: to_idx,
                kind,
            });
    }

    /// Performs a topological sort of the dependencies.
    ///
    /// It returns the nodes in dependency order, meaning
    /// a dependency will appear before its dependent. For
    /// example, given `a -> b -> c` where `a` depends on `b` and
    /// `b` depends on `c`, the result will be `[c, b, a]`.
    pub fn topo_sort(&self) -> Result<Vec<NodeIdx>, SortError> {
        // NB: While a DFS is little more complex than a BFS, we
        // use a DFS because it lets us early exit when we detect
        // a cycle.

        if self.nodes.is_empty() {
            return Ok(Vec::new());
        }

        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        enum Mark {
            /// The node has not been visited yet.
            Unvisited,
            /// The node is currently being visited (in the
            /// stack).
            Visiting,
            /// The node has been fully processed.
            Visited,
        }

        let mut marks = vec![Mark::Unvisited; self.nodes.len()];
        let mut sorted = Vec::with_capacity(self.nodes.len());

        // Stack stores (node_idx, edge_idx)
        let mut stack = Vec::new();

        // Process every node to handle disconnected graphs
        for start_idx in 0..self.nodes.len() {
            if marks[start_idx] != Mark::Unvisited {
                continue;
            }

            stack.push((start_idx, 0));

            while let Some((node_idx, edge_idx)) = stack.last_mut() {
                let node_idx = *node_idx;

                if *edge_idx == 0 {
                    // First time visiting this node
                    marks[node_idx] = Mark::Visiting;
                }

                let edges = &self
                    .nodes
                    .get_index(node_idx)
                    .assume("node must exist")?
                    .1
                    .edges;
                if *edge_idx >= edges.len() {
                    // All dependencies have been processed
                    marks[node_idx] = Mark::Visited;
                    sorted.push(node_idx);
                    stack.pop();
                    continue;
                }

                let target_idx = edges[*edge_idx].target_idx;
                *edge_idx += 1;

                match marks[target_idx] {
                    Mark::Unvisited => {
                        stack.push((target_idx, 0));
                    }
                    Mark::Visiting => {
                        // We're already visiting this node,
                        // which means we've found a cycle.
                        let cycle = self.build_cycle_path(&stack, target_idx);
                        return Err(Cycle { cycle }.into());
                    }
                    Mark::Visited => {
                        // Already processed
                    }
                }
            }
        }

        // Return indices directly - no cloning needed!
        Ok(sorted.into_iter().map(NodeIdx).collect())
    }

    #[cold]
    fn build_cycle_path(&self, stack: &[(usize, usize)], target_idx: usize) -> Vec<NodeIdx> {
        stack
            .iter()
            .skip_while(|(idx, _)| *idx != target_idx)
            .map(|(idx, _)| NodeIdx(*idx))
            .chain(iter::once(NodeIdx(target_idx)))
            .collect()
    }
}

impl<K> fmt::Debug for DependencyGraph<K>
where
    K: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DependencyGraph {{")?;
        for (key, node) in &self.nodes {
            writeln!(f, "  {:?} ->", key)?;
            for edge in &node.edges {
                let target_key = self.nodes.get_index(edge.target_idx).map(|(k, _)| k);
                if let Some(target) = target_key {
                    writeln!(f, "    {:?} ({:?})", target, edge.kind)?;
                }
            }
        }
        write!(f, "}}")
    }
}

/// Unable to sort the dependency graph.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum SortError {
    /// An internal bug was discovered.
    #[error("bug: {0}")]
    Bug(#[from] Bug),
    /// A cycle was found in the graph.
    #[error("{0}")]
    Cycle(#[from] Cycle),
}

/// Invalid node index error.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid node index: {0:?}")]
pub(crate) struct InvalidNodeIdx(NodeIdx);

/// A cycle in the dependency graph.
#[derive(Clone, Debug)]
pub(crate) struct Cycle {
    cycle: Vec<NodeIdx>,
}

impl IntoIterator for Cycle {
    type Item = NodeIdx;
    type IntoIter = vec::IntoIter<NodeIdx>;

    fn into_iter(self) -> Self::IntoIter {
        self.cycle.into_iter()
    }
}

impl fmt::Display for Cycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dependency cycle detected")
    }
}

impl error::Error for Cycle {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_graph() {
        let mut graph = DependencyGraph::new();

        // A -> B -> C
        graph.add_dependency("A", "B", DependencyKind::Type);
        graph.add_dependency("B", "C", DependencyKind::Type);

        let sorted_indices = graph.topo_sort().unwrap();
        let sorted: Vec<_> = sorted_indices
            .iter()
            .map(|&idx| graph.get(idx).unwrap())
            .collect();
        assert_eq!(sorted, vec![&"C", &"B", &"A"]);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = DependencyGraph::new();

        // A -> B -> C -> A (cycle)
        graph.add_dependency("A", "B", DependencyKind::Type);
        graph.add_dependency("B", "C", DependencyKind::Type);
        graph.add_dependency("C", "A", DependencyKind::Type);

        let err = match graph.topo_sort().unwrap_err() {
            SortError::Cycle(err) => err,
            SortError::Bug(bug) => panic!("unexpected err: {bug:?}"),
        };
        // The cycle should have 4 elements: A -> B -> C -> A
        assert_eq!(err.cycle.len(), 4);
    }

    #[test]
    fn test_complex_graph() {
        let mut graph = DependencyGraph::new();

        // Multiple dependencies
        graph.add_dependency("App", "Database", DependencyKind::Type);
        graph.add_dependency("App", "Logger", DependencyKind::Type);
        graph.add_dependency("Database", "Config", DependencyKind::Type);
        graph.add_dependency("Logger", "Config", DependencyKind::Type);

        let sorted_indices = graph.topo_sort().unwrap();
        let sorted: Vec<_> = sorted_indices
            .iter()
            .map(|&idx| graph.get(idx).unwrap())
            .collect();

        // Config should come before both Database and Logger
        let config_idx = sorted.iter().position(|id| id == &&"Config").unwrap();
        let db_idx = sorted.iter().position(|id| id == &&"Database").unwrap();
        let logger_idx = sorted.iter().position(|id| id == &&"Logger").unwrap();
        let app_idx = sorted.iter().position(|id| id == &&"App").unwrap();

        assert!(config_idx < db_idx);
        assert!(config_idx < logger_idx);
        assert!(db_idx < app_idx);
        assert!(logger_idx < app_idx);
    }

    #[test]
    fn test_disconnected_graph() {
        let mut graph = DependencyGraph::new();

        // Two disconnected components: (A -> B) and (C -> D)
        graph.add_dependency("A", "B", DependencyKind::Type);
        graph.add_dependency("C", "D", DependencyKind::Type);

        let sorted_indices = graph.topo_sort().unwrap();
        assert_eq!(sorted_indices.len(), 4);

        let sorted: Vec<_> = sorted_indices
            .iter()
            .map(|&idx| graph.get(idx).unwrap())
            .collect();

        // Check ordering within components
        let a_idx = sorted.iter().position(|id| id == &&"A").unwrap();
        let b_idx = sorted.iter().position(|id| id == &&"B").unwrap();
        let c_idx = sorted.iter().position(|id| id == &&"C").unwrap();
        let d_idx = sorted.iter().position(|id| id == &&"D").unwrap();

        assert!(b_idx < a_idx); // B comes before A
        assert!(d_idx < c_idx); // D comes before C
    }

    #[test]
    fn test_self_dependency() {
        let mut graph = DependencyGraph::new();

        // A depends on itself
        graph.add_dependency("A", "A", DependencyKind::Type);

        let err = match graph.topo_sort().unwrap_err() {
            SortError::Cycle(err) => err,
            SortError::Bug(bug) => panic!("unexpected err: {bug:?}"),
        };
        // Check that the cycle contains A by verifying one of
        // the nodes in the cycle maps back to "A"
        let contains_a = err
            .cycle
            .iter()
            .any(|&idx| graph.get(idx).map(|k| k == &"A").unwrap_or(false));
        assert!(contains_a);
    }
}
