#![expect(clippy::unwrap_used)]

use std::{
    cell::OnceCell,
    collections::{BTreeMap, BTreeSet},
    error, fmt,
    fmt::Write,
    hash::Hash,
    iter, mem,
    ops::ControlFlow,
    vec,
};

use aranya_policy_ast as ast;
use buggy::Bug;
use indexmap::IndexMap;
use tracing::instrument;

use crate::{
    ctx::Ctx,
    diag::{
        Diag, DiagCtx, Diagnostic, EmissionGuarantee, ErrorGuaranteed, MultiSpan, OptionExt,
        ResultExt, Severity,
    },
    hir::{
        visit::{self, Visitor, Walkable},
        AstLowering, Hir, HirView, Ident, IdentId, LetStmt, Named, Span, Stmt, StmtKind,
    },
    pass::{DepsRefs, Pass, View},
    symtab::{SymbolId, SymbolKind, SymbolResolution, SymbolsView},
};

#[derive(Copy, Clone, Debug)]
pub struct DepsPass;

impl Pass for DepsPass {
    const NAME: &'static str = "deps";
    type Output = DepGraph;
    type View<'cx> = DepsView<'cx>;
    type Deps = (AstLowering, SymbolResolution);

    fn run<'cx>(
        cx: Ctx<'cx>,
        (hir, symbols): DepsRefs<'cx, Self>,
    ) -> Result<Self::Output, ErrorGuaranteed> {
        let mut graph = Graph::new();

        // First add all nodes...
        for (id, _) in symbols {
            graph.add_node(id);
        }

        // ...then add the edges.
        let mut visitor = AddEdges {
            ctx: cx,
            hir,
            symbols,
            graph: &mut graph,
            item: None,
        };
        visitor.visit_all();

        let mut err = None;
        for scc in graph
            .find_sccs()
            .into_iter()
            .filter(|scc| scc.len() > 1)
            .take(5)
        {
            let mut cycle = Vec::new();
            for sym_id in scc {
                let sym = symbols.get(sym_id);
                let xref = hir.lookup(sym.ident).xref;
                let ident = cx.get_ident(xref);
                cycle.push((ident.clone(), sym.span));
            }
            let _ = err.insert(cx.dcx().emit_err_diag(CyclicDependencyError { cycle }));
        }

        if let Some(err) = err {
            Err(err)
        } else {
            Ok(DepGraph {
                graph,
                topo_sorted: OnceCell::new(),
            })
        }
    }
}

impl<'cx> Ctx<'cx> {
    pub fn deps(self) -> Result<DepsView<'cx>, ErrorGuaranteed> {
        let deps = self.get::<DepsPass>()?;
        Ok(View::new(self, deps))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DepsView<'cx> {
    ctx: Ctx<'cx>,
    deps: &'cx DepGraph,
}

impl<'cx> DepsView<'cx> {
    pub fn graph(&self) -> &'cx DepGraph {
        self.deps
    }

    /// Get the topologically sorted symbols.
    pub fn topo_sorted(&self) -> &'cx [SymbolId] {
        self.deps
            .topo_sorted
            .get_or_init(|| {
                self.deps
                    .graph
                    .topo_sort()
                    .unwrap_or_bug(self.ctx.dcx(), "dependency graph must be acyclic")
            })
            .as_slice()
    }
}

impl<'cx> View<'cx, DepGraph> for DepsView<'cx> {
    fn new(ctx: Ctx<'cx>, data: &'cx DepGraph) -> Self {
        Self { ctx, deps: data }
    }
}

/// Visitor that adds dependency edges to the graph by walking
/// the HIR.
///
/// This visitor traverses the HIR structure and identifies
/// dependencies between symbols. It maintains context about
/// which symbol is currently being processed, allowing it to
/// create edges from the current symbol to any symbols it
/// references.
#[derive(Debug)]
struct AddEdges<'a, 'cx> {
    ctx: Ctx<'cx>,
    hir: HirView<'cx>,
    symbols: SymbolsView<'cx>,
    graph: &'a mut Graph<SymbolId, SymbolKind>,
    /// The current symbol that we're resolving.
    item: Option<SymbolId>,
}

impl AddEdges<'_, '_> {
    /// Executes a closure with the symbol ID corresponding to
    /// the given identifier.
    ///
    /// This method resolves the identifier to its symbol ID and
    /// temporarily sets it as the current item being processed.
    /// This is necessary because the visitor needs to know which
    /// symbol is creating dependencies when it encounters
    /// references to other symbols.
    fn with_item_for_ident<F, R>(&mut self, ident: IdentId, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        let item = self.symbols.resolve(ident);
        self.with_item(item, f)
    }

    /// Executes a closure with a specific symbol ID as the
    /// current item.
    ///
    /// This method temporarily sets the current item and
    /// restores the previous value after the closure completes.
    /// This allows for nested symbol processing while
    /// maintaining the correct dependency context.
    fn with_item<F, R>(&mut self, item: SymbolId, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        let prev = mem::replace(&mut self.item, Some(item));
        let result = f(self);
        self.item = prev;
        result
    }
}

/// Macro that generates visitor methods for top-level items.
///
/// This macro creates visitor methods that automatically set the
/// current item context when visiting top-level items. This
/// ensures that dependencies are correctly attributed to the
/// right symbol.
macro_rules! update_item {
    ($visit:ident => $ty:ty) => {
        #[instrument(skip_all, fields(id = %v.ident(), item = ?self.item))]
        fn $visit(&mut self, v: &'hir $ty) -> Self::Result {
            self.with_item_for_ident(v.ident(), |this| v.walk(this))
        }
    };
}

impl<'ctx: 'hir, 'hir> Visitor<'hir> for AddEdges<'_, 'ctx> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'hir Hir {
        self.hir.hir()
    }

    visit::for_each_top_level_item!(update_item);

    /// Visits statements and handles let statements specially.
    ///
    /// Let statements create new symbols, so we need to set the
    /// current item context to the newly declared symbol before
    /// visiting its expression. This ensures that dependencies
    /// in the expression are attributed to the correct symbol.
    fn visit_stmt(&mut self, stmt: &'hir Stmt) -> Self::Result {
        let hir = self.hir;
        match &stmt.kind {
            StmtKind::Let(LetStmt { ident, expr }) => self.with_item_for_ident(*ident, |this| {
                let expr = hir.lookup(*expr);
                this.visit_expr(expr)
            }),
            _ => stmt.walk(self),
        }
    }

    /// Visits identifiers and creates dependency edges.
    ///
    /// When an identifier is encountered, it represents
    /// a dependency from the current symbol to the referenced
    /// symbol. This method creates the appropriate edge in the
    /// dependency graph, skipping any symbols that have been
    /// marked as skipped during symbol resolution.
    fn visit_ident(&mut self, ident: &'hir Ident) -> Self::Result {
        if self.symbols.is_skipped(ident.id) {
            return ControlFlow::Continue(());
        }
        let from = self.item.unwrap_or_bug(
            self.ctx.dcx(),
            "`self.item` must be set before visiting an ident",
        );
        let to = self.symbols.resolve(ident.id);
        let kind = self.symbols.get(to).kind;
        self.graph.add_dependency(from, to, kind);
        ControlFlow::Continue(())
    }
}

#[derive(Clone, Debug)]
pub struct DepGraph {
    pub(crate) graph: Graph<SymbolId, SymbolKind>,
    pub(crate) topo_sorted: OnceCell<Vec<SymbolId>>,
}

/// A directed dependency graph that tracks relationships between
/// nodes.
///
/// The graph is generic over the key type `K` and dependency
/// kind `D`.
#[derive(Clone)]
pub(crate) struct Graph<K, D> {
    /// Nodes indexed by key.
    nodes: IndexMap<K, NodeData<K, D>>,
    /// Reverse edge index: target -> Vec<source> for efficient
    /// incoming edge lookup.
    incoming_edges: BTreeMap<K, Vec<K>>,
}

// Basic operations with minimal bounds
impl<K, D> Graph<K, D> {
    /// Create a new empty dependency graph
    fn new() -> Self {
        Self {
            nodes: IndexMap::new(),
            incoming_edges: BTreeMap::new(),
        }
    }
}

impl<K, D> Graph<K, D>
where
    K: Hash + Eq + Ord,
{
    /// Adds a node to the graph.
    ///
    /// If the node already exists, returns its index. Otherwise,
    /// creates a new node and returns its index. This method is
    /// idempotent, making it safe to call multiple times with
    /// the same key.
    pub fn add_node(&mut self, id: K) -> usize {
        match self.nodes.get_index_of(&id) {
            Some(idx) => idx,
            None => {
                self.nodes.insert(
                    id,
                    NodeData {
                        edges: Vec::new(),
                        edge_targets: BTreeSet::new(),
                    },
                );
                self.nodes.len() - 1
            }
        }
    }
}

impl<K, D> Graph<K, D>
where
    K: Hash + Eq + Copy + Ord,
    D: Copy,
{
    /// Add a dependency edge from `from` to `to`.
    ///
    /// This method ensures both nodes exist in the graph before
    /// creating the edge. The edge represents a dependency where
    /// the `from` node depends on the `to` node, meaning the
    /// `to` node must be processed before the `from` node.
    ///
    /// # Panics
    ///
    /// This method panics if an edge already exists between
    /// these two nodes.
    pub fn add_dependency(&mut self, from: K, to: K, kind: D) {
        // Ensure both nodes exist
        self.add_node(from);
        self.add_node(to);

        let from_node = self.nodes.get_mut(&from).expect("from node must exist");

        assert!(!from_node.edge_targets.contains(&to), "edge already exists");

        from_node.edges.push(Edge { target: to, kind });
        from_node.edge_targets.insert(to);

        // Update reverse edge index
        self.incoming_edges.entry(to).or_default().push(from);
    }
}

impl<K, D> Graph<K, D>
where
    K: Hash + Eq + fmt::Debug + Copy + Ord,
    D: Copy,
{
    /// Check if there's a dependency path from `from` to `to`.
    ///
    /// This method performs a depth-first search to determine if
    /// there's a transitive dependency path between the two nodes.
    /// It's useful for detecting indirect dependencies and validating
    /// that the dependency graph maintains the desired relationships.
    ///
    /// # Algorithm Overview (DFS Path Detection)
    ///
    /// This is a standard depth-first search that explores the graph
    /// starting from the source node until it either reaches the target
    /// or exhausts all reachable paths.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes
    ///   and E is the number of edges
    /// - Best Case: O(1) when from == to
    /// - Average Case: O(V + E) for typical sparse graphs
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the visited array and recursion stack
    ///
    /// ## Pseudocode:
    /// ```text
    /// function has_dependency_path(graph, from, to):
    ///     if from == to:
    ///         return true
    ///
    ///     visited = array of false values, size = graph.nodes.length
    ///     return dfs_path_exists(from, to, visited)
    ///
    /// function dfs_path_exists(current, target, visited):
    ///     if current == target:
    ///         return true
    ///     if visited[current]:
    ///         return false
    ///
    ///     visited[current] = true
    ///     for each neighbor of current:
    ///         if dfs_path_exists(neighbor, target, visited):
    ///             return true
    ///     return false
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// let mut graph = Graph::<&str, DepType>::new();
    ///
    /// // Build a simple dependency chain: A -> B -> C
    /// graph.add_dependency("A", "B", DepType::Type);
    /// graph.add_dependency("B", "C", DepType::Value);
    ///
    /// // Check for dependency paths
    /// assert!(graph.has_dependency_path("A", "C"));  // A -> B -> C
    /// assert!(graph.has_dependency_path("A", "B"));  // A -> B
    /// assert!(graph.has_dependency_path("B", "C"));  // B -> C
    /// assert!(!graph.has_dependency_path("C", "A")); // No path from C to A
    /// assert!(!graph.has_dependency_path("C", "B")); // No path from C to B
    /// ```
    pub fn has_dependency_path(&self, from: K, to: K) -> bool {
        let from_idx = match self.nodes.get_index_of(&from) {
            Some(idx) => idx,
            None => return false,
        };
        let to_idx = match self.nodes.get_index_of(&to) {
            Some(idx) => idx,
            None => return false,
        };

        let mut visited = vec![false; self.nodes.len()];
        self.dfs_path_exists(from_idx, to_idx, &mut visited)
    }

    /// Performs depth-first search to check for path existence.
    ///
    /// This helper method implements the core DFS logic for path
    /// detection. It uses a visited array to avoid cycles and
    /// efficiently explores the graph structure.
    ///
    /// ## Algorithm Details:
    ///
    /// The DFS explores the graph by:
    /// 1. Base Cases: Return true if we reach the target, false if we hit a visited node
    /// 2. Recursive Exploration: Mark current node as visited, then explore all neighbors
    /// 3. Early Exit: Return true as soon as any path to the target is found
    ///
    /// The visited array prevents infinite loops in cyclic graphs and ensures
    /// each node is explored at most once, giving O(V + E) time complexity.
    fn dfs_path_exists(&self, from_idx: usize, to_idx: usize, visited: &mut [bool]) -> bool {
        if from_idx == to_idx {
            return true;
        }
        if visited[from_idx] {
            return false;
        }
        visited[from_idx] = true;

        let node_data = &self.nodes.get_index(from_idx).unwrap().1;
        for edge in &node_data.edges {
            let target_idx = self.nodes.get_index_of(&edge.target).unwrap();
            if self.dfs_path_exists(target_idx, to_idx, visited) {
                return true;
            }
        }
        false
    }

    /// Returns all nodes that must be processed before the given node.
    ///
    /// This method computes the transitive closure of all dependencies
    /// that lead to the given node. It's useful for determining the
    /// complete set of prerequisites needed before processing a
    /// particular symbol or component.
    ///
    /// The result excludes the node itself, as a node doesn't need
    /// to be processed before itself.
    ///
    /// # Algorithm Overview (Backward DFS Closure)
    ///
    /// This algorithm computes the backward closure by traversing the
    /// graph in reverse - following incoming edges to find all nodes
    /// that have dependencies on the target.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and E is the number of edges
    /// - Best Case: O(V + E) for sparse graphs with few incoming edges
    /// - Average Case: O(V + E) due to efficient reverse edge lookup
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the visited map and result vector
    ///
    /// ## Pseudocode:
    /// ```text
    /// function dependency_closure(graph, target):
    ///     closure = []
    ///     visited = {}
    ///     dfs_closure(target, visited, closure)
    ///     return closure - {target}  # Exclude target itself
    ///
    /// function dfs_closure(node, visited, closure):
    ///     if visited[node]:
    ///         return
    ///
    ///     visited[node] = true
    ///     closure.push(node)
    ///
    ///     # Find all nodes that have edges TO this node
    ///     for each other_node in graph:
    ///         if other_node has edge to node:
    ///             dfs_closure(other_node, visited, closure)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// let mut graph = Graph::<&str, DepType>::new();
    ///
    /// // Build a dependency graph: A -> B -> C, D -> B
    /// graph.add_dependency("A", "B", DepType::Type);
    /// graph.add_dependency("B", "C", DepType::Value);
    /// graph.add_dependency("D", "B", DepType::Type);
    ///
    /// // Find what must be processed before C
    /// let closure = graph.dependency_closure("C");
    /// assert_eq!(closure.len(), 3);
    /// assert!(closure.contains(&"A"));  // A -> B -> C
    /// assert!(closure.contains(&"B"));  // B -> C
    /// assert!(closure.contains(&"D"));  // D -> B -> C
    ///
    /// // Find what must be processed before B
    /// let closure = graph.dependency_closure("B");
    /// assert_eq!(closure.len(), 2);
    /// assert!(closure.contains(&"A"));  // A -> B
    /// assert!(closure.contains(&"D"));  // D -> B
    /// ```
    pub fn dependency_closure(&self, node: K) -> Vec<K> {
        let mut closure = Vec::new();
        let mut visited: BTreeMap<K, bool> = BTreeMap::new();

        self.dfs_closure(node, &mut visited, &mut closure);

        // Remove the node itself from its closure
        closure.retain(|&k| k != node);
        closure
    }

    /// Computes the dependency closure using depth-first search.
    ///
    /// This method traverses the graph backwards from the target node,
    /// following incoming edges to find all nodes that have dependencies
    /// on the target. It's the core algorithm for computing dependency
    /// closures.
    ///
    /// ## Algorithm Details:
    ///
    /// The backward traversal works by:
    /// 1. Reverse Edge Traversal: For each node, efficiently find all nodes that point to it using the reverse edge index
    /// 2. Recursive Exploration: Visit each predecessor and compute their closures
    /// 3. Cycle Handling: The visited map prevents infinite recursion in cyclic graphs
    ///
    /// This approach uses an optimized reverse edge index for O(1) incoming edge lookup,
    /// making it much more efficient than scanning all nodes for incoming edges.
    fn dfs_closure(&self, node_key: K, visited: &mut BTreeMap<K, bool>, closure: &mut Vec<K>) {
        if visited.get(&node_key) == Some(&true) {
            return;
        }
        visited.insert(node_key, true);
        closure.push(node_key);

        // Follow incoming edges (dependencies) using reverse index
        if let Some(sources) = self.incoming_edges.get(&node_key) {
            for &source in sources {
                self.dfs_closure(source, visited, closure);
            }
        }
    }

    /// Find all nodes that the given node can reach (transitive successors).
    ///
    /// This method computes the forward closure of a node, finding all
    /// nodes that depend on it either directly or indirectly. It's
    /// useful for understanding the impact of changes to a particular
    /// node and for determining which components need to be rebuilt
    /// when a dependency changes.
    ///
    /// # Algorithm Overview (Forward DFS Closure)
    ///
    /// This is the inverse of `dependency_closure` - instead of finding
    /// what a node depends on, we find what depends on it.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and E is the number of edges
    /// - Best Case: O(1) when the node has no outgoing edges
    /// - Average Case: O(V + E) for typical sparse graphs
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the visited map and result vector
    ///
    /// ## Pseudocode:
    /// ```text
    /// function find_dependents(graph, source):
    ///     dependents = []
    ///     visited = {}
    ///     dfs_dependents(source, visited, dependents)
    ///     return dependents - {source}  # Exclude source itself
    ///
    /// function dfs_dependents(node, visited, dependents):
    ///     if visited[node]:
    ///         return
    ///
    ///     visited[node] = true
    ///     dependents.push(node)
    ///
    ///     # Follow outgoing edges to find dependents
    ///     for each edge from node:
    ///         dfs_dependents(edge.target, visited, dependents)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// let mut graph = Graph::<&str, DepType>::new();
    ///
    /// // Build a dependency graph: A -> B -> C, A -> D
    /// graph.add_dependency("A", "B", DepType::Type);
    /// graph.add_dependency("B", "C", DepType::Value);
    /// graph.add_dependency("A", "D", DepType::Type);
    ///
    /// // Find what depends on A (impact analysis)
    /// let dependents = graph.find_dependents("A");
    /// assert_eq!(dependents.len(), 3);
    /// assert!(dependents.contains(&"B"));  // A -> B
    /// assert!(dependents.contains(&"C"));  // A -> B -> C
    /// assert!(dependents.contains(&"D"));  // A -> D
    ///
    /// // Find what depends on B
    /// let dependents = graph.find_dependents("B");
    /// assert_eq!(dependents.len(), 1);
    /// assert!(dependents.contains(&"C"));  // B -> C
    ///
    /// // Find what depends on C (leaf node)
    /// let dependents = graph.find_dependents("C");
    /// assert_eq!(dependents.len(), 0);  // No dependents
    /// ```
    pub fn find_dependents(&self, src: K) -> Vec<K> {
        let mut dependents = Vec::new();
        let mut visited: BTreeMap<K, bool> = BTreeMap::new();

        self.dfs_dependents(src, &mut visited, &mut dependents);

        // Remove the source node itself
        dependents.retain(|&k| k != src);
        dependents
    }

    /// Computes the forward closure using depth-first search.
    ///
    /// This method traverses the graph forwards from the source node,
    /// following outgoing edges to find all nodes that depend on it.
    /// It's the core algorithm for computing dependent sets.
    ///
    /// ## Algorithm Details:
    ///
    /// Forward traversal is simpler than backward traversal because:
    /// 1. Direct Edge Access: We can directly iterate over outgoing edges
    /// 2. Natural DFS: The graph structure naturally supports forward exploration
    /// 3. Efficient: No need to scan all nodes to find incoming edges
    ///
    /// This makes it ideal for impact analysis - understanding what would
    /// be affected by changes to a particular component.
    fn dfs_dependents(
        &self,
        node_key: K,
        visited: &mut BTreeMap<K, bool>,
        dependents: &mut Vec<K>,
    ) {
        if visited.get(&node_key) == Some(&true) {
            return;
        }
        visited.insert(node_key, true);
        dependents.push(node_key);

        // Follow outgoing edges
        let node_data = &self.nodes[&node_key];
        for edge in &node_data.edges {
            self.dfs_dependents(edge.target, visited, dependents);
        }
    }

    /// Find all nodes that can reach the given node (transitive predecessors).
    ///
    /// This method computes the backward closure of a node, finding all
    /// nodes that it depends on either directly or indirectly. It's
    /// essentially the inverse of `find_dependents` and is useful for
    /// understanding the complete dependency chain leading to a node.
    ///
    /// # Algorithm Overview (Backward DFS Closure)
    ///
    /// This method is identical to `dependency_closure` but with different
    /// naming to emphasize the direction of traversal. It's useful for
    /// understanding the complete dependency chain that leads to a target.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and E is the number of edges
    /// - Best Case: O(V + E) for sparse graphs with few incoming edges
    /// - Average Case: O(V + E) due to efficient reverse edge lookup
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the visited map and result vector
    ///
    /// ## Pseudocode:
    /// ```text
    /// function find_reachability(graph, target):
    ///     reachable = []
    ///     visited = {}
    ///     dfs_reachability(target, visited, reachable)
    ///     return reachable - {target}  # Exclude target itself
    ///
    /// function dfs_reachability(node, visited, reachable):
    ///     if visited[node]:
    ///         return
    ///
    ///     visited[node] = true
    ///     reachable.push(node)
    ///
    ///     # Find all nodes that have edges TO this node
    ///     for each other_node in graph:
    ///         if other_node has edge to node:
    ///             dfs_reachability(other_node, visited, reachable)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// let mut graph = Graph::<&str, DepType>::new();
    ///
    /// // Build a dependency graph: A -> B -> C, D -> B
    /// graph.add_dependency("A", "B", DepType::Type);
    /// graph.add_dependency("B", "C", DepType::Value);
    /// graph.add_dependency("D", "B", DepType::Type);
    ///
    /// // Find what can reach C (backward closure)
    /// let reachable = graph.find_reachability("C");
    /// assert_eq!(reachable.len(), 2);
    /// assert!(reachable.contains(&"A"));  // A -> B -> C
    /// assert!(reachable.contains(&"B"));  // B -> C
    ///
    /// // Find what can reach B
    /// let reachable = graph.find_reachability("B");
    /// assert_eq!(reachable.len(), 2);
    /// assert!(reachable.contains(&"A"));  // A -> B
    /// assert!(reachable.contains(&"D"));  // D -> B
    ///
    /// // Find what can reach A (root node)
    /// let reachable = graph.find_reachability("A");
    /// assert_eq!(reachable.len(), 0);  // No nodes reach A
    /// ```
    pub fn find_reachability(&self, target: K) -> Vec<K> {
        let mut reachable = Vec::new();
        let mut visited: BTreeMap<K, bool> = BTreeMap::new();

        self.dfs_reachability(target, &mut visited, &mut reachable);

        // Remove the target node itself
        reachable.retain(|&k| k != target);
        reachable
    }

    /// Computes the backward closure using depth-first search.
    ///
    /// This method traverses the graph backwards from the target node,
    /// finding all nodes that have edges pointing to it. It's used
    /// to compute the complete set of nodes that can reach the target.
    ///
    /// ## Algorithm Details:
    ///
    /// The backward traversal efficiently finds incoming edges using the reverse edge index,
    /// making it as efficient as forward traversal. This approach provides O(1) lookup
    /// for incoming edges instead of the previous O(V) scan.
    ///
    /// This is particularly useful for:
    /// - Understanding what needs to be built before a target
    /// - Analyzing the impact of removing a dependency
    /// - Planning build order for complex dependency graphs
    fn dfs_reachability(
        &self,
        node_key: K,
        visited: &mut BTreeMap<K, bool>,
        reachable: &mut Vec<K>,
    ) {
        if visited.get(&node_key) == Some(&true) {
            return;
        }
        visited.insert(node_key, true);
        reachable.push(node_key);

        // Find all nodes that have edges TO this node using reverse index
        if let Some(sources) = self.incoming_edges.get(&node_key) {
            for &source in sources {
                self.dfs_reachability(source, visited, reachable);
            }
        }
    }

    /// Find all strongly connected components in the graph.
    ///
    /// This method implements Tarjan's algorithm to find all strongly
    /// connected components (SCCs) in the graph. An SCC is a maximal
    /// subgraph where every node is reachable from every other node.
    ///
    /// The result is returned in topological order, with SCCs that
    /// have no incoming edges appearing first. This ordering is
    /// useful for processing the graph in dependency order while
    /// handling cycles gracefully.
    ///
    /// # Algorithm Overview (Tarjan's SCC)
    ///
    /// Tarjan's algorithm uses depth-first search with a stack to identify SCCs.
    /// For each node, we maintain:
    /// - `index`: DFS discovery time (when the node is first visited)
    /// - `lowlink`: Smallest index of any node reachable from this node that is on the stack
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and E is the number of edges
    /// - Best Case: O(V + E) - Tarjan's algorithm always visits each node and edge once
    /// - Average Case: O(V + E) - Optimal for finding all SCCs
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the stack, visited arrays, and recursion depth
    ///
    /// ## Pseudocode:
    /// ```text
    /// function find_sccs(graph):
    ///     index = 0
    ///     stack = []
    ///     components = []
    ///     for each node in graph:
    ///         if node.index is undefined:
    ///             strong_connect(node, index, stack, components)
    ///     return sort_topologically(components)
    ///
    /// function strong_connect(node, index, stack, components):
    ///     node.index = index
    ///     node.lowlink = index
    ///     index = index + 1
    ///     stack.push(node)
    ///     node.on_stack = true
    ///
    ///     for each neighbor of node:
    ///         if neighbor.index is undefined:
    ///             strong_connect(neighbor, index, stack, components)
    ///             node.lowlink = min(node.lowlink, neighbor.lowlink)
    ///         else if neighbor.on_stack:
    ///             node.lowlink = min(node.lowlink, neighbor.index)
    ///
    ///     if node.lowlink == node.index:
    ///         component = []
    ///         do:
    ///             neighbor = stack.pop()
    ///             neighbor.on_stack = false
    ///             component.push(neighbor)
    ///         while neighbor != node
    ///         components.push(component)
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// let mut graph = Graph::<&str, DepType>::new();
    ///
    /// // Build a graph with cycles: A -> B -> C -> A, D -> E -> D
    /// graph.add_dependency("A", "B", DepType::Type);
    /// graph.add_dependency("B", "C", DepType::Value);
    /// graph.add_dependency("C", "A", DepType::Type);  // Creates cycle A -> B -> C -> A
    /// graph.add_dependency("D", "E", DepType::Type);
    /// graph.add_dependency("E", "D", DepType::Type);  // Creates cycle D -> E -> D
    ///
    /// // Find all strongly connected components
    /// let sccs = graph.find_sccs();
    /// assert_eq!(sccs.len(), 2);  // Two SCCs
    ///
    /// // First SCC should contain the A -> B -> C -> A cycle
    /// let first_scc = &sccs[0];
    /// assert_eq!(first_scc.len(), 3);
    /// assert!(first_scc.contains(&"A"));
    /// assert!(first_scc.contains(&"B"));
    /// assert!(first_scc.contains(&"C"));
    ///
    /// // Second SCC should contain the D -> E -> D cycle
    /// let second_scc = &sccs[1];
    /// assert_eq!(second_scc.len(), 2);
    /// assert!(second_scc.contains(&"D"));
    /// assert!(second_scc.contains(&"E"));
    ///
    /// // Test with a DAG (no cycles)
    /// let mut dag = Graph::<&str, DepType>::new();
    /// dag.add_dependency("X", "Y", DepType::Type);
    /// dag.add_dependency("Y", "Z", DepType::Value);
    ///
    /// let sccs = dag.find_sccs();
    /// assert_eq!(sccs.len(), 3);  // Each node is its own SCC in a DAG
    /// ```
    fn find_sccs(&self) -> Vec<Vec<K>> {
        if self.nodes.is_empty() {
            return Vec::new();
        }

        let mut components = Vec::new();
        let mut stack = Vec::new();
        let mut indices = vec![None; self.nodes.len()];
        let mut lowlinks = vec![0; self.nodes.len()];
        let mut on_stack = vec![false; self.nodes.len()];
        let mut current_index = 0;

        for start_idx in 0..self.nodes.len() {
            if indices[start_idx].is_none() {
                self.strong_connect(
                    start_idx,
                    &mut current_index,
                    &mut indices,
                    &mut lowlinks,
                    &mut on_stack,
                    &mut stack,
                    &mut components,
                );
            }
        }

        // Sort components by topological order and convert to keys
        self.sort_sccs_topologically(&components)
            .into_iter()
            .map(|component| {
                component
                    .into_iter()
                    .filter_map(|idx| self.nodes.get_index(idx).map(|(k, _)| *k))
                    .collect()
            })
            .collect()
    }

    /// Core implementation of Tarjan's algorithm for finding SCCs.
    ///
    /// This method recursively explores the graph, maintaining a stack
    /// of nodes and computing lowlink values to identify SCCs. The
    /// lowlink of a node is the smallest index of any node reachable
    /// from it that is on the current stack.
    ///
    /// ## Algorithm Details:
    ///
    /// 1. Discovery Phase: Assign a unique index to each node as it's discovered
    /// 2. Lowlink Computation: Track the lowest index reachable from each node
    /// 3. SCC Detection: When a node's lowlink equals its index, we've found an SCC root
    /// 4. Component Extraction: Pop nodes from the stack until we reach the root
    ///
    /// The key insight is that a node is the root of an SCC if and only if its lowlink
    /// equals its discovery index. This happens when the node can't reach any node with
    /// a lower index that's still on the stack.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) - each node and edge is processed at most once
    /// - Best Case: O(V + E) - optimal for finding all SCCs
    /// - Average Case: O(V + E) - consistent performance regardless of graph structure
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the recursion stack and auxiliary arrays
    fn strong_connect(
        &self,
        node_idx: usize,
        current_index: &mut usize,
        indices: &mut [Option<usize>],
        lowlinks: &mut [usize],
        on_stack: &mut [bool],
        stack: &mut Vec<usize>,
        components: &mut Vec<Vec<usize>>,
    ) {
        // Step 1: Assign discovery index and initialize lowlink
        indices[node_idx] = Some(*current_index);
        lowlinks[node_idx] = *current_index;
        *current_index = current_index.saturating_add(1);

        // Step 2: Push onto stack and mark as on-stack
        stack.push(node_idx);
        on_stack[node_idx] = true;

        // Step 3: Explore all neighbors recursively
        let edges = &self.nodes.get_index(node_idx).unwrap().1.edges;
        for edge in edges {
            let target_idx = self.nodes.get_index_of(&edge.target).unwrap();

            if indices[target_idx].is_none() {
                // Neighbor not yet discovered - recurse
                self.strong_connect(
                    target_idx,
                    current_index,
                    indices,
                    lowlinks,
                    on_stack,
                    stack,
                    components,
                );
                // Update lowlink based on neighbor's lowlink
                lowlinks[node_idx] = lowlinks[node_idx].min(lowlinks[target_idx]);
            } else if on_stack[target_idx] {
                // Neighbor is on stack - this is a back edge
                // Update lowlink to the neighbor's discovery index
                let target_discovery_idx = indices[target_idx].unwrap();
                lowlinks[node_idx] = lowlinks[node_idx].min(target_discovery_idx);
            }
            // If neighbor is visited but not on stack, ignore it
        }

        // Step 4: Check if this node is an SCC root
        if lowlinks[node_idx] == indices[node_idx].unwrap() {
            // We've found an SCC root - extract the component
            let mut component = Vec::new();
            let mut target_idx;

            // Pop nodes from stack until we reach the root
            loop {
                target_idx = stack.pop().unwrap();
                on_stack[target_idx] = false;
                component.push(target_idx);
                if target_idx == node_idx {
                    break;
                }
            }
            components.push(component);
        }
    }

    /// Sorts SCCs in topological order for dependency processing.
    ///
    /// This method creates a meta-graph where each node represents an SCC
    /// and edges represent dependencies between SCCs. It then performs
    /// a topological sort on this meta-graph to determine the order
    /// in which SCCs should be processed.
    ///
    /// # Algorithm Overview
    ///
    /// 1. Meta-graph Construction: Create a graph where each SCC is a node
    /// 2. Edge Mapping: Map edges between individual nodes to edges between SCCs
    /// 3. Topological Sort: Sort the meta-graph using DFS-based topological sort
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and E is the number of edges
    /// - Best Case: O(V + E) for sparse graphs with few cross-SCC edges
    /// - Average Case: O(V + E) due to efficient reverse edge lookup
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V + E) for the meta-graph and auxiliary data structures
    ///
    /// ## Pseudocode:
    /// ```text
    /// function sort_sccs_topologically(components):
    ///     # Step 1: Create meta-graph
    ///     scc_graph = []
    ///     scc_indices = {}
    ///
    ///     # Map nodes to their SCC indices
    ///     for each (scc_idx, component) in components:
    ///         for each node in component:
    ///             scc_indices[node] = scc_idx
    ///
    ///     # Build edges between SCCs efficiently using reverse edge index
    ///     for each (scc_idx, component) in components:
    ///         edges = []
    ///         for each node in component:
    ///             # Use reverse edge index to find incoming edges
    ///             for each source that has edge to node:
    ///                 source_scc = scc_indices[source]
    ///                 if source_scc != scc_idx:
    ///                     edges.push(source_scc)
    ///         scc_graph.push(edges)
    ///
    ///     # Step 2: Topological sort of meta-graph
    ///     return topological_sort(scc_graph)
    /// ```
    fn sort_sccs_topologically(&self, components: &[Vec<usize>]) -> Vec<Vec<usize>> {
        // Step 1: Create a graph where each node represents an SCC
        let mut scc_graph = Vec::new();
        let mut scc_indices = BTreeMap::new();

        // Map each node to its SCC index
        for (scc_idx, component) in components.iter().enumerate() {
            for &node_idx in component {
                scc_indices.insert(node_idx, scc_idx);
            }
        }

        // Step 2: Build edges between SCCs more efficiently using reverse edge index
        // Initialize SCC graph with empty edge lists
        scc_graph.resize(components.len(), Vec::new());

        // Use reverse edge index to find cross-SCC dependencies more efficiently
        for (scc_idx, component) in components.iter().enumerate() {
            for &node_idx in component {
                // Get the actual node key from the index
                let node_key = self.nodes.get_index(node_idx).unwrap().0;

                // Check incoming edges to this node (using reverse index)
                if let Some(sources) = self.incoming_edges.get(node_key) {
                    for &source in sources {
                        let source_idx = self.nodes.get_index_of(&source).unwrap();
                        let source_scc = scc_indices[&source_idx];

                        // Only add edges between different SCCs
                        if source_scc != scc_idx {
                            // Avoid duplicate edges between SCCs
                            if !scc_graph[source_scc].contains(&scc_idx) {
                                scc_graph[source_scc].push(scc_idx);
                            }
                        }
                    }
                }
            }
        }

        // Step 3: Topological sort of SCCs using DFS
        let mut sorted_sccs = Vec::new();
        let mut visited = vec![false; components.len()];
        let mut temp_visited = vec![false; components.len()];

        for scc_idx in 0..components.len() {
            if !visited[scc_idx] {
                self.topo_sort_sccs(
                    scc_idx,
                    &scc_graph,
                    &mut visited,
                    &mut temp_visited,
                    &mut sorted_sccs,
                );
            }
        }

        // Return components in topological order
        sorted_sccs
            .into_iter()
            .map(|scc_idx| components[scc_idx].clone())
            .collect()
    }

    /// Performs topological sort on the SCC meta-graph.
    ///
    /// This method uses depth-first search to sort SCCs in dependency
    /// order. It detects cycles in the meta-graph (which would indicate
    /// a bug in the SCC computation) and ensures proper ordering.
    ///
    /// ## Algorithm Details:
    ///
    /// This is a standard DFS-based topological sort with cycle detection.
    /// We use two visited arrays:
    /// - `visited`: Permanent marking for fully processed nodes
    /// - `temp_visited`: Temporary marking for nodes currently being processed
    ///
    /// If we encounter a node marked as `temp_visited`, we've found a cycle.
    /// However, this should never happen in a properly constructed meta-graph
    /// of SCCs, so it indicates a bug in our SCC computation.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of SCCs and E is the number of cross-SCC edges
    /// - Best Case: O(V + E) - DFS visits each SCC and edge once
    /// - Average Case: O(V + E) - consistent performance for meta-graphs
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V) for the visited arrays and recursion stack
    fn topo_sort_sccs(
        &self,
        scc_idx: usize,
        scc_graph: &[Vec<usize>],
        visited: &mut [bool],
        temp_visited: &mut [bool],
        sorted: &mut Vec<usize>,
    ) {
        // Cycle detection - this should never happen in SCC meta-graph
        if temp_visited[scc_idx] {
            // This should not happen in a DAG of SCCs
            return;
        }
        if visited[scc_idx] {
            return;
        }

        // Mark as temporarily visited (in current DFS path)
        temp_visited[scc_idx] = true;

        // Recursively visit all dependencies
        for &target_scc in &scc_graph[scc_idx] {
            self.topo_sort_sccs(target_scc, scc_graph, visited, temp_visited, sorted);
        }

        // Mark as permanently visited and add to sorted list
        temp_visited[scc_idx] = false;
        visited[scc_idx] = true;
        sorted.push(scc_idx);
    }

    /// Performs a topological sort of the dependencies.
    ///
    /// The result is a vector of nodes in dependency order,
    /// where each node appears after all of its dependencies.
    ///
    /// It fails fast when cycles are detected.
    ///
    /// ## Time Complexity
    /// - Worst Case: O(V + E) where V is the number of nodes and
    ///   E is the number of edges
    /// - Best Case: O(V + E) - DFS visits each node and edge once
    /// - Average Case: O(V + E) - optimal for topological sorting
    ///
    /// ## Space Complexity
    /// - Worst Case: O(V)
    ///
    /// ## Pseudocode:
    /// ```text
    /// function topological_sort(graph):
    ///     marks = {}  # Track node states
    ///     sorted = []
    ///     stack = []
    ///
    ///     for each node in graph:
    ///         if marks[node] != Visited:
    ///             stack.push((node, 0))
    ///
    ///             while stack not empty:
    ///                 (current, edge_idx) = stack.top()
    ///
    ///                 if edge_idx == 0:
    ///                     marks[current] = Visiting
    ///
    ///                 if edge_idx >= current.edges.length:
    ///                     # All edges processed
    ///                     marks[current] = Visited
    ///                     sorted.push(current)
    ///                     stack.pop()
    ///                 else:
    ///                     target = current.edges[edge_idx]
    ///                     edge_idx++
    ///
    ///                     if marks[target] == Unvisited:
    ///                         stack.push((target, 0))
    ///                     else if marks[target] == Visiting:
    ///                         # Cycle detected!
    ///                         return error
    ///                     # If Visited, continue to next edge
    ///
    ///     return sorted
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use aranya_policy_compiler::depgraph::Graph;
    /// use aranya_policy_compiler::depgraph::SortError;
    ///
    /// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    /// enum DepType { Type, Value }
    ///
    /// // Test with a valid DAG
    /// let mut graph = Graph::<&str, DepType>::new();
    /// graph.add_dependency("App", "Database", DepType::Type);
    /// graph.add_dependency("App", "Logger", DepType::Type);
    /// graph.add_dependency("Database", "Config", DepType::Value);
    /// graph.add_dependency("Logger", "Config", DepType::Value);
    ///
    /// let sorted = graph.topo_sort().unwrap();
    /// assert_eq!(sorted.len(), 4);
    ///
    /// // Config should come first (no dependencies)
    /// let config_idx = sorted.iter().position(|&id| id == "Config").unwrap();
    /// let db_idx = sorted.iter().position(|&id| id == "Database").unwrap();
    /// let logger_idx = sorted.iter().position(|&id| id == "Logger").unwrap();
    /// let app_idx = sorted.iter().position(|&id| id == "App").unwrap();
    ///
    /// assert!(config_idx < db_idx);      // Config before Database
    /// assert!(config_idx < logger_idx);  // Config before Logger
    /// assert!(db_idx < app_idx);         // Database before App
    /// assert!(logger_idx < app_idx);     // Logger before App
    ///
    /// // Test with a cycle (should fail)
    /// let mut cyclic_graph = Graph::<&str, DepType>::new();
    /// cyclic_graph.add_dependency("A", "B", DepType::Type);
    /// cyclic_graph.add_dependency("B", "C", DepType::Value);
    /// cyclic_graph.add_dependency("C", "A", DepType::Type);  // Creates cycle
    ///
    /// let result = cyclic_graph.topo_sort();
    /// assert!(result.is_err());
    /// match result {
    ///     Err(SortError::Cycle(cycle)) => {
    ///         // The cycle should contain A, B, C
    ///         assert!(cycle.cycle.contains(&"A"));
    ///         assert!(cycle.cycle.contains(&"B"));
    ///         assert!(cycle.cycle.contains(&"C"));
    ///     }
    ///     _ => panic!("Expected cycle error"),
    /// }
    /// ```
    pub fn topo_sort(&self) -> Result<Vec<K>, SortError<K>> {
        // # Algorithm Overview (DFS-based Topological Sort)
        //
        // The implementation uses an iterative DFS. Each node goes
        // through three states:
        // - `Unvisited`: Not yet processed
        // - `Visiting`: Currently being processed (on the DFS stack)
        // - `Visited`: Fully processed and added to result
        //
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

        let mut marks: BTreeMap<K, Mark> = BTreeMap::new();
        let mut sorted = Vec::with_capacity(self.nodes.len());

        // Stores (key, edge_idx) for iterative DFS
        let mut stack = Vec::new();

        // Process every node to handle disconnected graphs
        for (start_key, _) in &self.nodes {
            if marks.get(start_key) == Some(&Mark::Visited) {
                continue;
            }

            stack.push((*start_key, 0));

            while let Some((node_key, edge_idx)) = stack.last_mut() {
                let key = *node_key;
                if *edge_idx == 0 {
                    // First time visiting this node.
                    marks.insert(key, Mark::Visiting);
                }

                let node_data = &self.nodes[&key];
                if *edge_idx >= node_data.edges.len() {
                    // All dependencies have been processed.
                    marks.insert(key, Mark::Visited);
                    sorted.push(key);
                    stack.pop();
                    continue;
                }

                // Process next edge
                let target = node_data.edges[*edge_idx].target;
                *edge_idx = edge_idx.saturating_add(1);

                match marks.get(&target) {
                    Some(&Mark::Unvisited) | None => {
                        // Target not yet visited.
                        stack.push((target, 0));
                    }
                    Some(&Mark::Visiting) => {
                        // We're currently visiting this node, so
                        // we have a cycle.
                        let cycle = self.build_cycle_path(&stack, target);
                        return Err(Cycle { cycle }.into());
                    }
                    Some(&Mark::Visited) => {
                        // We've already visited this node.
                    }
                }
            }
        }

        Ok(sorted)
    }

    /// Builds a cycle path from the current stack when a cycle
    /// is detected.
    #[cold]
    fn build_cycle_path(&self, stack: &[(K, usize)], target_key: K) -> Vec<K> {
        stack
            .iter()
            .skip_while(|(key, _)| *key != target_key)
            .map(|(key, _)| *key)
            .chain(iter::once(target_key))
            .collect()
    }
}

// Debug implementation with minimal bounds
impl<K, D> fmt::Debug for Graph<K, D>
where
    K: fmt::Debug,
    D: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DependencyGraph {{")?;
        for (key, node) in &self.nodes {
            writeln!(f, "  {:?} ->", key)?;
            for edge in &node.edges {
                writeln!(f, "    {:?} ({:?})", edge.target, edge.kind)?;
            }
        }
        write!(f, "}}")
    }
}

/// A directed edge in the dependency graph.
///
/// Edges represent dependencies between nodes, where the
/// `target` node must be processed before the source node.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Edge<K, D> {
    /// The target node key
    target: K,
    /// Additional data that describes the kind of dependency.
    kind: D,
}

/// Node data in the dependency graph.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeData<K, D> {
    /// Outgoing edges (dependencies).
    edges: Vec<Edge<K, D>>,
    /// Fast lookup for edge targets to prevent duplicates.
    edge_targets: BTreeSet<K>,
}

/// Unable to sort the dependency graph.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum SortError<K> {
    /// An internal bug was discovered.
    #[error("bug: {0}")]
    Bug(#[from] Bug),
    /// A cycle was found in the graph.
    #[error("{0}")]
    Cycle(#[from] Cycle<K>),
}

/// Enhanced error types for dependency operations.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum DepGraphError<K> {
    /// An internal bug was discovered.
    #[error("bug: {0}")]
    Bug(#[from] Bug),
    /// A cycle was found in the graph.
    #[error("{0}")]
    Cycle(#[from] Cycle<K>),
    /// Invalid node reference.
    #[error("invalid node: {0:?}")]
    InvalidNode(K),
    /// Strongly connected components found (potential cycles).
    #[error("strongly connected components detected")]
    PotentialCycles(Vec<Vec<K>>),
}

/// A cycle in the dependency graph.
#[derive(Clone, Debug)]
pub(crate) struct Cycle<K> {
    cycle: Vec<K>,
}

impl<K> IntoIterator for Cycle<K> {
    type Item = K;
    type IntoIter = vec::IntoIter<K>;

    fn into_iter(self) -> Self::IntoIter {
        self.cycle.into_iter()
    }
}

impl<K> fmt::Display for Cycle<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dependency cycle detected")
    }
}

impl<K> error::Error for Cycle<K> where K: fmt::Debug {}

/// A cyclic dependency was detected in the dependency graph.
#[derive(Clone, Debug, thiserror::Error)]
#[error("cyclic dependency detected")]
pub(crate) struct CyclicDependencyError {
    /// The identifiers that form the cycle with their spans
    cycle: Vec<(ast::Identifier, Span)>,
}

impl<'a, G: EmissionGuarantee> Diagnostic<'a, G> for CyclicDependencyError {
    fn into_diag(self, ctx: &'a DiagCtx, severity: Severity) -> Diag<'a, G> {
        let mut msg = String::from("cyclic dependency: ");
        for (i, (identifier, _)) in self.cycle.iter().enumerate() {
            if i > 0 {
                msg.push_str(" -> ");
            }
            write!(&mut msg, "\"{}\"", identifier).unwrap();
        }

        let diag = Diag::new(ctx, severity, msg);

        let mut multi_span = MultiSpan::new();
        for (identifier, span) in self.cycle {
            let label = format!("part of cyclic dependency: {}", identifier);
            multi_span.push_label(span, label);
        }

        diag.with_span(multi_span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum TestDep {
        Type,
    }

    #[test]
    fn test_simple_graph() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A -> B -> C
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);

        let sorted = graph.topo_sort().unwrap();
        assert_eq!(sorted, vec!["C", "B", "A"]);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A -> B -> C -> A (cycle)
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);
        graph.add_dependency("C", "A", TestDep::Type);

        let err = match graph.topo_sort().unwrap_err() {
            SortError::Cycle(err) => err,
            SortError::Bug(bug) => panic!("unexpected err: {bug:?}"),
        };
        // The cycle should have 4 elements: A -> B -> C -> A
        assert_eq!(err.cycle.len(), 4);
    }

    #[test]
    fn test_complex_graph() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Multiple dependencies
        graph.add_dependency("App", "Database", TestDep::Type);
        graph.add_dependency("App", "Logger", TestDep::Type);
        graph.add_dependency("Database", "Config", TestDep::Type);
        graph.add_dependency("Logger", "Config", TestDep::Type);

        let sorted = graph.topo_sort().unwrap();

        // Config should come before both Database and Logger
        let config_idx = sorted.iter().position(|id| id == &"Config").unwrap();
        let db_idx = sorted.iter().position(|id| id == &"Database").unwrap();
        let logger_idx = sorted.iter().position(|id| id == &"Logger").unwrap();
        let app_idx = sorted.iter().position(|id| id == &"App").unwrap();

        assert!(config_idx < db_idx);
        assert!(config_idx < logger_idx);
        assert!(db_idx < app_idx);
        assert!(logger_idx < app_idx);
    }

    #[test]
    fn test_disconnected_graph() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Two disconnected components: (A -> B) and (C -> D)
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("C", "D", TestDep::Type);

        let sorted = graph.topo_sort().unwrap();
        assert_eq!(sorted.len(), 4);

        // Check ordering within components
        let a_idx = sorted.iter().position(|id| id == &"A").unwrap();
        let b_idx = sorted.iter().position(|id| id == &"B").unwrap();
        let c_idx = sorted.iter().position(|id| id == &"C").unwrap();
        let d_idx = sorted.iter().position(|id| id == &"D").unwrap();

        assert!(b_idx < a_idx); // B comes before A
        assert!(d_idx < c_idx); // D comes before C
    }

    #[test]
    fn test_self_dependency() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A depends on itself
        graph.add_dependency("A", "A", TestDep::Type);

        let err = match graph.topo_sort().unwrap_err() {
            SortError::Cycle(err) => err,
            SortError::Bug(bug) => panic!("unexpected err: {bug:?}"),
        };
        // Check that the cycle contains A by verifying one of
        // the nodes in the cycle maps back to "A"
        let contains_a = err.cycle.iter().any(|&id| id == "A");
        assert!(contains_a);
    }

    #[test]
    fn test_strongly_connected_components() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Create a graph with SCCs: (A -> B -> C -> A) and (D -> E -> D)
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);
        graph.add_dependency("C", "A", TestDep::Type);
        graph.add_dependency("D", "E", TestDep::Type);
        graph.add_dependency("E", "D", TestDep::Type);

        let sccs = graph.find_sccs();
        assert_eq!(sccs.len(), 2);

        // Check that each SCC contains the expected nodes
        let mut found_a_cycle = false;
        let mut found_d_cycle = false;

        for scc in &sccs {
            let keys: Vec<_> = scc.iter().cloned().collect();

            if keys.contains(&"A") && keys.contains(&"B") && keys.contains(&"C") {
                found_a_cycle = true;
                assert_eq!(keys.len(), 3);
            } else if keys.contains(&"D") && keys.contains(&"E") {
                found_d_cycle = true;
                assert_eq!(keys.len(), 2);
            }
        }

        assert!(found_a_cycle);
        assert!(found_d_cycle);
    }

    #[test]
    fn test_reachability_queries() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A -> B -> C
        // D -> B
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);
        graph.add_dependency("D", "B", TestDep::Type);

        // Find what can reach C
        let reachable = graph.find_reachability("C");
        assert_eq!(reachable.len(), 3);
        assert!(reachable.contains(&"A"));
        assert!(reachable.contains(&"B"));
        assert!(reachable.contains(&"D"));

        // Find what A can reach
        let dependents = graph.find_dependents("A");
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&"B"));
        assert!(dependents.contains(&"C"));
    }

    #[test]
    fn test_dependency_closure() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A -> B -> C
        // D -> B
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);
        graph.add_dependency("D", "B", TestDep::Type);

        // C's dependency closure should include A, B, and D
        let closure = graph.dependency_closure("C");
        assert_eq!(closure.len(), 3);
        assert!(closure.contains(&"A"));
        assert!(closure.contains(&"B"));
        assert!(closure.contains(&"D"));

        // B's dependency closure should include A and D
        let closure = graph.dependency_closure("B");
        assert_eq!(closure.len(), 2);
        assert!(closure.contains(&"A"));
        assert!(closure.contains(&"D"));
    }

    #[test]
    fn test_dependency_path() {
        let mut graph = Graph::<&str, TestDep>::new();

        // A -> B -> C
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);

        // A should have a path to C
        assert!(graph.has_dependency_path("A", "C"));

        // C should not have a path to A
        assert!(!graph.has_dependency_path("C", "A"));

        // A should have a path to itself
        assert!(graph.has_dependency_path("A", "A"));
    }

    #[test]
    fn test_disconnected_components() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Two disconnected components: (A -> B) and (C -> D)
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("C", "D", TestDep::Type);

        let sccs = graph.find_sccs();
        // Each node is its own SCC in a DAG
        assert_eq!(sccs.len(), 4);

        // No path between disconnected components
        assert!(!graph.has_dependency_path("A", "C"));
        assert!(!graph.has_dependency_path("B", "D"));
    }

    #[test]
    fn test_cyclic_dependency_detection() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Create a cycle: A -> B -> C -> A
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "C", TestDep::Type);
        graph.add_dependency("C", "A", TestDep::Type);

        let sccs = graph.find_sccs();
        // One SCC containing the cycle
        assert_eq!(sccs.len(), 1);

        // The SCC should contain all three nodes
        let cycle = &sccs[0];
        assert_eq!(cycle.len(), 3);
        assert!(cycle.contains(&"A"));
        assert!(cycle.contains(&"B"));
        assert!(cycle.contains(&"C"));
    }

    #[test]
    fn test_multiple_cycles() {
        let mut graph = Graph::<&str, TestDep>::new();

        // Create two cycles: A -> B -> A and C -> D -> C
        graph.add_dependency("A", "B", TestDep::Type);
        graph.add_dependency("B", "A", TestDep::Type);
        graph.add_dependency("C", "D", TestDep::Type);
        graph.add_dependency("D", "C", TestDep::Type);

        let sccs = graph.find_sccs();
        // Two SCCs, each containing a cycle
        assert_eq!(sccs.len(), 2);

        // Each SCC should contain 2 nodes
        for scc in &sccs {
            assert_eq!(scc.len(), 2);
        }
    }
}
