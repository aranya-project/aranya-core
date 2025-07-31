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

#[derive(Debug, Clone, PartialEq)]
enum Item<'a> {
    GlobalLet(&'a AstNode<ast::GlobalLetStatement>),
    Fact(&'a AstNode<FactDefinition>),
    Action(&'a AstNode<ast::ActionDefinition>),
    Effect(&'a AstNode<ast::EffectDefinition>),
    Struct(&'a AstNode<ast::StructDefinition>),
    Enum(&'a AstNode<EnumDefinition>),
    Command(&'a AstNode<ast::CommandDefinition>),
    Function(&'a AstNode<ast::FunctionDefinition>),
    FinishFunction(&'a AstNode<ast::FinishFunctionDefinition>),
    FfiStruct(&'a ffi::Struct<'a>),
    FfiFunc(&'a ffi::Func<'a>),
    FfiEnum(&'a ffi::Enum<'a>),
}

impl Item<'_> {
    fn ident(&self) -> Identifier {
        match self {
            Item::GlobalLet(v) => v.identifier.clone(),
            Item::Fact(v) => v.identifier.clone(),
            Item::Action(v) => v.identifier.clone(),
            Item::Effect(v) => v.identifier.clone(),
            Item::Struct(v) => v.identifier.clone(),
            Item::Enum(v) => v.identifier.clone(),
            Item::Command(v) => v.identifier.clone(),
            Item::Function(v) => v.identifier.clone(),
            Item::FinishFunction(v) => v.identifier.clone(),
            Item::FfiStruct(v) => v.name.clone(),
            Item::FfiFunc(v) => v.name.clone(),
            Item::FfiEnum(v) => v.name.clone(),
        }
    }
}

type Items<'a> = BTreeMap<Identifier, Item<'a>>;

fn collect_items<'a>(ast: &'a AstPolicy, schema: &'a [ModuleSchema<'a>]) -> Items<'a> {
    ast.facts
        .iter()
        .map(Item::Fact)
        .chain(ast.global_lets.iter().map(Item::GlobalLet))
        .chain(ast.actions.iter().map(Item::Action))
        .chain(ast.effects.iter().map(Item::Effect))
        .chain(ast.structs.iter().map(Item::Struct))
        .chain(ast.enums.iter().map(Item::Enum))
        .chain(ast.commands.iter().map(Item::Command))
        .chain(ast.functions.iter().map(Item::Function))
        .chain(ast.finish_functions.iter().map(Item::FinishFunction))
        .chain(schema.iter().flat_map(|m| {
            m.structs
                .iter()
                .map(|s| Item::FfiStruct(s))
                .chain(m.functions.iter().map(|f| Item::FfiFunc(f)))
                .chain(m.enums.iter().map(|e| Item::FfiEnum(e)))
        }))
        .map(|item| {
            let ident = item.ident();
            (ident, item)
        })
        .collect()
}

fn topo_sort(graph: &DependencyGraph<Identifier>) -> Result<Vec<Identifier>, CompileError> {
    match graph.topo_sort() {
        Ok(sorted) => {
            let keys = graph
                .get_disjoint(sorted)
                .map(|r| r.cloned())
                .collect::<Result<_, _>>()?;
            Ok(keys)
        }
        Err(SortError::Bug(err)) => Err(err.into()),
        Err(SortError::Cycle(cycle)) => {
            let path = graph
                .get_disjoint(cycle)
                .map(|r| r.cloned())
                .collect::<Result<_, _>>()?;
            Err(CompileError::new(CompileErrorType::RecursiveDefinition(
                path,
            )))
        }
    }
}

/// Builds a dependency graph with all of the items from the AST
/// and FFI modules.
fn build_dependency_graph(items: &Items<'_>) -> Result<DependencyGraph<Identifier>, CompileError> {
    let mut graph = DependencyGraph::new();

    // Add all nodes first
    for (node, _) in items {
        graph.add_node(node.clone());
    }

    // Add edges with appropriate dependency kinds
    for (node, item) in items {
        let edges = Edges::new(item);
        for (target, kind) in edges {
            // println!("kind = {kind:?}, target = {target}");
            // if kind == DependencyKind::Global {
            //     let Some(item) = items.get(&target) else {
            //         // Either this is a variable identifier or it
            //         // refers to a global dependency that does
            //         // not exist.
            //         println!("var ident");
            //         continue;
            //     };
            //     println!("item = {item:?}");
            //     if !matches!(item, Item::GlobalLet(_)) {
            //         return Err(CompileError::new(CompileErrorType::AlreadyDefined(
            //             target.to_string(),
            //         )));
            //     }
            // }
            if &target == node {
                // Self-reference
                return Err(CompileError::new(CompileErrorType::RecursiveDefinition(
                    vec![node.clone()],
                )));
            }
            if !items.contains_key(&target) {
                println!("items does not contain {target}");
                return Err(CompileError::new(CompileErrorType::NotDefined(
                    target.to_string(),
                )));
            }
            graph.add_dependency(node.clone(), target, kind);
        }
    }

    Ok(graph)
}

#[derive(Clone, Debug)]
struct Edges {
    edges: Vec<(Identifier, DependencyKind)>,
}

impl Edges {
    fn new(item: &Item<'_>) -> Self {
        let mut edges = Self { edges: Vec::new() };
        edges.walk_item(item);
        edges
    }

    /// Adds a definitive edge from the [`Item`] to `target`.
    fn add_edge(&mut self, target: Identifier, kind: DependencyKind) {
        self.edges.push((target, kind));
    }

    fn walk_item(&mut self, item: &Item<'_>) {
        match item {
            Item::GlobalLet(v) => {
                self.walk_expr(&v.expression);
            }
            Item::Fact(v) => {
                for field in v.key.iter().chain(v.value.iter()) {
                    self.walk_vtype(&field.field_type);
                }
            }
            Item::Action(v) => self.walk_stmts(&v.statements),
            Item::Effect(v) => {
                for item in &v.items {
                    match item {
                        StructItem::Field(f) => self.walk_vtype(&f.field_type),
                        StructItem::StructRef(s) => {
                            self.add_edge(s.clone(), DependencyKind::StructComposition)
                        }
                    }
                }
            }
            Item::Struct(v) => {
                for item in &v.items {
                    match item {
                        StructItem::Field(f) => self.walk_vtype(&f.field_type),
                        StructItem::StructRef(s) => {
                            self.add_edge(s.clone(), DependencyKind::StructComposition)
                        }
                    }
                }
            }
            Item::Enum(_) => {}
            Item::Command(v) => {
                for item in &v.fields {
                    match item {
                        StructItem::Field(f) => self.walk_vtype(&f.field_type),
                        StructItem::StructRef(s) => {
                            self.add_edge(s.clone(), DependencyKind::StructComposition)
                        }
                    }
                }
                self.walk_stmts(&v.policy);
                self.walk_stmts(&v.recall);
                self.walk_stmts(&v.seal);
                self.walk_stmts(&v.open);
            }
            Item::Function(v) => {
                for arg in &v.arguments {
                    self.walk_vtype(&arg.field_type);
                }
                self.walk_vtype(&v.return_type);
                self.walk_stmts(&v.statements);
            }
            Item::FinishFunction(v) => {
                for arg in &v.arguments {
                    self.walk_vtype(&arg.field_type);
                }
                self.walk_stmts(&v.statements);
            }
            Item::FfiStruct(_) | Item::FfiFunc(_) | Item::FfiEnum(_) => {}
        }
    }

    fn walk_vtype(&mut self, vtype: &VType) {
        match vtype {
            VType::Struct(name) | VType::Enum(name) => {
                self.add_edge(name.clone(), DependencyKind::Type);
            }
            VType::Optional(inner) => self.walk_vtype(inner),
            VType::String | VType::Bytes | VType::Int | VType::Bool | VType::Id => {
                // Primitive types have no dependencies
            }
        }
    }

    fn walk_expr(&mut self, expr: &Expression) {
        println!("expr = {expr:?}");
        match expr {
            Expression::NamedStruct(s) => self.add_edge(s.identifier.clone(), DependencyKind::Type),
            Expression::FunctionCall(f) => {
                self.add_edge(f.identifier.clone(), DependencyKind::FunctionCall)
            }
            Expression::EnumReference(e) => {
                self.add_edge(e.identifier.clone(), DependencyKind::EnumReference)
            }
            Expression::InternalFunction(f) => match f {
                ast::InternalFunction::Query(fact)
                | ast::InternalFunction::Exists(fact)
                | ast::InternalFunction::FactCount(_, _, fact) => {
                    self.add_edge(fact.identifier.clone(), DependencyKind::FactReference);
                }
                ast::InternalFunction::If(a, b, c) => {
                    self.walk_expr(a);
                    self.walk_expr(b);
                    self.walk_expr(c);
                }
                ast::InternalFunction::Serialize(e) | ast::InternalFunction::Deserialize(e) => {
                    self.walk_expr(e)
                }
            },
            Expression::Optional(opt) => {
                if let Some(e) = opt {
                    self.walk_expr(e);
                }
            }
            Expression::Add(a, b)
            | Expression::Subtract(a, b)
            | Expression::And(a, b)
            | Expression::Or(a, b)
            | Expression::Equal(a, b)
            | Expression::NotEqual(a, b)
            | Expression::GreaterThan(a, b)
            | Expression::LessThan(a, b)
            | Expression::GreaterThanOrEqual(a, b)
            | Expression::LessThanOrEqual(a, b) => {
                self.walk_expr(a);
                self.walk_expr(b);
            }
            Expression::Dot(e, _) => self.walk_expr(e),
            Expression::Substruct(e, substruct_id) => {
                self.walk_expr(e);
                self.add_edge(substruct_id.clone(), DependencyKind::SubstructTarget);
            }
            Expression::Negative(e)
            | Expression::Not(e)
            | Expression::Unwrap(e)
            | Expression::CheckUnwrap(e)
            | Expression::Is(e, _) => self.walk_expr(e),
            Expression::Block(stmts, e) => {
                self.walk_stmts(stmts);
                self.walk_expr(e);
            }
            Expression::Match(m) => {
                self.walk_expr(&m.scrutinee);
                for arm in &m.arms {
                    match &arm.inner.pattern {
                        MatchPattern::Values(values) => {
                            for value in values {
                                self.walk_expr(value);
                            }
                        }
                        MatchPattern::Default => {}
                    }
                    self.walk_expr(&arm.inner.expression);
                }
            }
            Expression::ForeignFunctionCall(f) => {
                for arg in &f.arguments {
                    self.walk_expr(arg);
                }
            }
            Expression::Identifier(x) => {
                println!("ident = {x}");
                self.add_edge(x.clone(), DependencyKind::Global);
            }
            Expression::Int(_) | Expression::String(_) | Expression::Bool(_) => {
                // Literals have no dependencies.
            }
        }
    }

    fn walk_stmts(&mut self, stmts: &[AstNode<ast::Statement>]) {
        for stmt in stmts {
            self.walk_stmt(stmt);
        }
    }

    fn walk_stmt(&mut self, stmt: &AstNode<ast::Statement>) {
        match &stmt.inner {
            ast::Statement::Let(s) => self.walk_expr(&s.expression),
            ast::Statement::Check(s) => self.walk_expr(&s.expression),
            ast::Statement::Match(m) => {
                self.walk_expr(&m.expression);
                for arm in &m.arms {
                    match &arm.pattern {
                        MatchPattern::Values(values) => {
                            for value in values {
                                self.walk_expr(value);
                            }
                        }
                        MatchPattern::Default => {}
                    }
                    self.walk_stmts(&arm.statements);
                }
            }
            ast::Statement::If(s) => {
                for (cond, branch) in &s.branches {
                    self.walk_expr(cond);
                    self.walk_stmts(branch);
                }
                if let Some(fallback) = &s.fallback {
                    self.walk_stmts(fallback);
                }
            }
            ast::Statement::Publish(e) | ast::Statement::Emit(e) => self.walk_expr(e),
            ast::Statement::Return(r) => self.walk_expr(&r.expression),
            ast::Statement::Finish(stmts) => self.walk_stmts(stmts),
            ast::Statement::Map(m) => {
                self.add_edge(m.fact.identifier.clone(), DependencyKind::FactReference);
                self.walk_stmts(&m.statements);
            }
            ast::Statement::Create(c) => {
                self.add_edge(c.fact.identifier.clone(), DependencyKind::FactReference);
            }
            ast::Statement::Delete(d) => {
                self.add_edge(d.fact.identifier.clone(), DependencyKind::FactReference);
            }
            ast::Statement::Update(u) => {
                self.add_edge(u.fact.identifier.clone(), DependencyKind::FactReference);
                for (_, field) in &u.to {
                    if let FactField::Expression(expr) = field {
                        self.walk_expr(expr);
                    }
                }
            }
            ast::Statement::FunctionCall(f) => {
                self.add_edge(f.identifier.clone(), DependencyKind::FunctionCall)
            }
            ast::Statement::ActionCall(a) => {
                self.add_edge(a.identifier.clone(), DependencyKind::ActionCall)
            }
            ast::Statement::DebugAssert(e) => self.walk_expr(e),
        }
    }
}

impl IntoIterator for Edges {
    type Item = (Identifier, DependencyKind);
    type IntoIter = vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.edges.into_iter()
    }
}
