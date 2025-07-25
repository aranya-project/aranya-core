//! Dependency analysis for detecting recursion and circular dependencies.

use std::collections::{HashMap, HashSet};
use aranya_policy_ast::Identifier;
use crate::ir::*;

#[cfg(test)]
mod tests;

/// Dependency analyzer for detecting cycles.
pub struct DependencyAnalyzer<'a> {
    ir: &'a IR,
    graph: DependencyGraph,
}

/// A graph of dependencies between functions and globals.
#[derive(Debug)]
struct DependencyGraph {
    /// Nodes in the graph.
    nodes: HashSet<DependencyNode>,
    
    /// Edges from node to its dependencies.
    edges: HashMap<DependencyNode, HashSet<DependencyNode>>,
}

/// A node in the dependency graph.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum DependencyNode {
    Function(Identifier),
    Global(Identifier),
}

/// Types of dependency errors.
#[derive(Debug, Clone)]
pub enum DependencyError {
    /// Direct function recursion.
    DirectRecursion {
        function: Identifier,
        call_sites: Vec<Location>,
    },
    
    /// Mutual recursion between functions.
    MutualRecursion {
        cycle: Vec<Identifier>,
        participants: HashMap<Identifier, Vec<Location>>,
    },
    
    /// Circular dependency in global initialization.
    CircularGlobals {
        cycle: Vec<Identifier>,
    },
    
    /// Complex cycle involving both functions and globals.
    ComplexCycle {
        nodes: Vec<DependencyNode>,
    },
}

/// Strongly connected component.
#[derive(Debug)]
struct SCC {
    nodes: Vec<DependencyNode>,
}

impl<'a> DependencyAnalyzer<'a> {
    /// Create a new dependency analyzer.
    pub fn new(ir: &'a IR) -> Self {
        Self {
            ir,
            graph: DependencyGraph::new(),
        }
    }
    
    /// Analyze dependencies and detect cycles.
    pub fn analyze(mut self) -> Result<(), Vec<DependencyError>> {
        // Build dependency graph
        self.build_graph();
        
        // Find strongly connected components
        let sccs = self.find_sccs();
        
        // Analyze each SCC for cycles
        let mut errors = Vec::new();
        
        for scc in sccs {
            if scc.nodes.len() > 1 || self.has_self_edge(&scc.nodes[0]) {
                // Found a cycle
                if let Some(error) = self.analyze_cycle(&scc) {
                    errors.push(error);
                }
            }
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    /// Build the dependency graph.
    fn build_graph(&mut self) {
        // Add function dependencies
        for (name, function) in &self.ir.functions {
            let from_node = DependencyNode::Function(name.clone());
            self.graph.nodes.insert(from_node.clone());
            
            // Analyze function body for dependencies
            self.analyze_function_dependencies(name, function);
        }
        
        // Add global dependencies
        for (name, global) in &self.ir.globals {
            let from_node = DependencyNode::Global(name.clone());
            self.graph.nodes.insert(from_node.clone());
            
            // Analyze initializer for dependencies
            self.analyze_initializer_dependencies(name, &global.initializer);
        }
    }
    
    /// Analyze dependencies in a function.
    fn analyze_function_dependencies(&mut self, func_name: &Identifier, function: &Function) {
        let from_node = DependencyNode::Function(func_name.clone());
        
        // Analyze all blocks
        for block in function.cfg.blocks.values() {
            // Check instructions
            for instruction in &block.instructions {
                self.analyze_instruction_dependencies(&from_node, instruction);
            }
            
            // Check terminator
            self.analyze_terminator_dependencies(&from_node, &block.terminator);
        }
    }
    
    /// Analyze dependencies in an instruction.
    fn analyze_instruction_dependencies(&mut self, from_node: &DependencyNode, instruction: &Instruction) {
        match instruction {
            Instruction::Call { target, .. } => {
                if let CallTarget::Function(callee) = target {
                    let to_node = DependencyNode::Function(callee.clone());
                    self.graph.add_edge(from_node.clone(), to_node);
                }
            }
            
            Instruction::FieldAccess { object, .. } |
            Instruction::Publish { command: object } => {
                self.analyze_value_dependencies(from_node, object);
            }
            
            Instruction::BinaryOp { left, right, .. } => {
                self.analyze_value_dependencies(from_node, left);
                self.analyze_value_dependencies(from_node, right);
            }
            
            Instruction::UnaryOp { operand, .. } => {
                self.analyze_value_dependencies(from_node, operand);
            }
            
            Instruction::StructNew { fields, .. } => {
                for (_, value) in fields {
                    self.analyze_value_dependencies(from_node, value);
                }
            }
            
            Instruction::QueryFact { key_constraints, value_constraints, .. } |
            Instruction::CreateFact { key_fields: key_constraints, value_fields: value_constraints, .. } => {
                for (_, value) in key_constraints.iter().chain(value_constraints) {
                    self.analyze_value_dependencies(from_node, value);
                }
            }
            
            _ => {}
        }
    }
    
    /// Analyze dependencies in a value.
    fn analyze_value_dependencies(&mut self, from_node: &DependencyNode, value: &Value) {
        if let Value::GlobalRef(global) = value {
            let to_node = DependencyNode::Global(global.clone());
            self.graph.add_edge(from_node.clone(), to_node);
        }
    }
    
    /// Analyze dependencies in a terminator.
    fn analyze_terminator_dependencies(&mut self, from_node: &DependencyNode, terminator: &Terminator) {
        match terminator {
            Terminator::Return(Some(value)) => {
                self.analyze_value_dependencies(from_node, value);
            }
            
            Terminator::Jump { args, .. } => {
                for arg in args {
                    self.analyze_value_dependencies(from_node, arg);
                }
            }
            
            Terminator::Branch { condition, true_args, false_args, .. } => {
                self.analyze_value_dependencies(from_node, condition);
                for arg in true_args.iter().chain(false_args) {
                    self.analyze_value_dependencies(from_node, arg);
                }
            }
            
            Terminator::Switch { scrutinee, cases, default } => {
                self.analyze_value_dependencies(from_node, scrutinee);
                for case in cases {
                    for arg in &case.args {
                        self.analyze_value_dependencies(from_node, arg);
                    }
                }
                if let Some((_, args)) = default {
                    for arg in args {
                        self.analyze_value_dependencies(from_node, arg);
                    }
                }
            }
            
            _ => {}
        }
    }
    
    /// Analyze dependencies in an initializer.
    fn analyze_initializer_dependencies(&mut self, global_name: &Identifier, initializer: &InitializerExpr) {
        let from_node = DependencyNode::Global(global_name.clone());
        
        match initializer {
            InitializerExpr::GlobalRef(other_global) => {
                let to_node = DependencyNode::Global(other_global.clone());
                self.graph.add_edge(from_node, to_node);
            }
            
            InitializerExpr::Call { func, args } => {
                let to_node = DependencyNode::Function(func.clone());
                self.graph.add_edge(from_node.clone(), to_node);
                
                for arg in args {
                    self.analyze_initializer_dependencies(global_name, arg);
                }
            }
            
            InitializerExpr::Struct { fields, .. } => {
                for (_, field_init) in fields {
                    self.analyze_initializer_dependencies(global_name, field_init);
                }
            }
            
            InitializerExpr::Const(_) => {}
        }
    }
    
    /// Find strongly connected components using Tarjan's algorithm.
    fn find_sccs(&self) -> Vec<SCC> {
        let mut index_counter = 0;
        let mut stack = Vec::new();
        let mut lowlinks = HashMap::new();
        let mut index = HashMap::new();
        let mut on_stack = HashSet::new();
        let mut sccs = Vec::new();
        
        for node in &self.graph.nodes {
            if !index.contains_key(node) {
                self.tarjan_visit(
                    node,
                    &mut index_counter,
                    &mut stack,
                    &mut lowlinks,
                    &mut index,
                    &mut on_stack,
                    &mut sccs,
                );
            }
        }
        
        sccs
    }
    
    /// Tarjan's algorithm visit.
    fn tarjan_visit(
        &self,
        node: &DependencyNode,
        index_counter: &mut usize,
        stack: &mut Vec<DependencyNode>,
        lowlinks: &mut HashMap<DependencyNode, usize>,
        index: &mut HashMap<DependencyNode, usize>,
        on_stack: &mut HashSet<DependencyNode>,
        sccs: &mut Vec<SCC>,
    ) {
        index.insert(node.clone(), *index_counter);
        lowlinks.insert(node.clone(), *index_counter);
        *index_counter += 1;
        stack.push(node.clone());
        on_stack.insert(node.clone());
        
        if let Some(successors) = self.graph.edges.get(node) {
            for successor in successors {
                if !index.contains_key(successor) {
                    self.tarjan_visit(
                        successor,
                        index_counter,
                        stack,
                        lowlinks,
                        index,
                        on_stack,
                        sccs,
                    );
                    lowlinks.insert(
                        node.clone(),
                        lowlinks[node].min(lowlinks[successor]),
                    );
                } else if on_stack.contains(successor) {
                    lowlinks.insert(
                        node.clone(),
                        lowlinks[node].min(index[successor]),
                    );
                }
            }
        }
        
        if lowlinks[node] == index[node] {
            let mut scc_nodes = Vec::new();
            loop {
                let w = stack.pop().unwrap();
                on_stack.remove(&w);
                scc_nodes.push(w.clone());
                if w == *node {
                    break;
                }
            }
            sccs.push(SCC { nodes: scc_nodes });
        }
    }
    
    /// Check if a node has a self-edge.
    fn has_self_edge(&self, node: &DependencyNode) -> bool {
        self.graph.edges
            .get(node)
            .map(|deps| deps.contains(node))
            .unwrap_or(false)
    }
    
    /// Analyze a cycle and produce an error.
    fn analyze_cycle(&self, scc: &SCC) -> Option<DependencyError> {
        // Classify the cycle
        let functions: Vec<_> = scc.nodes.iter()
            .filter_map(|n| match n {
                DependencyNode::Function(f) => Some(f.clone()),
                _ => None,
            })
            .collect();
        
        let globals: Vec<_> = scc.nodes.iter()
            .filter_map(|n| match n {
                DependencyNode::Global(g) => Some(g.clone()),
                _ => None,
            })
            .collect();
        
        if !functions.is_empty() && globals.is_empty() {
            // Pure function recursion
            if functions.len() == 1 {
                Some(DependencyError::DirectRecursion {
                    function: functions[0].clone(),
                    call_sites: self.find_call_sites(&functions[0], &functions[0]),
                })
            } else {
                let mut participants = HashMap::new();
                for func in &functions {
                    participants.insert(
                        func.clone(),
                        self.find_recursive_call_sites(func, &functions),
                    );
                }
                Some(DependencyError::MutualRecursion {
                    cycle: functions,
                    participants,
                })
            }
        } else if functions.is_empty() && !globals.is_empty() {
            // Pure global circular dependency
            Some(DependencyError::CircularGlobals { cycle: globals })
        } else {
            // Mixed cycle
            Some(DependencyError::ComplexCycle {
                nodes: scc.nodes.clone(),
            })
        }
    }
    
    /// Find call sites where a function calls another.
    fn find_call_sites(&self, caller: &Identifier, callee: &Identifier) -> Vec<Location> {
        let mut locations = Vec::new();
        
        if let Some(function) = self.ir.functions.get(caller) {
            for (block_id, block) in &function.cfg.blocks {
                for (i, instruction) in block.instructions.iter().enumerate() {
                    if let Instruction::Call { target: CallTarget::Function(f), .. } = instruction {
                        if f == callee {
                            locations.push(Location {
                                function: caller.clone(),
                                block: *block_id,
                                instruction: i,
                            });
                        }
                    }
                }
            }
        }
        
        locations
    }
    
    /// Find all recursive call sites for a function.
    fn find_recursive_call_sites(&self, func: &Identifier, cycle: &[Identifier]) -> Vec<Location> {
        let mut locations = Vec::new();
        
        for callee in cycle {
            locations.extend(self.find_call_sites(func, callee));
        }
        
        locations
    }
}

impl DependencyGraph {
    fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            edges: HashMap::new(),
        }
    }
    
    fn add_edge(&mut self, from: DependencyNode, to: DependencyNode) {
        self.nodes.insert(from.clone());
        self.nodes.insert(to.clone());
        self.edges.entry(from).or_insert_with(HashSet::new).insert(to);
    }
}