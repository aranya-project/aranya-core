//! Control flow graph built from a module's bytecode.
//!
//! One CFG is built per label (function, action, command block, ...) rather
//! than for the whole policy: [`Cfg::build`] takes the label's entry address
//! and walks instructions up to the next label.
//!
//! The bytecode is partitioned into [`CfgBlock`]s — maximal runs of
//! instructions with a single entry and single exit — connected by [`CfgEdge`]s
//! for the possible control flow (fall-through, jump, and the two sides of a
//! conditional branch). `Return` and `Exit` are terminal: they end a block with
//! no outgoing edges.
//!
//! Analyses run over this graph rather than over individual execution paths, so
//! they stay correct across branches and terminate on loops (e.g. the backward
//! jump a `map` compiles to) via a visited-set. See [`super::unused`] for the
//! unused-variable check built on top of it.

use std::collections::{BTreeMap, BTreeSet};

use aranya_policy_module::{Instruction, ModuleV0, Target};
use petgraph::graph::{DiGraph, NodeIndex};

/// A basic block: sequence of instructions with single entry / single exit (no branches).
#[derive(Debug)]
pub struct CfgBlock {
    /// Inclusive start address in `progmem`.
    pub start: usize,
    /// Exclusive end address in `progmem`.
    pub end: usize,
}

impl CfgBlock {
    /// Address of the last instruction in this block.
    pub fn last_addr(&self) -> usize {
        self.end.saturating_sub(1)
    }
}

/// Edge kinds in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgEdge {
    /// Sequential fall-through to next block.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Branch if condition is true.
    BranchTaken,
    /// Branch if condition is false.
    BranchNotTaken,
}

/// Control flow graph for a single function-like entry point.
pub struct Cfg {
    /// The graph itself. Nodes are basic blocks; edges are control flow.
    pub graph: DiGraph<CfgBlock, CfgEdge>,
    /// Entry node index.
    pub entry: NodeIndex,
    /// Map from block start address to node index (for lookup).
    pub start_to_node: BTreeMap<usize, NodeIndex>,
}

impl Cfg {
    /// Build a CFG for the function starting at `entry_addr`.
    pub fn build(module: &ModuleV0, entry_addr: usize) -> Self {
        // Functions are laid out back-to-back in `progmem` with no end marker,
        // and `labels` is keyed by name (not sorted by address), so this
        // function ends at the nearest label starting after `entry_addr`. If
        // none is greater, this is the last function and it runs to the end.
        let end_addr = module
            .labels
            .values()
            .filter(|&&a| a > entry_addr)
            .min()
            .copied()
            .unwrap_or(module.progmem.len());

        // Pass 1: identify block leaders.
        let mut leaders: BTreeSet<usize> = BTreeSet::from([entry_addr]);
        for pc in entry_addr..end_addr {
            let next_pc = pc.saturating_add(1);
            match &module.progmem[pc] {
                Instruction::Jump(Target::Resolved(t)) => {
                    leaders.insert(*t);
                    if next_pc < end_addr {
                        leaders.insert(next_pc);
                    }
                }
                Instruction::Branch(Target::Resolved(t)) => {
                    leaders.insert(*t);
                    if next_pc < end_addr {
                        leaders.insert(next_pc);
                    }
                }
                Instruction::Return | Instruction::Exit(_) => {
                    if next_pc < end_addr {
                        leaders.insert(next_pc);
                    }
                }
                _ => {}
            }
        }
        let leaders: Vec<usize> = leaders.into_iter().collect();

        // Pass 2: create blocks and nodes.
        let mut graph = DiGraph::new();
        let mut start_to_node = BTreeMap::new();
        for (i, &start) in leaders.iter().enumerate() {
            // The next leader starts the next block; the last block runs to
            // the end of the function.
            let block_end = leaders
                .get(i.saturating_add(1))
                .copied()
                .unwrap_or(end_addr);
            let node = graph.add_node(CfgBlock {
                start,
                end: block_end,
            });
            start_to_node.insert(start, node);
        }

        // Pass 3: add edges based on each block's last instruction.
        for &node in start_to_node.values() {
            // Copy out block addresses so don't have to clone the block.
            let (last_addr, block_end) = {
                let block = &graph[node];
                (block.last_addr(), block.end)
            };
            match &module.progmem[last_addr] {
                Instruction::Jump(Target::Resolved(t)) => {
                    if let Some(&to) = start_to_node.get(t) {
                        graph.add_edge(node, to, CfgEdge::Jump);
                    }
                }
                Instruction::Branch(Target::Resolved(t)) => {
                    if let Some(&to) = start_to_node.get(t) {
                        graph.add_edge(node, to, CfgEdge::BranchTaken);
                    }
                    if let Some(&to) = start_to_node.get(&block_end) {
                        graph.add_edge(node, to, CfgEdge::BranchNotTaken);
                    }
                }
                Instruction::Return | Instruction::Exit(_) => {
                    // Terminal: no outgoing edges.
                }
                _ => {
                    if let Some(&to) = start_to_node.get(&block_end) {
                        graph.add_edge(node, to, CfgEdge::Fallthrough);
                    }
                }
            }
        }

        let entry = *start_to_node
            .get(&entry_addr)
            .expect("entry address is always a leader");

        Self {
            graph,
            entry,
            start_to_node,
        }
    }

    /// Returns the set of nodes reachable from the entry (DFS).
    pub fn reachable_nodes(&self) -> BTreeSet<NodeIndex> {
        use petgraph::visit::Dfs;
        let mut dfs = Dfs::new(&self.graph, self.entry);
        let mut reachable = BTreeSet::new();
        while let Some(node) = dfs.next(&self.graph) {
            reachable.insert(node);
        }
        reachable
    }
}
