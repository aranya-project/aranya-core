//! Unused-variable detection via forward reachability.
//!
//! A `Def(name)` is *unused* when no `Get(name)` is reachable from it, i.e. the
//! value it binds is never read on any path leaving the definition.
//!
//! Because the search is over the CFG (not a single path), a variable read in
//! only one branch is still used, e.g. in `if c { return a } else { return b }`
//! neither `a` nor `b` is flagged.
//!
//! This works because the policy language doesn't allow shadowing: on any
//! given path a name is bound at most once, so every reachable `Get(name)`
//! reads the same definition. (Full liveness with kill-sets would only be
//! needed if dead stores were possible.)
//!
//! The forward search uses a visited-set, so loops (e.g. the backward `Jump` in
//! a `map`) terminate. The `map ... as` binding is set by `QueryNext`, not
//! `Def`, so it is intentionally not checked here.

use std::collections::BTreeSet;

use aranya_policy_ast::Identifier;
use aranya_policy_module::{Instruction, ModuleV0};
use petgraph::graph::NodeIndex;

use super::graph::Cfg;

/// A diagnostic reporting a definition whose value is never read
/// on any reachable path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedVarDiagnostic {
    /// Address of the `Def(name)` instruction.
    pub address: usize,
    /// The unused variable's name.
    pub name: Identifier,
}

/// Returns true if a `Get(name)` is reachable forward from the definition at
/// `def_addr` in `def_node`. Uses a visited-set, so loops (e.g. `map`
/// back-edges) terminate.
fn is_read_after(
    cfg: &Cfg,
    progmem: &[Instruction],
    def_node: NodeIndex,
    def_addr: usize,
    name: &Identifier,
) -> bool {
    // Whether the block at `node` reads `name` at or after `from`.
    let reads_name = |node: NodeIndex, from: usize| {
        let block = &cfg.graph[node];
        (from..block.end).any(|addr| matches!(&progmem[addr], Instruction::Get(n) if n == name))
    };

    // Scan the remainder of the defining block, after the `Def`.
    if reads_name(def_node, def_addr.saturating_add(1)) {
        return true;
    }

    // Then scan successor blocks, in full, until exhausted.
    let mut visited = BTreeSet::from([def_node]);
    let mut stack: Vec<NodeIndex> = cfg.graph.neighbors(def_node).collect();
    while let Some(node) = stack.pop() {
        if !visited.insert(node) {
            continue;
        }
        if reads_name(node, cfg.graph[node].start) {
            return true;
        }
        stack.extend(cfg.graph.neighbors(node));
    }
    false
}

/// Detect unused variable definitions.
///
/// Global variables (from `module.globals`) are never reported. `predefined`
/// lists implicit locals (e.g. `this`, `envelope`) for command contexts, which
/// are also never reported.
pub fn unused_vars(
    cfg: &Cfg,
    module: &ModuleV0,
    predefined: &BTreeSet<Identifier>,
) -> Vec<UnusedVarDiagnostic> {
    let mut diags = Vec::new();
    for &node in &cfg.reachable_nodes() {
        let block = &cfg.graph[node];
        for addr in block.start..block.end {
            let Instruction::Def(name) = &module.progmem[addr] else {
                continue;
            };
            // Skip global, predefined vars; we only care about local unused vars.
            if module.globals.contains_key(name) || predefined.contains(name) {
                continue;
            }
            if !is_read_after(cfg, &module.progmem, node, addr, name) {
                diags.push(UnusedVarDiagnostic {
                    address: addr,
                    name: name.clone(),
                });
            }
        }
    }
    diags.sort_by_key(|d| d.address);
    diags
}
