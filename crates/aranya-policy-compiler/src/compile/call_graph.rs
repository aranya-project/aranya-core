//! Contains [`CallGraph`], which records calls between functions and actions in order to detect recursion.
use std::collections::BTreeMap;

use aranya_policy_ast::{Ident, Span};
use aranya_policy_module::Label;
use petgraph::{
    algo::tarjan_scc,
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef as _,
};

use crate::compile::error::RecursiveCall;

/// A directed graph of calls between callables (functions, finish functions and actions).
/// Nodes are callees. Edges are calls, weighted with the span of the call site.
pub(super) struct CallGraph {
    graph: DiGraph<Label, Span>,
    // node lookup by label, the graph can't lookup by label
    nodes: BTreeMap<Label, NodeIndex>,
}

impl CallGraph {
    /// Creates a new empty graph.
    pub(super) fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            nodes: BTreeMap::new(),
        }
    }

    /// Returns the node for `label`, adding one if needed.
    fn node(&mut self, label: &Label) -> NodeIndex {
        if let Some(&node) = self.nodes.get(label) {
            return node;
        }
        let node = self.graph.add_node(label.clone());
        self.nodes.insert(label.clone(), node);
        node
    }

    /// Records a call from `caller` to `callee`. `site` is the span of the callee name at
    /// the call site.
    pub(super) fn add_call(&mut self, caller: &Label, callee: &Label, site: Span) {
        let caller = self.node(caller);
        let callee = self.node(callee);
        self.graph.add_edge(caller, callee, site);
    }

    /// Checks that there is no recursion, or returns a [`RecursiveCall`] describing the
    /// first group of recursive callables, in source order.
    pub(super) fn check_recursion(&self) -> Result<(), RecursiveCall> {
        // Find recursive calls
        let recursive_calls = tarjan_scc(&self.graph).into_iter().map(|scc| {
            let mut calls: Vec<_> = scc
                .iter()
                .flat_map(|&node| self.graph.edges(node))
                .filter(|call| scc.contains(&call.target()))
                .collect();
            calls.sort_unstable_by_key(|call| call.weight().start());
            calls
        });

        // Report the SCC with the first recursive call in source order.
        let Some(calls) = recursive_calls
            .filter(|calls| !calls.is_empty())
            .min_by_key(|calls| calls.first().map(|call| call.weight().start()))
        else {
            return Ok(());
        };
        let calls = calls
            .into_iter()
            .filter_map(|call| {
                let caller = self.graph.node_weight(call.source())?;
                let callee = self.graph.node_weight(call.target())?;
                let site = Ident {
                    inner: callee.name.clone(),
                    span: *call.weight(),
                };
                Some((caller.name.clone(), site))
            })
            .collect();
        Err(RecursiveCall { calls })
    }
}
