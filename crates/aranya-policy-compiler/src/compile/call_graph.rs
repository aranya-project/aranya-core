//! Contains [`CallGraph`], which records calls between functions and actions in order to detect recursion.
use std::collections::HashMap;

use aranya_policy_ast::{Ident, Span};
use aranya_policy_module::Label;

use crate::compile::{error::RecursiveCall, topo::TopoSort};

/// A directed graph of calls between callables (functions, finish functions and actions).
pub(super) struct CallGraph {
    /// Calls as `(caller, callee, site)`, where `site` is the span of the callee name.
    calls: Vec<(Label, Label, Span)>,
}

impl CallGraph {
    /// Creates a new empty graph.
    pub(super) fn new() -> Self {
        Self { calls: Vec::new() }
    }

    /// Records a call from `caller` to `callee`. `site` is the span of the callee name at
    /// the call site.
    pub(super) fn add_call(&mut self, caller: &Label, callee: &Label, site: Span) {
        self.calls.push((caller.clone(), callee.clone(), site));
    }

    /// Checks that there is no recursion, or returns a [`RecursiveCall`] describing the
    /// first group of mutually recursive callables in source order.
    pub(super) fn check_recursion(&self) -> Result<(), RecursiveCall> {
        let mut topo = TopoSort::new();
        for (caller, callee, _) in &self.calls {
            topo.insert(caller, [callee]);
        }

        // Maps each callable that is part of a cycle to the index of its cycle. Callables
        // that are not recursive are not in the map.
        let mut cycle_of = HashMap::new();
        for (i, cycle) in topo.cycles().into_iter().enumerate() {
            for label in cycle {
                cycle_of.insert(label, i);
            }
        }

        // Collects the calls that are part of a cycle, along with the cycle's index. A call
        // is part of a cycle when its caller and callee are in the same cycle.
        let mut calls = Vec::new();
        for (caller, callee, site) in &self.calls {
            let Some(&i) = cycle_of.get(caller) else {
                // The caller is not recursive.
                continue;
            };
            if cycle_of.get(callee) != Some(&i) {
                // The call leaves the caller's cycle.
                continue;
            }
            calls.push((i, caller, callee, *site));
        }
        calls.sort_unstable_by_key(|(.., site)| site.start());

        // Report the cycle with the first call in source order.
        let Some(&(first, ..)) = calls.first() else {
            return Ok(());
        };
        let calls = calls
            .into_iter()
            .filter(|&(i, ..)| i == first)
            .map(|(_, caller, callee, span)| {
                let callee = Ident {
                    inner: callee.name.clone(),
                    span,
                };
                (caller.name.clone(), callee)
            })
            .collect();
        Err(RecursiveCall { calls })
    }
}
