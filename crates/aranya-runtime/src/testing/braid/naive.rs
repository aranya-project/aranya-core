//! The naive braid reference implementation (the oracle).
//!
//! Deliberately naive: plain data, whole-slice scans, no segments, no LCA,
//! no heap, no early termination. It restates production's backward braid
//! walk (the algorithm in `aranya-docs/docs/braid-optimization.md`) over the
//! whole graph; `graph.md` states the ordering properties that walk must
//! satisfy. A reader can audit it against those docs in minutes. It must
//! never share code with the
//! production braid — this file imports nothing from `crate::client`,
//! `crate::storage`, or `crate::command`.
//!
//! The differential harness that compares this oracle against production
//! lives in [`super::harness`].

use alloc::{format, string::String, vec, vec::Vec};

/// Priority ordering restated from `graph.md`. Derived `Ord` on this exact
/// variant order gives `Merge < Basic(..) < Finalize < Init`, matching
/// production's `Priority` — deliberately restated, not imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NaivePriority {
    Merge,
    Basic(u32),
    Finalize,
    Init,
}

/// A command as the oracle sees it: pure data, no runtime types.
#[derive(Debug, Clone)]
pub struct NaiveCommand {
    /// Compared byte-lexicographically, matching `CmdId`'s `Ord`.
    pub id: [u8; 32],
    pub priority: NaivePriority,
    /// Indices into the same slice. Empty for the init command.
    pub parents: Vec<usize>,
}

/// A command graph mid-walk: the commands plus which ones have been taken.
/// Every query is a whole-slice scan; no adjacency structures.
struct NaiveGraph<'a> {
    commands: &'a [NaiveCommand],
    taken: Vec<bool>,
}

impl<'a> NaiveGraph<'a> {
    fn new(commands: &'a [NaiveCommand]) -> Self {
        Self {
            commands,
            taken: vec![false; commands.len()],
        }
    }

    fn all_taken(&self) -> bool {
        self.taken.iter().all(|&taken| taken)
    }

    /// Commands that list `i` as a parent.
    fn children(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        self.commands
            .iter()
            .enumerate()
            .filter(move |(_, command)| command.parents.contains(&i))
            .map(|(child, _)| child)
    }

    /// A command is frontier when it has not been taken and every one of
    /// its children has been.
    fn is_frontier(&self, i: usize) -> bool {
        !self.taken[i] && self.children(i).all(|child| self.taken[child])
    }

    /// The walk's ordering key.
    fn key(&self, i: usize) -> (NaivePriority, &[u8; 32]) {
        (self.commands[i].priority, &self.commands[i].id)
    }

    fn is_merge(&self, i: usize) -> bool {
        matches!(self.commands[i].priority, NaivePriority::Merge)
    }

    /// Take the frontier command with the lowest key; return its index.
    fn take_lowest_frontier(&mut self) -> usize {
        let next = (0..self.commands.len())
            .filter(|&i| self.is_frontier(i))
            .min_by_key(|&i| self.key(i))
            .expect("graph is acyclic and non-empty, so a frontier command exists");
        self.taken[next] = true;
        next
    }
}

/// The reference braid: walk the whole graph backward, repeatedly taking
/// the frontier command with the lowest `(priority, id)`, then reverse.
/// Merge commands participate in the walk (with their low `Merge` key)
/// but are excluded from the output, mirroring production, which never
/// evaluates them. Returns indices into `commands` in forward braid order.
pub fn naive_braid(commands: &[NaiveCommand]) -> Vec<usize> {
    let mut graph = NaiveGraph::new(commands);
    let mut stack: Vec<usize> = Vec::new();

    while !graph.all_taken() {
        stack.push(graph.take_lowest_frontier());
    }

    stack.reverse();
    stack.retain(|&i| !graph.is_merge(i));
    stack
}

/// Check a weave (`order`: indices into `commands`, merges excluded) against
/// the requirements in `aranya-docs/docs/graph.md` ("Algorithm"): exactly one
/// init; every non-merge command exactly once; parents before children; and
/// when `A` immediately precedes `B` without being `B`'s parent, `A`'s
/// priority is at least `B`'s, with the greater id first on a tie. Merges are
/// not in the weave, so "parent" looks through them to the nearest non-merge
/// ancestors. Returns a description of the first violation found.
pub fn spec_violation(commands: &[NaiveCommand], order: &[usize]) -> Option<String> {
    let is_merge = |i: usize| matches!(commands[i].priority, NaivePriority::Merge);
    let non_merges: Vec<usize> = (0..commands.len()).filter(|&i| !is_merge(i)).collect();
    let mut sorted = order.to_vec();
    sorted.sort_unstable();
    if sorted != non_merges {
        return Some(format!(
            "weave {order:?} is not every non-merge command exactly once"
        ));
    }
    let inits = order
        .iter()
        .filter(|&&i| matches!(commands[i].priority, NaivePriority::Init))
        .count();
    if inits != 1 {
        return Some(format!("weave has {inits} init commands, not one"));
    }

    let mut position = vec![usize::MAX; commands.len()];
    for (pos, &i) in order.iter().enumerate() {
        position[i] = pos;
    }
    for (pos, &b) in order.iter().enumerate() {
        let parents = weave_parents(commands, b);
        if let Some(&p) = parents.iter().find(|&&p| position[p] >= pos) {
            return Some(format!(
                "command {p} is a parent of {b} but does not precede it"
            ));
        }
        let Some(prev) = pos.checked_sub(1) else {
            continue;
        };
        let a = order[prev];
        if parents.contains(&a) {
            continue;
        }
        let key = |i: usize| (commands[i].priority, &commands[i].id);
        if key(a) <= key(b) {
            return Some(format!(
                "command {a} ({:?}) immediately precedes non-child {b} ({:?}) \
                 without the greater (priority, id) key",
                commands[a].priority, commands[b].priority
            ));
        }
    }
    None
}

/// The nearest non-merge ancestors of `i`: its parents, looking through
/// merges.
fn weave_parents(commands: &[NaiveCommand], i: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut pending = commands[i].parents.clone();
    while let Some(p) = pending.pop() {
        if matches!(commands[p].priority, NaivePriority::Merge) {
            pending.extend(commands[p].parents.iter().copied());
        } else if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn mkid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn cmd(id: u8, priority: NaivePriority, parents: &[usize]) -> NaiveCommand {
        NaiveCommand {
            id: mkid(id),
            priority,
            parents: parents.to_vec(),
        }
    }

    /// The oracle's order, checked against the graph.md weave requirements.
    fn braid(cmds: &[NaiveCommand]) -> Vec<usize> {
        let order = naive_braid(cmds);
        assert_eq!(spec_violation(cmds, &order), None);
        order
    }

    #[test]
    fn oracle_linear_chain() {
        // init <- a <- b : only one topological order.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(0), &[0]),
            cmd(2, NaivePriority::Basic(0), &[1]),
        ];
        assert_eq!(braid(&cmds), vec![0, 1, 2]);
    }

    #[test]
    fn oracle_diamond_priority_wins() {
        // a(1) and b(2) concurrent under init, merged. Higher priority first.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(1), &[0]), // a
            cmd(2, NaivePriority::Basic(2), &[0]), // b
            cmd(3, NaivePriority::Merge, &[1, 2]),
        ];
        // Merge excluded from output; b (higher priority) before a.
        assert_eq!(braid(&cmds), vec![0, 2, 1]);
    }

    #[test]
    fn oracle_id_breaks_ties() {
        // Same priority: higher id first in forward order.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(0), &[0]), // low id
            cmd(9, NaivePriority::Basic(0), &[0]), // high id
        ];
        assert_eq!(braid(&cmds), vec![0, 2, 1]);
    }

    #[test]
    fn oracle_direction_counterexample() {
        // Chains a(1)->c(4) and b(2)->d(3), merged. The backward-min walk
        // reversed yields init,a,c,b,d — a forward-greedy-max walk would
        // yield init,b,d,a,c, which is WRONG. This test pins the direction.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(1), &[0]), // a
            cmd(2, NaivePriority::Basic(2), &[0]), // b
            cmd(3, NaivePriority::Basic(4), &[1]), // c
            cmd(4, NaivePriority::Basic(3), &[2]), // d
            cmd(5, NaivePriority::Merge, &[3, 4]),
        ];
        assert_eq!(braid(&cmds), vec![0, 1, 3, 2, 4]);
    }

    #[test]
    fn oracle_multi_head_needs_no_merge() {
        // Two childless heads: frontier starts from both.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(1), &[0]),
            cmd(2, NaivePriority::Basic(2), &[0]),
        ];
        assert_eq!(braid(&cmds), vec![0, 2, 1]);
    }

    #[test]
    fn spec_check_rejects_bad_weaves() {
        // The diamond from oracle_diamond_priority_wins.
        let cmds = vec![
            cmd(0, NaivePriority::Init, &[]),
            cmd(1, NaivePriority::Basic(1), &[0]), // a
            cmd(2, NaivePriority::Basic(2), &[0]), // b
            cmd(3, NaivePriority::Merge, &[1, 2]),
        ];
        // a (priority 1) before its non-child b (priority 2).
        assert!(spec_violation(&cmds, &[0, 1, 2]).is_some());
        // A command missing, and the merge included.
        assert!(spec_violation(&cmds, &[0, 2]).is_some());
        assert!(spec_violation(&cmds, &[0, 2, 1, 3]).is_some());
        // A child before its parent (looking through the merge).
        let with_tail = [cmds.as_slice(), &[cmd(4, NaivePriority::Basic(0), &[3])]].concat();
        assert!(spec_violation(&with_tail, &[0, 2, 4, 1]).is_some());
        assert_eq!(spec_violation(&with_tail, &[0, 2, 1, 4]), None);
    }

    #[test]
    fn oracle_priority_variant_order() {
        // Restated ordering: Merge < Basic(0) < Basic(MAX) < Finalize < Init.
        assert!(NaivePriority::Merge < NaivePriority::Basic(0));
        assert!(NaivePriority::Basic(0) < NaivePriority::Basic(u32::MAX));
        assert!(NaivePriority::Basic(u32::MAX) < NaivePriority::Finalize);
        assert!(NaivePriority::Finalize < NaivePriority::Init);
    }
}
