//! Enumerating the graph shapes a client can hold.
//!
//! A shape is a parent structure ([`ProgParents`] per command, indexed by a
//! topological command number). This module is pure combinatorics: it knows
//! nothing about production commands, sync, or the oracle, and imports nothing
//! from the runtime. It answers one question — *which graph shapes are worth
//! testing* — and [`super::harness`] answers the rest.
//!
//! The realizable shapes are exactly the *braidable prime blocks*: single-sink
//! prime DAGs whose singles have one parent and merges two concurrent parents
//! (a parent pair merges at most once), no wider than [`PEERS`]. A peer's own
//! commands form a chain — each descends from its previous head — so any
//! antichain has at most one command per peer: a graph is never wider than the
//! peer count. Conversely every such graph is reachable: assign one peer per
//! chain of a width decomposition (see [`chain_clients`]) and let each sync a
//! command's parents just before authoring it (partial sync delivers any causal
//! prefix, so even a bare merge head is observable).
//!
//! [`enumerate_braidable`] walks that structural space directly, one
//! representative per isomorphism class.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

/// Parent choice for a command; indices are 0-based command numbers in the
/// graph's structure (a topological labeling: command 0 is init, and every
/// parent index is smaller than the command's own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgParents {
    Init,
    Single(usize),
    Merge(usize, usize),
}

/// The peer count, and so the width cap: a graph is no wider than the number
/// of peers concurrently authoring (each peer's commands form a single chain).
pub const PEERS: usize = 3;

/// The bit for command index `i` (i < 64, always true for our sizes).
pub(crate) fn cmd_bit(i: usize) -> u64 {
    1u64.checked_shl(u32::try_from(i).expect("command index < 64"))
        .expect("command index < 64")
}

/// `anc[i]` = bitmask of command i and all of its ancestors.
pub(crate) fn anc_masks(structure: &[ProgParents]) -> Vec<u64> {
    let n = structure.len();
    let mut anc = vec![0u64; n];
    for i in 0..n {
        anc[i] = cmd_bit(i)
            | match structure[i] {
                ProgParents::Init => 0,
                ProgParents::Single(j) => anc[j],
                ProgParents::Merge(j, k) => anc[j] | anc[k],
            };
    }
    anc
}

/// Whether commands `a` and `b` are concurrent: distinct, and neither an
/// ancestor of the other. `anc` is from [`anc_masks`].
pub(crate) fn concurrent(anc: &[u64], a: usize, b: usize) -> bool {
    a != b && anc[a] & cmd_bit(b) == 0 && anc[b] & cmd_bit(a) == 0
}

/// `has_child[i]` = whether some command names `i` as a parent.
pub(crate) fn has_child(structure: &[ProgParents]) -> Vec<bool> {
    let mut has_child = vec![false; structure.len()];
    for p in structure {
        match *p {
            ProgParents::Init => {}
            ProgParents::Single(j) => has_child[j] = true,
            ProgParents::Merge(j, k) => {
                has_child[j] = true;
                has_child[k] = true;
            }
        }
    }
    has_child
}

/// A graph is a *prime block* when the only width-1 points — commands
/// comparable (ancestor-or-descendant) to every other — are the base and the
/// closing merge, i.e. exactly two. An intermediate width-1 point would split
/// it into smaller braidable regions.
fn is_prime(structure: &[ProgParents]) -> bool {
    let n = structure.len();
    if n < 3 {
        return false;
    }
    let anc = anc_masks(structure);
    (0..n)
        .filter(|&c| (0..n).all(|d| !concurrent(&anc, c, d)))
        .count()
        == 2
}

/// The index of the merge of parents `a < b`, if the graph already has it.
pub(crate) fn find_merge(structure: &[ProgParents], a: usize, b: usize) -> Option<usize> {
    structure
        .iter()
        .position(|p| matches!(*p, ProgParents::Merge(x, y) if x == a && y == b))
}

/// The number of commands with no child — the graph's global heads.
fn global_sink_count(structure: &[ProgParents]) -> usize {
    has_child(structure).iter().filter(|&&c| !c).count()
}

/// The width (largest antichain) of a shape: a minimum chain cover of the
/// reachability order, which by König/Dilworth is `n` minus a maximum bipartite
/// matching of the proper-ancestor relation.
pub(crate) fn graph_width(structure: &[ProgParents]) -> usize {
    let n = structure.len();
    let anc = anc_masks(structure);
    // desc[x] = the commands x is a proper ancestor of (its right-side edges).
    let mut desc: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (y, &anc_y) in anc.iter().enumerate() {
        for (x, edges) in desc.iter_mut().enumerate() {
            if x != y && anc_y & cmd_bit(x) != 0 {
                edges.push(y);
            }
        }
    }
    let mut match_pred: Vec<Option<usize>> = vec![None; n];
    for u in 0..n {
        let mut used = vec![false; n];
        augment(u, &desc, &mut match_pred, &mut used);
    }
    let matched = match_pred.iter().filter(|m| m.is_some()).count();
    n.checked_sub(matched).expect("matching size <= n")
}

/// One augmenting step of Kuhn's maximum-bipartite-matching, shared by the two
/// matchings this module builds ([`graph_width`] over the ancestor relation and
/// [`chain_clients`] over direct parent edges).
fn augment(
    u: usize,
    children: &[Vec<usize>],
    match_pred: &mut [Option<usize>],
    used: &mut [bool],
) -> bool {
    for &v in &children[u] {
        if used[v] {
            continue;
        }
        used[v] = true;
        if match_pred[v].is_none()
            || augment(match_pred[v].expect("some"), children, match_pred, used)
        {
            match_pred[v] = Some(u);
            return true;
        }
    }
    false
}

/// Every braidable prime block of at most `max_n` commands, one representative
/// per isomorphism class, as a bare parent structure.
///
/// The shapes are exactly the graphs a client can hold: single-sink prime DAGs
/// with singles (one parent) and merges (two concurrent parents, each pair
/// merged at most once), no wider than [`PEERS`]. A breadth-first walk grows
/// every such graph — adding a single child of any command, or a merge of any
/// concurrent not-yet-merged pair — deduplicated up to isomorphism and pruned
/// on width and command budget. [`super::harness::shape_only_program`] turns a
/// shape into a runnable distributed schedule.
pub fn enumerate_braidable(max_n: usize) -> Vec<Vec<ProgParents>> {
    let mut visited: BTreeSet<Vec<(u8, usize, usize)>> = BTreeSet::new();
    let mut blocks: BTreeMap<Vec<(u8, usize, usize)>, Vec<ProgParents>> = BTreeMap::new();
    let mut stack: Vec<Vec<ProgParents>> = vec![vec![ProgParents::Init]];

    while let Some(structure) = stack.pop() {
        let key = canonical_key(&structure);
        if !visited.insert(key.clone()) {
            continue;
        }
        let sinks = global_sink_count(&structure);
        // A block is closed (one head) and irreducible (no interior width-1
        // point that would split it into smaller braidable regions).
        if sinks == 1 && is_prime(&structure) {
            blocks.entry(key).or_insert_with(|| structure.clone());
        }
        if structure.len() >= max_n {
            continue;
        }
        // Budget prune: s heads need at least s-1 more merges to reconverge to
        // a single head, so a shape that cannot afford them in the commands
        // left can never close a block.
        if sinks > 1 {
            let remaining = max_n.checked_sub(structure.len()).expect("len <= max_n");
            if remaining < sinks.checked_sub(1).expect("sinks >= 1") {
                continue;
            }
        }
        let n = structure.len();
        let anc = anc_masks(&structure);
        // A single child of any command.
        for v in 0..n {
            let mut next = structure.clone();
            next.push(ProgParents::Single(v));
            if graph_width(&next) <= PEERS {
                stack.push(next);
            }
        }
        // A merge of any concurrent pair not already merged (init, ancestor of
        // all, is never concurrent with anything).
        for k in 0..n {
            for j in 0..k {
                if concurrent(&anc, j, k) && find_merge(&structure, j, k).is_none() {
                    let mut next = structure.clone();
                    next.push(ProgParents::Merge(j, k));
                    if graph_width(&next) <= PEERS {
                        stack.push(next);
                    }
                }
            }
        }
    }

    blocks.into_values().collect()
}

/// Canonical isomorphism key of a shape: the lexicographically-minimal parent
/// encoding over all topological relabelings. Isomorphic DAGs share their set
/// of topological-order encodings, so the minimum is a complete, sound
/// isomorphism invariant (and absorbs automorphisms for free).
///
/// It is built directly rather than by ranging over every order: a command's
/// descriptor depends only on the labels already assigned, so at each position
/// only the ready commands (all parents placed) with the minimal descriptor can
/// begin a minimal encoding. Ties — exactly the graph's automorphisms — are the
/// only branch points, so an asymmetric graph is canonicalized along one path.
fn canonical_key(structure: &[ProgParents]) -> Vec<(u8, usize, usize)> {
    let n = structure.len();
    let mut placed = vec![false; n];
    let mut label = vec![0usize; n];
    let mut enc: Vec<(u8, usize, usize)> = Vec::with_capacity(n);
    let mut best: Option<Vec<(u8, usize, usize)>> = None;
    extend(structure, &mut placed, &mut label, &mut enc, &mut best);
    return best.expect("at least one topological order");

    /// Command `i`'s descriptor given the labels assigned so far: its kind, and
    /// its parents' (already-placed) labels, merge parents label-sorted.
    fn descriptor(structure: &[ProgParents], label: &[usize], i: usize) -> (u8, usize, usize) {
        match structure[i] {
            ProgParents::Init => (0, 0, 0),
            ProgParents::Single(j) => (1, label[j], label[j]),
            ProgParents::Merge(j, k) => (2, label[j].min(label[k]), label[j].max(label[k])),
        }
    }

    fn extend(
        structure: &[ProgParents],
        placed: &mut Vec<bool>,
        label: &mut Vec<usize>,
        enc: &mut Vec<(u8, usize, usize)>,
        best: &mut Option<Vec<(u8, usize, usize)>>,
    ) {
        let n = structure.len();
        let pos = enc.len();
        // This prefix can no longer beat the best complete encoding.
        if best.as_ref().is_some_and(|b| enc.as_slice() > &b[..pos]) {
            return;
        }
        if pos == n {
            match best.as_ref() {
                Some(b) if b.as_slice() <= enc.as_slice() => {}
                _ => *best = Some(enc.clone()),
            }
            return;
        }
        // The ready commands (all parents placed) with their descriptors.
        let mut ready: Vec<(usize, (u8, usize, usize))> = Vec::new();
        for i in 0..n {
            if placed[i] {
                continue;
            }
            let all_parents_placed = match structure[i] {
                ProgParents::Init => true,
                ProgParents::Single(j) => placed[j],
                ProgParents::Merge(j, k) => placed[j] && placed[k],
            };
            if all_parents_placed {
                ready.push((i, descriptor(structure, label, i)));
            }
        }
        let min_desc = ready
            .iter()
            .map(|&(_, d)| d)
            .min()
            .expect("a shape of pos < n commands has a ready command");
        // Only minimal-descriptor commands can begin a minimal encoding; ties
        // (automorphisms) are the branch points.
        for (i, d) in ready.into_iter().filter(|&(_, d)| d == min_desc) {
            placed[i] = true;
            label[i] = pos;
            enc.push(d);
            extend(structure, placed, label, enc, best);
            enc.pop();
            placed[i] = false;
        }
    }
}

/// Assign each command to a client by a minimum chain decomposition of the
/// graph (minimum vertex-disjoint path cover over the direct parent edges).
/// Commands in one chain are causally ordered, so two concurrent commands
/// always land on different clients. The client count is the size of that
/// path cover, which can exceed the graph's width ([`graph_width`], a chain
/// cover over reachability): consecutive commands on one client must be
/// direct parent and child, so e.g. two stacked diamonds (width 2) take
/// three clients. Init is always client 0.
pub fn chain_clients(structure: &[ProgParents]) -> Vec<usize> {
    let n = structure.len();
    // children[u] = the commands that name u as a direct parent.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (v, p) in structure.iter().enumerate() {
        match *p {
            ProgParents::Init => {}
            ProgParents::Single(j) => children[j].push(v),
            ProgParents::Merge(j, k) => {
                children[j].push(v);
                children[k].push(v);
            }
        }
    }

    // Maximum bipartite matching (Kuhn): match_pred[v] = the command chosen
    // as v's predecessor in the path cover.
    let mut match_pred: Vec<Option<usize>> = vec![None; n];
    for u in 0..n {
        let mut used = vec![false; n];
        augment(u, &children, &mut match_pred, &mut used);
    }

    // Successor / head from the matching.
    let mut succ: Vec<Option<usize>> = vec![None; n];
    let mut has_pred = vec![false; n];
    for (v, pred) in match_pred.iter().enumerate() {
        if let Some(u) = *pred {
            succ[u] = Some(v);
            has_pred[v] = true;
        }
    }

    // Walk each chain from its head, numbering clients in index order; init
    // (index 0, never a successor) is the first head, hence client 0.
    let mut client_of = vec![usize::MAX; n];
    let mut next = 0usize;
    for (start, &pred) in has_pred.iter().enumerate() {
        if !pred {
            let mut cur = start;
            loop {
                client_of[cur] = next;
                match succ[cur] {
                    Some(v) => cur = v,
                    None => break,
                }
            }
            next = next.checked_add(1).expect("client count fits");
        }
    }
    client_of
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn canonical_key_identifies_isomorphic_shapes() {
        // Extending the left branch vs the right branch of a fork are the
        // same shape (swap the two branches).
        let left = vec![
            ProgParents::Init,
            ProgParents::Single(0),
            ProgParents::Single(0),
            ProgParents::Single(1),
        ];
        let right = vec![
            ProgParents::Init,
            ProgParents::Single(0),
            ProgParents::Single(0),
            ProgParents::Single(2),
        ];
        assert_eq!(canonical_key(&left), canonical_key(&right));
        // A chain is a different shape.
        let chain = vec![
            ProgParents::Init,
            ProgParents::Single(0),
            ProgParents::Single(1),
            ProgParents::Single(2),
        ];
        assert_ne!(canonical_key(&left), canonical_key(&chain));
    }

    /// Braidable prime blocks by command count, up to isomorphism, through
    /// n=9. The sequence continues with 1157 at n=10, validated out of band
    /// under a release build.
    #[test]
    fn braidable_shape_counts() {
        let mut by_n = [0usize; 10];
        for structure in enumerate_braidable(9) {
            by_n[structure.len()] = by_n[structure.len()].checked_add(1).expect("count fits");
        }
        let seq: Vec<usize> = (4..=9).map(|n| by_n[n]).collect();
        assert_eq!(
            seq,
            vec![1, 1, 4, 13, 53, 234],
            "braidable shape counts changed"
        );
    }

    #[test]
    fn chain_clients_one_per_branch() {
        let width = |s: &[ProgParents]| *chain_clients(s).iter().max().unwrap();
        // A chain is one branch; a fork two; a three-way fan-out three; a
        // diamond has width two.
        assert_eq!(
            width(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(1)
            ]),
            0
        );
        assert_eq!(
            width(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0)
            ]),
            1
        );
        assert_eq!(
            width(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0),
                ProgParents::Single(0),
            ]),
            2
        );
        assert_eq!(
            width(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0),
                ProgParents::Merge(1, 2),
            ]),
            1
        );
        // Init is always client 0.
        for structure in enumerate_braidable(6) {
            assert_eq!(chain_clients(&structure)[0], 0);
        }
    }
}
