//! Enumerating the graph shapes a client can hold.
//!
//! A shape is a parent structure ([`ProgParents`] per command, indexed by a
//! topological command number). This module is pure combinatorics: it knows
//! nothing about production commands, sync, or the oracle, and imports nothing
//! from the runtime. It answers one question — *which graph shapes are worth
//! testing* — and [`super::harness`] answers the rest.
//!
//! A client-holdable shape is a DAG grown from a lone init by the moves in
//! [`extensions`]: a single child of any command, or a merge of two concurrent
//! commands not already merged (a pair merges at most once), such that the
//! graph splits into at most [`PEERS`] chains ([`chain_clients`]). Each chain
//! is one peer's line of authorship, and every such graph is reachable: let
//! each peer sync a command's parents just before authoring it (partial sync
//! delivers any causal prefix, so even a bare merge head is observable).
//!
//! [`enumerate_shapes`] walks that space exhaustively, one representative per
//! isomorphism class; the random sweep in [`super::harness`] samples paths
//! through it. Both use [`extensions`], so there is one definition of the
//! shape space.

use alloc::{collections::BTreeMap, vec, vec::Vec};

/// Parent choice for a command; indices are 0-based command numbers in the
/// graph's structure (a topological labeling: command 0 is init, and every
/// parent index is smaller than the command's own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgParents {
    Init,
    Single(usize),
    Merge(usize, usize),
}

/// The peer count, and so the chain cap: a shape splits into at most this
/// many chains, one per peer authoring it.
pub const PEERS: usize = 3;

/// The bit for command index `i` (i < 64, always true for our sizes).
fn cmd_bit(i: usize) -> u64 {
    1u64.checked_shl(u32::try_from(i).expect("command index < 64"))
        .expect("command index < 64")
}

/// `anc[i]` = bitmask of command i and all of its ancestors.
fn anc_masks(structure: &[ProgParents]) -> Vec<u64> {
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

/// The index of the merge of parents `a < b`, if the graph already has it.
fn find_merge(structure: &[ProgParents], a: usize, b: usize) -> Option<usize> {
    structure
        .iter()
        .position(|p| matches!(*p, ProgParents::Merge(x, y) if x == a && y == b))
}

/// The number of chains [`chain_clients`] splits the shape into.
pub(crate) fn chain_count(structure: &[ProgParents]) -> usize {
    chain_clients(structure)
        .iter()
        .max()
        .map_or(0, |&m| m.checked_add(1).expect("chain count fits"))
}

/// Every shape one command larger: a single child of any command, or a merge
/// of any concurrent pair not already merged, keeping at most [`PEERS`]
/// chains. This is the one definition of the shape space.
///
/// The chain cap can be applied while growing because removing a sink never
/// increases a minimum path cover, so every prefix of a shape within the cap
/// is itself within the cap. A single child of the newest command (a sink)
/// never adds a chain, so the result is never empty.
pub fn extensions(structure: &[ProgParents]) -> Vec<Vec<ProgParents>> {
    let n = structure.len();
    let anc = anc_masks(structure);
    let mut moves: Vec<ProgParents> = (0..n).map(ProgParents::Single).collect();
    for k in 0..n {
        for j in 0..k {
            if concurrent(&anc, j, k) && find_merge(structure, j, k).is_none() {
                moves.push(ProgParents::Merge(j, k));
            }
        }
    }
    moves
        .into_iter()
        .map(|parents| {
            let mut next = structure.to_vec();
            next.push(parents);
            next
        })
        .filter(|next| chain_count(next) <= PEERS)
        .collect()
}

/// Every client-holdable shape of at most `max_n` commands, one representative
/// per isomorphism class: a depth-first walk over [`extensions`] from the lone
/// init, deduplicated by [`canonical_key`]. Isomorphic shapes have isomorphic
/// extensions, so expanding one representative per class loses nothing.
pub fn enumerate_shapes(max_n: usize) -> Vec<Vec<ProgParents>> {
    let mut seen: BTreeMap<Vec<(u8, usize, usize)>, Vec<ProgParents>> = BTreeMap::new();
    let mut stack = vec![vec![ProgParents::Init]];
    while let Some(structure) = stack.pop() {
        if seen.contains_key(&canonical_key(&structure)) {
            continue;
        }
        if structure.len() < max_n {
            stack.extend(extensions(&structure));
        }
        seen.insert(canonical_key(&structure), structure);
    }
    seen.into_values().collect()
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

/// One augmenting step of Kuhn's maximum-bipartite-matching, used by
/// [`chain_clients`] to build a minimum path cover over direct parent edges.
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

    #[test]
    fn extensions_are_client_holdable() {
        // Every move from every small shape keeps the structure valid:
        // parents precede the new command, merges join a concurrent pair
        // merged nowhere else, and the chain cap holds.
        for structure in enumerate_shapes(5) {
            let anc = anc_masks(&structure);
            for next in extensions(&structure) {
                let i = structure.len();
                assert_eq!(&next[..i], &structure[..]);
                match next[i] {
                    ProgParents::Init => panic!("init only at index 0"),
                    ProgParents::Single(j) => assert!(j < i),
                    ProgParents::Merge(j, k) => {
                        assert!(j < k && k < i);
                        assert!(concurrent(&anc, j, k), "merge of non-concurrent pair");
                        assert!(find_merge(&structure, j, k).is_none(), "pair merged twice");
                    }
                }
                assert!(chain_count(&next) <= PEERS);
            }
        }
    }

    /// Client-holdable shapes by command count, up to isomorphism.
    #[test]
    fn shape_counts() {
        let mut by_n = [0usize; 9];
        for structure in enumerate_shapes(8) {
            by_n[structure.len()] = by_n[structure.len()].checked_add(1).expect("count fits");
        }
        assert_eq!(
            by_n[1..],
            [1, 1, 2, 5, 13, 41, 151, 635],
            "shape counts changed"
        );
    }

    #[test]
    fn chain_clients_one_per_branch() {
        let chains = |s: &[ProgParents]| chain_count(s);
        // A chain is one branch; a fork two; a three-way fan-out three; a
        // diamond has two.
        assert_eq!(
            chains(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(1)
            ]),
            1
        );
        assert_eq!(
            chains(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0)
            ]),
            2
        );
        assert_eq!(
            chains(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0),
                ProgParents::Single(0),
            ]),
            3
        );
        assert_eq!(
            chains(&[
                ProgParents::Init,
                ProgParents::Single(0),
                ProgParents::Single(0),
                ProgParents::Merge(1, 2),
            ]),
            2
        );
        // Init is always client 0.
        for structure in enumerate_shapes(6) {
            assert_eq!(chain_clients(&structure)[0], 0);
        }
    }
}
