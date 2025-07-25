//! Cycle detection for dependency graphs.

use super::error::{SemanticAnalysisError, SemanticAnalysisErrorKind};
use crate::dependency_graph::{DependencyGraph, NodeIdx, SortError};
use aranya_policy_ast::Identifier;

/// Detect cycles in a dependency graph and return topologically sorted nodes.
pub fn detect_cycles(
    dependency_graph: &DependencyGraph<Identifier>,
) -> Result<Vec<NodeIdx>, SemanticAnalysisError> {
    match dependency_graph.topo_sort() {
        Ok(sorted_nodes) => Ok(sorted_nodes),
        Err(SortError::Cycle(cycle)) => {
            // Convert cycle node indices to identifiers
            let cycle_identifiers: Vec<Identifier> = cycle
                .into_iter()
                .filter_map(|node_idx| dependency_graph.get(node_idx).cloned())
                .collect();

            Err(SemanticAnalysisError::circular_dependency(cycle_identifiers))
        }
        Err(SortError::Bug(bug)) => Err(SemanticAnalysisError::new(
            SemanticAnalysisErrorKind::InternalError(format!("Dependency graph sort error: {}", bug)),
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependency_graph::DependencyKind;

    #[test]
    fn test_no_cycles() {
        let mut graph = DependencyGraph::new();
        
        // A -> B -> C
        graph.add_dependency(
            Identifier::new("A"),
            Identifier::new("B"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("B"),
            Identifier::new("C"),
            DependencyKind::Type,
        );

        let result = detect_cycles(&graph);
        assert!(result.is_ok());
        
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 3);
        
        // C should come before B, B should come before A
        let identifiers: Vec<_> = sorted
            .iter()
            .map(|&idx| graph.get(idx).unwrap())
            .collect();
        
        let c_pos = identifiers.iter().position(|&id| id == &Identifier::new("C")).unwrap();
        let b_pos = identifiers.iter().position(|&id| id == &Identifier::new("B")).unwrap();
        let a_pos = identifiers.iter().position(|&id| id == &Identifier::new("A")).unwrap();
        
        assert!(c_pos < b_pos);
        assert!(b_pos < a_pos);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = DependencyGraph::new();
        
        // A -> B -> C -> A (cycle)
        graph.add_dependency(
            Identifier::new("A"),
            Identifier::new("B"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("B"),
            Identifier::new("C"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("C"),
            Identifier::new("A"),
            DependencyKind::Type,
        );

        let result = detect_cycles(&graph);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error.kind, SemanticAnalysisErrorKind::CircularDependency { .. }));
        
        if let SemanticAnalysisErrorKind::CircularDependency { cycle } = error.kind {
            // The cycle should contain all three identifiers
            assert!(cycle.contains(&Identifier::new("A")));
            assert!(cycle.contains(&Identifier::new("B")));
            assert!(cycle.contains(&Identifier::new("C")));
        }
    }

    #[test]
    fn test_self_cycle() {
        let mut graph = DependencyGraph::new();
        
        // A -> A (self cycle)
        graph.add_dependency(
            Identifier::new("A"),
            Identifier::new("A"),
            DependencyKind::Type,
        );

        let result = detect_cycles(&graph);
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(matches!(error.kind, SemanticAnalysisErrorKind::CircularDependency { .. }));
    }

    #[test]
    fn test_complex_dependency_graph() {
        let mut graph = DependencyGraph::new();
        
        // Complex graph with multiple dependencies but no cycles
        graph.add_dependency(
            Identifier::new("App"),
            Identifier::new("Database"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("App"),
            Identifier::new("Logger"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("Database"),
            Identifier::new("Config"),
            DependencyKind::Type,
        );
        graph.add_dependency(
            Identifier::new("Logger"),
            Identifier::new("Config"),
            DependencyKind::Type,
        );

        let result = detect_cycles(&graph);
        assert!(result.is_ok());
        
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 4);
        
        // Config should come before Database and Logger
        // Database and Logger should come before App
        let identifiers: Vec<_> = sorted
            .iter()
            .map(|&idx| graph.get(idx).unwrap())
            .collect();
        
        let config_pos = identifiers.iter().position(|&id| id == &Identifier::new("Config")).unwrap();
        let database_pos = identifiers.iter().position(|&id| id == &Identifier::new("Database")).unwrap();
        let logger_pos = identifiers.iter().position(|&id| id == &Identifier::new("Logger")).unwrap();
        let app_pos = identifiers.iter().position(|&id| id == &Identifier::new("App")).unwrap();
        
        assert!(config_pos < database_pos);
        assert!(config_pos < logger_pos);
        assert!(database_pos < app_pos);
        assert!(logger_pos < app_pos);
    }

    #[test]
    fn test_empty_graph() {
        let graph = DependencyGraph::new();
        
        let result = detect_cycles(&graph);
        assert!(result.is_ok());
        
        let sorted = result.unwrap();
        assert_eq!(sorted.len(), 0);
    }
}